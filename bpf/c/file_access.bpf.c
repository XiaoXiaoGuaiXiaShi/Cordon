#include "common_structs.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define NAME_MAX 255
#define ARRAY_SIZE 10

struct fileopen_config {
    u32 mode;
};

struct file_path {
    unsigned char path[NAME_MAX];
};

struct callback_ctx {
    unsigned char *path;
    bool found;
};

struct file_open_audit_event {
    u64 cgroup;
    u32 pid;
    int ret;
    char nodename[NEW_UTS_LEN + 1];
    char task[TASK_COMM_LEN];
    char parent_task[TASK_COMM_LEN];
    unsigned char path[NAME_MAX];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} fileopen_events SEC(".maps");

BPF_HASH(fileopen_config_map, u32, struct fileopen_config, 64);
BPF_HASH(file_pids, u32, struct pids_config, 128);
BPF_HASH(file_cgroups, u32, struct cgroup_config, 128);
BPF_HASH(allowed_access_files, u32, struct file_path, 256);
BPF_HASH(denied_access_files, u32, struct file_path, 256);

static u64 cb_check_path(struct bpf_map *map, u32 *key, struct file_path *map_path, struct callback_ctx *ctx) {
    // bpf_printk("checking ctx->found: %d, path: map_path: %s, ctx_path: %s", ctx->found, map_path->path, ctx->path);

    size_t size = strlen(map_path->path, NAME_MAX);
    if (strcmp(map_path->path, ctx->path, size) == 0) {
        ctx->found = 1;
    }

    return 0;
}

// 判断是否属于容器内进程
static int get_pid(struct task_struct *current_task)
{
    unsigned int pid = (unsigned int)(bpf_get_current_pid_tgid() >> 32);
    unsigned int cgroup_inum = bpf_core_field_exists(current_task->cgroups->subsys[4]->cgroup->kn->id) ? BPF_CORE_READ(current_task, cgroups, subsys[4], cgroup, kn, id) : -1;

    struct callback_pid cp = { .pid = pid, .found = false};
    cp.found = false;
    // bpf_printk("Current pid: %u\n", pid);
    bpf_for_each_map_elem(&file_pids, cb_check_pid, &cp, 0);
    if (cp.found) {
        // bpf_printk("Process in specific container for %s: %d\n", name, cp.pid);
        if(!bpf_map_lookup_elem(&file_cgroups, &pid))
        {
            struct cgroup_config value = { .cgroup_inum = cgroup_inum };
            bpf_map_update_elem(&file_cgroups, &pid, &value, BPF_ANY);
        }
        return 1;
    }

    struct callback_cgroup cg = { .cgroup_inum = cgroup_inum, .found = false};
    cg.found = false;
    // bpf_printk("Process in specific container for %s, inum: %d\n", name, cn.inum);
    bpf_for_each_map_elem(&file_cgroups, cb_check_inum, &cg, 0);
    if (cg.found) {
        // bpf_printk("Process in specific container for %s, cgroup inum: %d\n", name, cg.cgroup_inum);
        return 1;
    }

	return 0;    
}

SEC("lsm/file_open")
int BPF_PROG(file_access_control, struct file *file)
{
    // u64 start, ts;
    // start = bpf_ktime_get_ns();
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
	if (!get_pid(current_task))
		return 0;

    int ret = -1;
    int index = 0;
    struct fileopen_config *config = (struct fileopen_config *)bpf_map_lookup_elem(&fileopen_config_map, &index);
    struct file_open_audit_event event = {};
    struct uts_namespace *uts_ns;
    struct nsproxy *nsproxy;
    BPF_CORE_READ_INTO(&nsproxy, current_task, nsproxy);
    BPF_CORE_READ_INTO(&uts_ns, nsproxy, uts_ns);
    BPF_CORE_READ_INTO(&event.nodename, uts_ns, name.nodename);
    event.cgroup = bpf_get_current_cgroup_id();
    event.pid = (u32)(bpf_get_current_pid_tgid() >> 32);

    bpf_get_current_comm(&event.task, sizeof(event.task));
    struct task_struct *parent_task = BPF_CORE_READ(current_task, real_parent);
    bpf_probe_read_kernel_str(&event.parent_task, sizeof(event.parent_task), &parent_task->comm);

    if (bpf_d_path(&file->f_path, event.path, NAME_MAX) < 0) {
        return 0;
    }

    struct callback_ctx cb = { .path = event.path, .found = false};
    cb.found = false;
    bpf_for_each_map_elem(&denied_access_files, cb_check_path, &cb, 0);
    if (cb.found) {
        // bpf_printk("Access Denied: %s\n", cb.path);
        ret = -EPERM;
        goto out;
    }

    bpf_for_each_map_elem(&allowed_access_files, cb_check_path, &cb, 0);
    if (cb.found) {
        ret = 0;
        goto out;
    }

out:
    if (config && config->mode == MODE_MONITOR) {
        ret = 0;
    }

    event.ret = ret;
    bpf_ringbuf_output(&fileopen_events, &event, sizeof(event), 0);

    // ts = bpf_ktime_get_ns();
    // bpf_printk("file_access_control spend %d ns.", (ts-start));
    return ret;

}