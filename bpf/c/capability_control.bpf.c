#include "common_structs.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define NAME_MAX 255

struct cap_config {
    u32 mode;
};

struct cap_id {
    uint8_t cap;
};

struct cap_control_audit_event {
    u64 cgroup;
    u32 pid;
    int ret;
    char nodename[NEW_UTS_LEN + 1];
    char task[TASK_COMM_LEN];
    char parent_task[TASK_COMM_LEN];
    uint8_t cap;
};

struct callback_ctx {
    uint8_t cap;
    bool found;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} capcontrol_events SEC(".maps");

BPF_HASH(cap_config_map, u32, struct cap_config, 128);
BPF_HASH(cap_pids, u32, struct pids_config, 128);
BPF_HASH(cap_cgroups, u32, struct cgroup_config, 128);
BPF_HASH(allowed_caps, u32, struct cap_id, 128);
BPF_HASH(denied_caps, u32, struct cap_id, 128);

static u64 cb_check_cap(struct bpf_map *map, u32 *key, struct cap_id *map_cap, struct callback_ctx *ctx) {
    if (map_cap->cap == ctx->cap) {
        ctx->found = 1;
    }

    return 0;
}

static int get_pid(struct task_struct *current_task)
{
    unsigned int pid = (unsigned int)(bpf_get_current_pid_tgid() >> 32);
    unsigned int cgroup_inum = bpf_core_field_exists(current_task->cgroups->subsys[4]->cgroup->kn->id) ? BPF_CORE_READ(current_task, cgroups, subsys[4], cgroup, kn, id) : -1;

    struct callback_pid cp = { .pid = pid, .found = false};
    cp.found = false;
    // bpf_printk("Current pid: %u\n", pid);
    bpf_for_each_map_elem(&cap_pids, cb_check_pid, &cp, 0);
    if (cp.found) {
        // bpf_printk("Process in specific container for bpf: %d\n", cp.pid);
        if(!bpf_map_lookup_elem(&cap_cgroups, &pid))
        {
            struct cgroup_config value = { .cgroup_inum = cgroup_inum };
            bpf_map_update_elem(&cap_cgroups, &pid, &value, BPF_ANY);
        }
        return 1;
    }

    struct callback_cgroup cg = { .cgroup_inum = cgroup_inum, .found = false};
    cg.found = false;
    // bpf_printk("Process in specific container for %s, inum: %d\n", name, cn.inum);
    bpf_for_each_map_elem(&cap_cgroups, cb_check_inum, &cg, 0);
    if (cg.found) {
        // bpf_printk("Process in specific container for %s, cgroup inum: %d\n", name, cg.cgroup_inum);
        return 1;
    }

	return 0;    
}

SEC("lsm/task_alloc")
int BPF_PROG(task_alloc, struct task_struct * task, long unsigned int clone_flags)
{
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    unsigned int task_inum = bpf_core_field_exists(current_task->cgroups->subsys[4]->cgroup->kn->id) ? BPF_CORE_READ(current_task, cgroups, subsys[4], cgroup, kn, id) : -1;

	if (!get_pid(current_task))
		return 0;
}

SEC("lsm/capable")
int BPF_PROG(capability_control, struct cred *cred, struct user_namespace *ns, int cap, unsigned int opts)
{
    // u64 start, ts;
    // start = bpf_ktime_get_ns();
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    unsigned int task_inum = bpf_core_field_exists(current_task->cgroups->subsys[4]->cgroup->kn->id) ? BPF_CORE_READ(current_task, cgroups, subsys[4], cgroup, kn, id) : -1;

    if (!get_pid(current_task))
		return 0;
	// if (!get_ns(current_task))
	// 	return 0;
    
    // unsigned int pid = (unsigned int)(bpf_get_current_pid_tgid() >> 32);
    // if(!bpf_map_lookup_elem(&target_inums, &pid))
    // {
    //     unsigned int task_inum = bpf_core_field_exists(current_task->cgroups->subsys[4]->cgroup->kn->id) ? BPF_CORE_READ(current_task, cgroups, subsys[4], cgroup, kn, id) : -1;
    //     struct inums_config value = { .inum = task_inum };
    //     // 更新 target_inums 映射
    //     bpf_map_update_elem(&target_inums, &pid, &value, BPF_ANY);
    // }

    struct cap_control_audit_event event = {};
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
    event.cap = cap;
    // int inum = bpf_core_field_exists(ns->ns.inum) ? BPF_CORE_READ(ns, ns.inum) : -1;
    // bpf_printk("user_namespace->ns.inum:%d", inum);
    // bpf_printk("task:%s", event.task);

    int ret = -1;
    int index = 0;
    struct cap_config *config = (struct cap_config *)bpf_map_lookup_elem(&cap_config_map, &index);

    struct callback_ctx cb = { .cap = event.cap, .found = false};
    cb.found = false;
    bpf_for_each_map_elem(&denied_caps, cb_check_cap, &cb, 0);
    if (cb.found) {
        // bpf_printk("Cap Denied: %d\n", cb.cap);
        ret = -EPERM;
        goto out;
    }

    bpf_for_each_map_elem(&allowed_caps, cb_check_cap, &cb, 0);
    if (cb.found) {
        ret = 0;
        goto out;
    }
    
out:
    if (config && config->mode == MODE_MONITOR) {
        ret = 0;
    }

    event.ret = ret;
    bpf_ringbuf_output(&capcontrol_events, &event, sizeof(event), 0);

    // ts = bpf_ktime_get_ns();
    // bpf_printk("capable %d ns.", (ts-start));

    return ret; // 0 表示允许操作，非 0 表示拒绝操作
}