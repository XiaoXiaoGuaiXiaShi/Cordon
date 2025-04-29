#include "common_structs.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct sys_config {
    u32 mode;
};

struct sys_control_audit_event {
    u64 cgroup;
    u32 pid;
    int ret;
    char nodename[NEW_UTS_LEN + 1];
    char task[TASK_COMM_LEN];
    char parent_task[TASK_COMM_LEN];
    char sysname[4];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} syscontrol_events SEC(".maps");

BPF_HASH(sys_config_map, u32, struct sys_config, 64);
BPF_HASH(bpf_pids, u32, struct pids_config, 128);
BPF_HASH(bpf_cgroups, u32, struct cgroup_config, 128);

// 判断是否属于容器内进程
static int get_pid(struct task_struct *current_task)
{
    unsigned int pid = (unsigned int)(bpf_get_current_pid_tgid() >> 32);
    unsigned int cgroup_inum = bpf_core_field_exists(current_task->cgroups->subsys[4]->cgroup->kn->id) ? BPF_CORE_READ(current_task, cgroups, subsys[4], cgroup, kn, id) : -1;

    struct callback_pid cp = { .pid = pid, .found = false};
    cp.found = false;
    // bpf_printk("Current pid: %u\n", pid);
    bpf_for_each_map_elem(&bpf_pids, cb_check_pid, &cp, 0);
    if (cp.found) {
        // bpf_printk("Process in specific container for bpf: %d\n", cp.pid);
        if(!bpf_map_lookup_elem(&bpf_cgroups, &pid))
        {
            struct cgroup_config value = { .cgroup_inum = cgroup_inum };
            bpf_map_update_elem(&bpf_cgroups, &pid, &value, BPF_ANY);
        }
        return 1;
    }

    struct callback_cgroup cg = { .cgroup_inum = cgroup_inum, .found = false};
    cg.found = false;
    // bpf_printk("Process in specific container for %s, inum: %d\n", name, cn.inum);
    bpf_for_each_map_elem(&bpf_cgroups, cb_check_inum, &cg, 0);
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

SEC("lsm/bpf_prog")
int BPF_PROG(bpf_syscall_control, struct bpf_prog * prog)
{
    u64 start, ts;
    start = bpf_ktime_get_ns();

    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    unsigned int task_inum = bpf_core_field_exists(current_task->cgroups->subsys[4]->cgroup->kn->id) ? BPF_CORE_READ(current_task, cgroups, subsys[4], cgroup, kn, id) : -1;

	// if (!get_pid(current_task))
	// 	return 0;
    
    int ret = -1;
    struct sys_control_audit_event event = {};
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
    char str[] = "bpf";
    bpf_probe_read(event.sysname, sizeof(event.sysname), str);

    // bpf_printk("event.sysname : %s\n", event.sysname);

    int index = 0;
    struct sys_config *config = (struct sys_config *)bpf_map_lookup_elem(&sys_config_map, &index);
    if (config && config->mode == MODE_MONITOR) {
        ret = 0;
    }

    event.ret = ret;
    bpf_ringbuf_output(&syscontrol_events, &event, sizeof(event), 0);

    ts = bpf_ktime_get_ns();
    // bpf_printk("capable %d ns.", (ts-start));

    return ret; // 0 表示允许操作，非 0 表示拒绝操作
}