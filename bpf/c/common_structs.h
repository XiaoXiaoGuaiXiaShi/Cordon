#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define ALLOW_ACCESS 0
#define AUDIT_EVENTS_RING_SIZE (4 * 4096)
#define TASK_COMM_LEN 16
#define NEW_UTS_LEN 64

enum mode
{
  MODE_MONITOR,
  MODE_BLOCK
};

#define BPF_HASH(name, key_type, val_type, size) \
  struct                                         \
  {                                              \
    __uint(type, BPF_MAP_TYPE_HASH);             \
    __uint(max_entries, size);                   \
    __type(key, key_type);                       \
    __type(value, val_type);                     \
  } name SEC(".maps")

static inline int strcmp(const unsigned char *a, const unsigned char *b, size_t len)
{
  unsigned char c1, c2;
  size_t i;

  for (i=0; i<len; i++) {
    c1 = (unsigned char)a[i];
    c2 = (unsigned char)b[i];

    if (c1 != c2 || c1 == '\0' || c2 == '\0') {
      return 1;
    }
  }

  return 0;
}

static __always_inline int strlen(const unsigned char *s, size_t max_len)
{
	size_t i;

	for (i = 0; i < max_len; i++) {
		if (s[i] == '\0')
			return i;
	}

	return i;
}


struct pids_config {
    unsigned int pid;
};
struct cgroup_config {
    unsigned int cgroup_inum;
};
struct callback_pid {
    unsigned int pid;
    bool found;
};
struct callback_cgroup {
    unsigned int cgroup_inum;
    bool found;
};
// 回调函数，用于检查PID是否在映射中
static u64 cb_check_pid(struct bpf_map *map, u32 *key, struct pids_config *map_pid, struct callback_pid *c_pid) {
    // bpf_printk("checking c_pid->found: %d, map_pid->pid: %u, c_pid->pid: %u", c_pid->found, map_pid->pid, c_pid->pid);
    if (map_pid->pid == c_pid->pid) {
        c_pid->found = 1;
    }

    return 0;
}

static u64 cb_check_inum(struct bpf_map *map, u32 *key, struct cgroup_config *map_inum, struct callback_cgroup *c_inum) {
    // bpf_printk("checking c_inum->found: %d, inum: map_inum: %s, c_inum_inum: %s", c_inum->found, map_inum->inum, c_inum->inum);
    if (map_inum->cgroup_inum == c_inum->cgroup_inum) {
        c_inum->found = 1;
    }

    return 0;
}


struct ns_config {
    unsigned int pidns_inum;
    unsigned int mntns_inum;
};
struct callback_ns {
    unsigned int pidns_inum;
    unsigned int mntns_inum;
    bool found;
};

BPF_HASH(target_ns, u32, struct ns_config, 128);


static u64 cb_check_ns(struct bpf_map *map, u32 *key, struct ns_config *pidn_inum, struct callback_ns *pidns_inum) {
    if (pidn_inum->mntns_inum == pidns_inum->mntns_inum && pidn_inum->pidns_inum == pidns_inum->pidns_inum) {
        pidns_inum->found = 1;
    }

    return 0;
}

// 从pidns和mntns判断是否属于容器内进程
static int get_ns(struct task_struct *current_task)
{
    unsigned int pid = (unsigned int)(bpf_get_current_pid_tgid() >> 32);
    unsigned int pid_inum = bpf_core_field_exists(current_task->nsproxy->pid_ns_for_children->ns.inum) ? BPF_CORE_READ(current_task, nsproxy, pid_ns_for_children, ns.inum) : -1;
    unsigned int mnt_inum = bpf_core_field_exists(current_task->nsproxy->mnt_ns->ns.inum) ? BPF_CORE_READ(current_task, nsproxy, mnt_ns, ns.inum) : -1;

    struct callback_ns ns = { .mntns_inum=mnt_inum, .pidns_inum = pid_inum, .found = false};
    ns.found = false;
    // bpf_printk("Process in specific container for %s, inum: %d\n", name, cn.inum);
    // BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns).inum;
    bpf_for_each_map_elem(&target_ns, cb_check_ns, &ns, 0);
    if (ns.found) {
        // bpf_printk("Process in specific container for capability checking, pid namespace inum: %d\n", ns.pidns_inum);
        return 1;
    }

	return 0;    
}