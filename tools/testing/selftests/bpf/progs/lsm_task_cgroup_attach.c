// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

#define LABEL_MAX	32

extern struct cgroup *bpf_cgroup_from_id(__u64 cgid) __ksym;
extern void bpf_cgroup_release(struct cgroup *cgrp) __ksym;

const char xattr_zone[] = "security.bpf.zone";
static const char label_sealed[] = "sealed";
char buf[LABEL_MAX];
__u32 monitored_pid;
__u32 moved_pid;
__u64 moved_to;
__u32 allowed;
__u32 denied;

static __always_inline bool is_sealed(int len)
{
	return len == sizeof(label_sealed) &&
	       !bpf_strncmp(buf, sizeof(label_sealed), label_sealed);
}

/* Whether the mover's own cgroup is sealed: the mover is the writer of
 * cgroup.procs or cgroup.threads, or the parent forking into a cgroup.
 */
static __always_inline bool mover_sealed(void)
{
	struct bpf_dynptr value;
	struct cgroup *cgrp;
	int len;

	cgrp = bpf_cgroup_from_id(bpf_get_current_cgroup_id());
	if (!cgrp)
		return false;
	bpf_dynptr_from_mem(buf, sizeof(buf), 0, &value);
	len = bpf_cgroup_read_xattr(cgrp, xattr_zone, &value);
	bpf_cgroup_release(cgrp);
	return is_sealed(len);
}

/* Nothing enters a sealed cgroup unless the mover is in one itself; leaving
 * one is not gated. The hook runs in the mover's context with the moved
 * task and the destination both in hand, whichever way the move was asked
 * for, and both are recorded.
 */
SEC("lsm/task_cgroup_attach")
int BPF_PROG(gate_attach, struct task_struct *task, struct cgroup *dst_cgrp)
{
	struct bpf_dynptr value;
	int len;

	if (bpf_get_current_pid_tgid() >> 32 != monitored_pid)
		return 0;
	moved_pid = task->pid;
	moved_to = BPF_CORE_READ(dst_cgrp, kn, id);
	bpf_dynptr_from_mem(buf, sizeof(buf), 0, &value);
	len = bpf_cgroup_read_xattr(dst_cgrp, xattr_zone, &value);
	if (!is_sealed(len) || mover_sealed()) {
		allowed++;
		return 0;
	}
	denied++;
	return -EPERM;
}
