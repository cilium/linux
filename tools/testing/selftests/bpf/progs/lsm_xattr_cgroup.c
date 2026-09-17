// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

#define LABEL_MAX	32
#define MAX_ERRNO	4095

/* Which name the file_open program asks for, set by the runner. */
enum {
	MODE_NONE,
	MODE_ZONE,	/* security.bpf.zone */
	MODE_USER,	/* user.note */
	MODE_MISSING,	/* a security.bpf. name that is not there */
	MODE_SHORT,	/* the zone, into a buffer too short for it */
	MODE_FOREIGN,	/* another LSM's label */
};

extern struct cgroup *bpf_cgroup_from_id(__u64 cgid) __ksym;
extern void bpf_cgroup_release(struct cgroup *cgrp) __ksym;

const char xattr_zone[] = "security.bpf.zone";
const char xattr_note[] = "user.note";
const char xattr_missing[] = "security.bpf.missing";
const char xattr_foreign[] = "security.selinux";
char own_buf[LABEL_MAX];
char tp_buf[LABEL_MAX];
char task_buf[LABEL_MAX];
__u32 monitored_pid;
__u32 mode;
__s32 own_ret;
__u32 tp_armed;
__s32 tp_ret;
__s32 task_ret;
__u32 task_pid;

/* Read the current task's own cgroup, looked up by id, and hand the read's
 * error back to the open so that userspace sees it.
 */
SEC("lsm/file_open")
int BPF_PROG(read_own_cgroup, struct file *file)
{
	struct bpf_dynptr value;
	struct cgroup *cgrp;
	int len;

	if (bpf_get_current_pid_tgid() >> 32 != monitored_pid || !mode)
		return 0;
	cgrp = bpf_cgroup_from_id(bpf_get_current_cgroup_id());
	if (!cgrp)
		return -ENOENT;
	bpf_dynptr_from_mem(own_buf, sizeof(own_buf), 0, &value);
	switch (mode) {
	case MODE_ZONE:
		len = bpf_cgroup_read_xattr(cgrp, xattr_zone, &value);
		break;
	case MODE_USER:
		len = bpf_cgroup_read_xattr(cgrp, xattr_note, &value);
		break;
	case MODE_MISSING:
		len = bpf_cgroup_read_xattr(cgrp, xattr_missing, &value);
		break;
	case MODE_SHORT:
		bpf_dynptr_from_mem(own_buf, 2, 0, &value);
		len = bpf_cgroup_read_xattr(cgrp, xattr_zone, &value);
		break;
	case MODE_FOREIGN:
		len = bpf_cgroup_read_xattr(cgrp, xattr_foreign, &value);
		break;
	default:
		len = 0;
	}
	bpf_cgroup_release(cgrp);
	own_ret = len;
	if (len < 0 && len >= -MAX_ERRNO)
		return len;
	return 0;
}

/* The kfunc is in the common set: a tracing program reads the same label. */
SEC("tp_btf/sys_enter")
int BPF_PROG(read_own_cgroup_tp, struct pt_regs *regs, long id)
{
	struct bpf_dynptr value;
	struct cgroup *cgrp;

	if (bpf_get_current_pid_tgid() >> 32 != monitored_pid || !tp_armed)
		return 0;
	tp_armed = 0;
	cgrp = bpf_cgroup_from_id(bpf_get_current_cgroup_id());
	if (!cgrp)
		return 0;
	bpf_dynptr_from_mem(tp_buf, sizeof(tp_buf), 0, &value);
	tp_ret = bpf_cgroup_read_xattr(cgrp, xattr_zone, &value);
	bpf_cgroup_release(cgrp);
	return 0;
}

/* Another task's cgroup, reached through the task under RCU rather than
 * looked up by id: the moved task's, in the mover's context.
 */
SEC("lsm/task_cgroup_attach")
int BPF_PROG(read_task_cgroup, struct task_struct *task, struct cgroup *dst_cgrp)
{
	struct bpf_dynptr value;
	struct cgroup *cgrp;
	int len = -ENOENT;

	if (bpf_get_current_pid_tgid() >> 32 != monitored_pid)
		return 0;
	bpf_dynptr_from_mem(task_buf, sizeof(task_buf), 0, &value);
	bpf_rcu_read_lock();
	cgrp = task->cgroups->dfl_cgrp;
	if (cgrp)
		len = bpf_cgroup_read_xattr(cgrp, xattr_zone, &value);
	bpf_rcu_read_unlock();
	task_ret = len;
	task_pid = task->pid;
	return 0;
}
