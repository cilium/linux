/* SPDX-License-Identifier: GPL-2.0 */
/* Zone labels for the lsm_zone_* tests: a task's zone is the security.bpf.zone
 * label of its cgroup, a file's the same label on the file. "trusted" is the
 * one zone the policy does not enforce on; any other label is enforced;
 * no label is outside the policy.
 */
#ifndef __LSM_ZONE_H
#define __LSM_ZONE_H

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_kfuncs.h"
#include "bpf_experimental.h"

#define PROT_WRITE	0x2
#define PROT_EXEC	0x4
#define VM_EXEC		0x00000004
#define FMODE_WRITE	0x2
#define ATTR_SIZE	0x8
#define PTRACE_MODE_ATTACH 0x2
#define MAY_WRITE	0x2
#define AF_UNIX		1
#define SOCK_STREAM	1
#define SOCK_SEQPACKET	5
#define S_IFMT		0170000
#define S_IFREG		0100000

#define ZONE_MAX	32

enum {
	ZONE_NONE,	/* no label on the cgroup: outside the policy */
	ZONE_DEFAULT,	/* any label but "trusted": enforced */
	ZONE_TRUSTED,
};

extern struct cgroup *bpf_cgroup_from_id(__u64 cgid) __ksym;
extern void bpf_cgroup_release(struct cgroup *cgrp) __ksym;
extern struct file *bpf_get_vma_file(struct vm_area_struct *vma) __ksym;

const char xattr_zone[] = "security.bpf.zone";
static const char label_trusted[] = "trusted";

/* Per-task scratch for the xattr reads. A buffer shared between tasks would
 * let one task's read overwrite another's between the read and the compare.
 */
struct scratch {
	char zone[ZONE_MAX];
	char file[64];
	char name[32];
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct scratch);
} scratch_map SEC(".maps");

static __always_inline struct scratch *scratch(void)
{
	return bpf_task_storage_get(&scratch_map, bpf_get_current_task_btf(), 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
}

static __always_inline bool is_trusted(const char *label, int len)
{
	return len == sizeof(label_trusted) &&
	       !bpf_strncmp(label, sizeof(label_trusted), label_trusted);
}

/* Read the current task's zone label into the scratch and return its length.
 * The label sits on the cgroup itself, so no walk up the hierarchy is needed.
 */
static __always_inline int current_zone_label(struct scratch *s)
{
	struct bpf_dynptr value;
	struct cgroup *cgrp;
	int len;

	cgrp = bpf_cgroup_from_id(bpf_get_current_cgroup_id());
	if (!cgrp)
		return -ENOENT;
	bpf_dynptr_from_mem(s->zone, sizeof(s->zone), 0, &value);
	len = bpf_cgroup_read_xattr(cgrp, xattr_zone, &value);
	bpf_cgroup_release(cgrp);
	return len;
}

static __always_inline int zone_of_label(struct scratch *s, int len)
{
	if (len <= 0)
		return ZONE_NONE;
	if (is_trusted(s->zone, len))
		return ZONE_TRUSTED;
	return ZONE_DEFAULT;
}

static __always_inline int current_zone(struct scratch *s)
{
	if (!s)
		return ZONE_DEFAULT;	/* cannot tell: fail closed */
	return zone_of_label(s, current_zone_label(s));
}

/* The zone of another task, read off its cgroup under RCU. */
static __always_inline int task_zone(struct scratch *s, struct task_struct *task)
{
	struct bpf_dynptr value;
	struct cgroup *cgrp;
	int len = -ENOENT;

	if (!s)
		return ZONE_DEFAULT;
	bpf_dynptr_from_mem(s->zone, sizeof(s->zone), 0, &value);
	bpf_rcu_read_lock();
	cgrp = task->cgroups->dfl_cgrp;
	if (cgrp)
		len = bpf_cgroup_read_xattr(cgrp, xattr_zone, &value);
	bpf_rcu_read_unlock();
	return zone_of_label(s, len);
}

/* The cgroup a socket was created in, which the kernel records on a full
 * sock only: a request or timewait minisock shares just the common header,
 * so the record is read past its end. Those carry no cgroup here, as they
 * carry none for the kernel's own socket cgroup helper.
 */
static __always_inline __u64 sock_cgroup_id(struct sock *sk)
{
	__u8 state;

	if (!sk)
		return 0;
	state = BPF_CORE_READ(sk, __sk_common.skc_state);
	if (state == TCP_TIME_WAIT || state == TCP_NEW_SYN_RECV)
		return 0;
	return BPF_CORE_READ(sk, sk_cgrp_data.cgroup, kn, id);
}

/* The zone of the cgroup a socket was created in, read like a task's, off
 * that cgroup's own label.
 */
static __always_inline int sock_zone(struct scratch *s, struct sock *sk)
{
	struct bpf_dynptr value;
	struct cgroup *cgrp;
	__u64 id;
	int len;

	if (!s)
		return ZONE_DEFAULT;
	id = sock_cgroup_id(sk);
	cgrp = id ? bpf_cgroup_from_id(id) : NULL;
	if (!cgrp)
		return ZONE_NONE;
	bpf_dynptr_from_mem(s->zone, sizeof(s->zone), 0, &value);
	len = bpf_cgroup_read_xattr(cgrp, xattr_zone, &value);
	bpf_cgroup_release(cgrp);
	return zone_of_label(s, len);
}

/* Read a file's zone label into the scratch: the label length, or an error. */
static __always_inline int file_zone_label(struct scratch *s, struct file *file)
{
	struct bpf_dynptr value;

	bpf_dynptr_from_mem(s->file, sizeof(s->file), 0, &value);
	return bpf_get_file_xattr(file, xattr_zone, &value);
}

#endif /* __LSM_ZONE_H */
