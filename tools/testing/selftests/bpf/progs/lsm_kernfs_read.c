// SPDX-License-Identifier: GPL-2.0
/* Reading a kernfs node's label from a hook that is not kernfs_init_security.
 *
 * A label can only be written when the node is created, which that one hook
 * alone can do. Reading it neither sleeps nor takes a lock, so it is
 * admitted anywhere -- and has to be, or a label put on a node at creation
 * could never be acted on afterwards.
 *
 * The node here is the one behind the cgroup the task runs in. cgrp->kn is
 * RCU-protected, and kernfs_root() drops its own RCU section before handing
 * back the root the lookup then uses, so the read has to happen inside the
 * caller's section: implicit in the non-sleepable hook below, explicit in
 * the sleepable one.
 */
#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_kfuncs.h"

char _license[] SEC("license") = "GPL";

#define LABEL_MAX	32

extern struct cgroup *bpf_cgroup_from_id(__u64 cgid) __ksym;
extern void bpf_cgroup_release(struct cgroup *cgrp) __ksym;

const char xattr_zone[] = "security.bpf.zone";

__u32 monitored_pid;
int bind_ret = -999;		/* read from a sleepable hook */
int connect_ret = -999;		/* and from one that may not sleep */
char bind_zone[LABEL_MAX];
char connect_zone[LABEL_MAX];

static __always_inline bool monitored(void)
{
	return (bpf_get_current_pid_tgid() >> 32) == monitored_pid;
}

/* Not sleepable: the RCU section the kfunc needs is already held. */
SEC("lsm/socket_connect")
int BPF_PROG(read_at_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen)
{
	struct bpf_dynptr value;
	struct cgroup *cgrp;

	if (!monitored())
		return 0;
	cgrp = bpf_cgroup_from_id(bpf_get_current_cgroup_id());
	if (!cgrp)
		return 0;
	bpf_dynptr_from_mem(connect_zone, sizeof(connect_zone), 0, &value);
	connect_ret = bpf_get_kernfs_xattr(cgrp->kn, xattr_zone, &value);
	bpf_cgroup_release(cgrp);
	return 0;
}

/* Sleepable: nothing holds RCU for us, so the walk and the read are taken
 * inside an explicit section.
 */
SEC("lsm.s/socket_bind")
int BPF_PROG(read_at_bind, struct socket *sock, struct sockaddr *address,
	     int addrlen)
{
	struct bpf_dynptr value;
	struct cgroup *cgrp;

	if (!monitored())
		return 0;
	cgrp = bpf_cgroup_from_id(bpf_get_current_cgroup_id());
	if (!cgrp)
		return 0;
	bpf_dynptr_from_mem(bind_zone, sizeof(bind_zone), 0, &value);
	bpf_rcu_read_lock();
	bind_ret = bpf_get_kernfs_xattr(cgrp->kn, xattr_zone, &value);
	bpf_rcu_read_unlock();
	bpf_cgroup_release(cgrp);
	return 0;
}
