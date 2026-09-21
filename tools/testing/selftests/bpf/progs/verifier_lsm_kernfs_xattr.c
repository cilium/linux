// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_kfuncs.h"
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

extern struct cgroup *bpf_cgroup_from_id(__u64 cgid) __ksym;
extern void bpf_cgroup_release(struct cgroup *cgrp) __ksym;

const char xattr_zone[] = "security.bpf.zone";
char value_buf[8] = "z";

SEC("lsm.s/kernfs_init_security")
__success
int BPF_PROG(allow_hook_nodes, struct kernfs_node *kn_dir, struct kernfs_node *kn)
{
	struct bpf_dynptr value;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_get_kernfs_xattr(kn_dir, xattr_zone, &value);
	bpf_set_kernfs_xattr(kn, xattr_zone, &value);
	return 0;
}

/*
 * Walking to an ancestor yields an untrusted pointer, so the two nodes the
 * hook was handed are the only ones a policy can reach. Neither kfunc takes
 * KF_RCU, so this stays true inside an RCU read side too.
 */
SEC("lsm.s/kernfs_init_security")
__failure __msg("must be referenced or trusted")
int BPF_PROG(reject_ancestor_write, struct kernfs_node *kn_dir,
	     struct kernfs_node *kn)
{
	struct bpf_dynptr value;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_set_kernfs_xattr(kn_dir->__parent, xattr_zone, &value);
	return 0;
}

/* The getter takes an RCU pointer, and kernfs_node->__parent is not one:
 * it is not in BTF_TYPE_SAFE_RCU, so it reads back untrusted and an
 * ancestor's label stays out of reach.
 */
SEC("lsm.s/kernfs_init_security")
__failure __msg("must be a rcu pointer")
int BPF_PROG(reject_ancestor_read, struct kernfs_node *kn_dir,
	     struct kernfs_node *kn)
{
	struct bpf_dynptr value;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_get_kernfs_xattr(kn_dir->__parent, xattr_zone, &value);
	return 0;
}

/* The read only walks an rhashtable under RCU, so it needs no sleepable program. */
SEC("lsm/kernfs_init_security")
__success
int BPF_PROG(allow_read_non_sleepable, struct kernfs_node *kn_dir,
	     struct kernfs_node *kn)
{
	struct bpf_dynptr value;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_get_kernfs_xattr(kn_dir, xattr_zone, &value);
	return 0;
}

/* The write allocates and takes the node's mutex, so it does. */
SEC("lsm/kernfs_init_security")
__failure __msg("program must be sleepable to call sleepable kfunc bpf_set_kernfs_xattr")
int BPF_PROG(reject_write_non_sleepable, struct kernfs_node *kn_dir,
	     struct kernfs_node *kn)
{
	struct bpf_dynptr value;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_set_kernfs_xattr(kn, xattr_zone, &value);
	return 0;
}

/*
 * A cgroup-scoped program on the hook returns through the cgroup convention
 * rather than the LSM one, so it is kept away from the kfuncs.
 */
SEC("lsm_cgroup/kernfs_init_security")
__failure __msg("calling kernel function bpf_set_kernfs_xattr is not allowed")
int BPF_PROG(reject_lsm_cgroup, struct kernfs_node *kn_dir,
	     struct kernfs_node *kn)
{
	struct bpf_dynptr value;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_set_kernfs_xattr(kn, xattr_zone, &value);
	return 0;
}

/* Writing a label is still confined to the hook that creates the node, on
 * a hook that has no kernfs node of its own as much as anywhere else.
 */
SEC("lsm/inode_init_security")
__failure __msg("calling kernel function bpf_set_kernfs_xattr is not allowed")
int BPF_PROG(reject_write_wrong_hook, struct inode *inode, struct inode *dir,
	     const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
{
	struct bpf_dynptr value;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_set_kernfs_xattr(NULL, xattr_zone, &value);
	return 0;
}

/* Reading one is not: the node behind a cgroup is an RCU pointer, and a
 * non-sleepable hook is already inside an RCU section.
 */
SEC("lsm/socket_connect")
__success
int BPF_PROG(allow_read_off_hook, struct socket *sock)
{
	struct bpf_dynptr value;
	struct cgroup *cgrp;

	cgrp = bpf_cgroup_from_id(bpf_get_current_cgroup_id());
	if (!cgrp)
		return 0;
	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_get_kernfs_xattr(cgrp->kn, xattr_zone, &value);
	bpf_cgroup_release(cgrp);
	return 0;
}
