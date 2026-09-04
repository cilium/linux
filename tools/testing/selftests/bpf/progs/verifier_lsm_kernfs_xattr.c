// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_kfuncs.h"
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

const char xattr_zone[] = "security.bpf.zone";
char value_buf[8] = "z";

SEC("lsm.s/kernfs_init_security")
__success
int BPF_PROG(allow_hook_nodes, struct kernfs_node *kn_dir, struct kernfs_node *kn)
{
	struct bpf_dynptr value;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_kernfs_read_xattr(kn_dir, xattr_zone, &value);
	bpf_kernfs_set_xattr(kn, xattr_zone, &value);
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
	bpf_kernfs_set_xattr(kn_dir->__parent, xattr_zone, &value);
	return 0;
}

SEC("lsm.s/kernfs_init_security")
__failure __msg("must be referenced or trusted")
int BPF_PROG(reject_ancestor_read, struct kernfs_node *kn_dir,
	     struct kernfs_node *kn)
{
	struct bpf_dynptr value;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_kernfs_read_xattr(kn_dir->__parent, xattr_zone, &value);
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
	bpf_kernfs_read_xattr(kn_dir, xattr_zone, &value);
	return 0;
}

/* The write allocates and takes the node's mutex, so it does. */
SEC("lsm/kernfs_init_security")
__failure __msg("program must be sleepable to call sleepable kfunc bpf_kernfs_set_xattr")
int BPF_PROG(reject_write_non_sleepable, struct kernfs_node *kn_dir,
	     struct kernfs_node *kn)
{
	struct bpf_dynptr value;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_kernfs_set_xattr(kn, xattr_zone, &value);
	return 0;
}

/*
 * A cgroup-scoped program on the hook returns through the cgroup convention
 * rather than the LSM one, so it is kept away from the kfuncs.
 */
SEC("lsm_cgroup/kernfs_init_security")
__failure __msg("calling kernel function bpf_kernfs_set_xattr is not allowed")
int BPF_PROG(reject_lsm_cgroup, struct kernfs_node *kn_dir,
	     struct kernfs_node *kn)
{
	struct bpf_dynptr value;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_kernfs_set_xattr(kn, xattr_zone, &value);
	return 0;
}

SEC("lsm/inode_init_security")
__failure __msg("calling kernel function bpf_kernfs_read_xattr is not allowed")
int BPF_PROG(reject_wrong_hook, struct inode *inode, struct inode *dir,
	     const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
{
	struct bpf_dynptr value;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_kernfs_read_xattr(NULL, xattr_zone, &value);
	return 0;
}
