// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_kfuncs.h"
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

const char xattr_label[] = "security.bpf.label";
char value_buf[8] = "l";

/* The dentry is not attached yet, so the read goes by the inode. */
SEC("lsm.s/d_instantiate")
__success
int BPF_PROG(allow_inode_read, struct dentry *dentry, struct inode *inode)
{
	struct bpf_dynptr value;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_get_inode_xattr(inode, dentry, xattr_label, &value);
	return 0;
}

/* The parent of a mkdir is an inode; an alias of it is looked up. */
SEC("lsm.s/inode_mkdir")
__success
int BPF_PROG(allow_parent_read, struct inode *dir, struct dentry *dentry,
	     umode_t mode)
{
	struct bpf_dynptr value;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_get_inode_xattr(dir, NULL, xattr_label, &value);
	return 0;
}

/* The read does filesystem I/O, so it is for sleepable programs only. */
SEC("lsm/d_instantiate")
__failure __msg("program must be sleepable to call sleepable kfunc")
int BPF_PROG(reject_non_sleepable, struct dentry *dentry, struct inode *inode)
{
	struct bpf_dynptr value;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_get_inode_xattr(inode, dentry, xattr_label, &value);
	return 0;
}

/* A create instantiates with the inode unlocked and vfs_link() with it
 * locked, so no variant of the writers fits, and they are refused.
 */
SEC("lsm.s/d_instantiate")
__failure __msg("calling kernel function bpf_set_dentry_xattr is not allowed")
int BPF_PROG(reject_write, struct dentry *dentry, struct inode *inode)
{
	struct bpf_dynptr value;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_set_dentry_xattr(dentry, xattr_label, &value, 0);
	return 0;
}
