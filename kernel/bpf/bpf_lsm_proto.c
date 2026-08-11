// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2025 Google LLC.
 */

#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/xattr.h>
#include <linux/bpf_lsm.h>

/*
 * Strong definition of the mmap_file() BPF LSM hook. The __nullable suffix on
 * the struct file pointer parameter name marks it as PTR_MAYBE_NULL. This
 * explicitly enforces that BPF LSM programs check for NULL before attempting to
 * dereference it.
 */
int bpf_lsm_mmap_file(struct file *file__nullable, unsigned long reqprot,
		      unsigned long prot, unsigned long flags)
{
	return 0;
}

/*
 * Strong definition of the inode_init_security() BPF LSM hook.
 *
 * The hook signature hands the LSM an array of struct xattr slots to fill in
 * with memory the core will later kfree(). A BPF program cannot allocate on
 * behalf of the caller, so the raw hook is on the disabled list and programs
 * attach to bpf_lsm_inode_init_label() instead. This shim publishes the slot
 * array on current for the duration of the call so that bpf_inode_init_xattr()
 * can claim slots from it.
 *
 * Whether the policy provided a label is decided by looking at the slot array
 * rather than at the program return value: BPF_MODIFY_RETURN only overrides
 * the return value when a program returns non-zero, so a program returning 0
 * would otherwise be indistinguishable from no program at all.
 */
int bpf_lsm_inode_init_security(struct inode *inode, struct inode *dir,
				const struct qstr *qstr, struct xattr *xattrs,
				int *xattr_count)
{
	struct bpf_lsm_label_ctx ctx = {
		.op		= BPF_LSM_LABEL_OP_INIT,
		.xattrs		= xattrs,
		.xattr_count	= xattr_count,
		.xattr_avail	= BPF_LSM_INODE_INIT_XATTRS,
	};
	struct bpf_lsm_label_ctx *saved;
	int filled, ret;

	saved = current->bpf_lsm_label;
	current->bpf_lsm_label = &ctx;
	filled = *xattr_count;
	ret = bpf_lsm_inode_init_label(inode, dir, qstr);
	filled = *xattr_count - filled;
	current->bpf_lsm_label = saved;

	if (ret)
		return ret;
	return filled ? 0 : -EOPNOTSUPP;
}
