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
		.op = BPF_LSM_LABEL_OP_INIT,
		.init = {
			.xattrs	= xattrs,
			.count	= xattr_count,
			.avail	= BPF_LSM_INODE_INIT_XATTRS,
		},
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
	if (ctx.error)
		return ctx.error;
	return filled ? 0 : -EOPNOTSUPP;
}

/*
 * The names security_inode_{get,set}security() pass down have already had the
 * "security." prefix stripped, so a BPF LSM label is "bpf.<something>".
 */
static bool is_bpf_lsm_suffix(const char *name)
{
	return !strncmp(name, XATTR_BPF_LSM_SUFFIX,
			sizeof(XATTR_BPF_LSM_SUFFIX) - 1);
}

/*
 * Strong definition of the inode_getsecurity() BPF LSM hook.
 *
 * This is what lets a policy present a label that is not simply the raw bytes
 * on disk: SELinux uses the equivalent to translate an on-disk context through
 * current policy, and it is the only way to show a label at all on a
 * filesystem that cannot store xattrs.
 *
 * The hook is expected to hand back a buffer the caller kfree()s, which a BPF
 * program cannot allocate. Collect the label into a bounded scratch buffer
 * instead and duplicate it to the exact size once the program is done.
 */
int bpf_lsm_inode_getsecurity(struct mnt_idmap *idmap, struct inode *inode,
			      const char *name, void **buffer, bool alloc)
{
	struct bpf_lsm_label_ctx ctx = { .op = BPF_LSM_LABEL_OP_GET };
	struct bpf_lsm_label_ctx *saved;
	void *out;
	int ret;

	if (!is_bpf_lsm_suffix(name))
		return -EOPNOTSUPP;

	ctx.get.buf = kmalloc(BPF_LSM_LABEL_SIZE_MAX, GFP_KERNEL);
	if (!ctx.get.buf)
		return -ENOMEM;
	ctx.get.size = BPF_LSM_LABEL_SIZE_MAX;

	saved = current->bpf_lsm_label;
	current->bpf_lsm_label = &ctx;
	ret = bpf_lsm_inode_get_label(inode, name);
	current->bpf_lsm_label = saved;

	if (!ret)
		ret = ctx.error;
	if (!ret && !ctx.handled)
		ret = -EOPNOTSUPP;
	if (ret)
		goto out;

	if (alloc) {
		out = kmemdup(ctx.get.buf, ctx.get.used, GFP_KERNEL);
		if (!out) {
			ret = -ENOMEM;
			goto out;
		}
		*buffer = out;
	}
	ret = ctx.get.used;
out:
	kfree(ctx.get.buf);
	return ret;
}

/*
 * Strong definition of the inode_setsecurity() BPF LSM hook.
 *
 * Reached from __vfs_setxattr_noperm() when the filesystem has no xattr
 * handler of its own, i.e. when the label has nowhere on-disk to live and the
 * policy is expected to keep it itself, typically in inode local storage.
 *
 * Unlike the get side there is nothing to hand back, so the program only has
 * to claim the operation with bpf_claim_label().
 */
int bpf_lsm_inode_setsecurity(struct inode *inode, const char *name,
			      const void *value, size_t size, int flags)
{
	struct bpf_lsm_label_ctx ctx = { .op = BPF_LSM_LABEL_OP_SET };
	struct bpf_lsm_label_ctx *saved;
	int ret;

	if (!is_bpf_lsm_suffix(name))
		return -EOPNOTSUPP;

	saved = current->bpf_lsm_label;
	current->bpf_lsm_label = &ctx;
	ret = bpf_lsm_inode_set_label(inode, name, value, size, flags);
	current->bpf_lsm_label = saved;

	if (!ret)
		ret = ctx.error;
	if (ret)
		return ret;
	return ctx.handled ? 0 : -EOPNOTSUPP;
}

/*
 * Strong definition of the inode_listsecurity() BPF LSM hook.
 *
 * Appends the names of the labels the policy claims for this inode, so that
 * listxattr() reports them even when nothing is stored on disk. The hook is
 * additive across LSMs, so this returns 0 on success to let the remaining
 * modules contribute their own names.
 */
int bpf_lsm_inode_listsecurity(struct inode *inode, char **buffer,
			       ssize_t *remaining_size)
{
	struct bpf_lsm_label_ctx ctx = {
		.op = BPF_LSM_LABEL_OP_LIST,
		.list = {
			.buf		= buffer,
			.remaining	= remaining_size,
		},
	};
	struct bpf_lsm_label_ctx *saved;
	int ret;

	saved = current->bpf_lsm_label;
	current->bpf_lsm_label = &ctx;
	ret = bpf_lsm_inode_list_labels(inode);
	current->bpf_lsm_label = saved;

	return ret ? ret : ctx.error;
}
