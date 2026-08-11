// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Google LLC. */

#include <linux/bpf.h>
#include <linux/bpf_lsm.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/file.h>
#include <linux/kernfs.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/xattr.h>

#include "internal.h"

__bpf_kfunc_start_defs();

/**
 * bpf_get_task_exe_file - get a reference on the exe_file struct file member of
 *                         the mm_struct that is nested within the supplied
 *                         task_struct
 * @task: task_struct of which the nested mm_struct exe_file member to get a
 * reference on
 *
 * Get a reference on the exe_file struct file member field of the mm_struct
 * nested within the supplied *task*. The referenced file pointer acquired by
 * this BPF kfunc must be released using bpf_put_file(). Failing to call
 * bpf_put_file() on the returned referenced struct file pointer that has been
 * acquired by this BPF kfunc will result in the BPF program being rejected by
 * the BPF verifier.
 *
 * This BPF kfunc may only be called from BPF LSM programs.
 *
 * Internally, this BPF kfunc leans on get_task_exe_file(), such that calling
 * bpf_get_task_exe_file() would be analogous to calling get_task_exe_file()
 * directly in kernel context.
 *
 * Return: A referenced struct file pointer to the exe_file member of the
 * mm_struct that is nested within the supplied *task*. On error, NULL is
 * returned.
 */
__bpf_kfunc struct file *bpf_get_task_exe_file(struct task_struct *task)
{
	return get_task_exe_file(task);
}

/**
 * bpf_put_file - put a reference on the supplied file
 * @file: file to put a reference on
 *
 * Put a reference on the supplied *file*. Only referenced file pointers may be
 * passed to this BPF kfunc. Attempting to pass an unreferenced file pointer, or
 * any other arbitrary pointer for that matter, will result in the BPF program
 * being rejected by the BPF verifier.
 *
 * This BPF kfunc may only be called from BPF LSM programs.
 */
__bpf_kfunc void bpf_put_file(struct file *file)
{
	fput(file);
}

/**
 * bpf_path_d_path - resolve the pathname for the supplied path
 * @path: path to resolve the pathname for
 * @buf: buffer to return the resolved pathname in
 * @buf__sz: length of the supplied buffer
 *
 * Resolve the pathname for the supplied *path* and store it in *buf*. This BPF
 * kfunc is the safer variant of the legacy bpf_d_path() helper and should be
 * used in place of bpf_d_path() whenever possible.
 *
 * This BPF kfunc may only be called from BPF LSM programs.
 *
 * Return: A positive integer corresponding to the length of the resolved
 * pathname in *buf*, including the NUL termination character. On error, a
 * negative integer is returned.
 */
__bpf_kfunc int bpf_path_d_path(const struct path *path, char *buf, size_t buf__sz)
{
	int len;
	char *ret;

	if (!buf__sz)
		return -EINVAL;

	ret = d_path(path, buf, buf__sz);
	if (IS_ERR(ret))
		return PTR_ERR(ret);

	len = buf + buf__sz - ret;
	memmove(buf, ret, len);
	return len;
}

static bool match_security_bpf_prefix(const char *name__str)
{
	return !strncmp(name__str, XATTR_NAME_BPF_LSM, XATTR_NAME_BPF_LSM_LEN);
}

/*
 * Decide whether the filesystem is in a state where its xattr handlers can be
 * called for @inode at all.
 *
 * A filesystem may instantiate an inode from inside fill_super(), before its
 * own per-inode state is complete: overlayfs attaches the ovl_entry to its
 * root inode only after d_make_root(), and ovl_i_path_real() dereferences it
 * unconditionally. Reaching a handler in that window oopses. The superblock
 * only gets SB_BORN once vfs_get_tree() has returned, which is exactly the
 * point past which such an inode is safe to touch.
 *
 * SELinux does not need this because it defers label resolution for
 * superblocks it has not initialised yet; a BPF policy has no such state, so
 * enforce the precondition here rather than relying on it being observed.
 */
static int bpf_xattr_inode_ready(struct inode *inode)
{
	if (!inode)
		return -EINVAL;
	if (!(READ_ONCE(inode->i_sb->s_flags) & SB_BORN))
		return -EBUSY;
	return 0;
}

static int bpf_xattr_read_permission(const char *name, struct inode *inode,
				     struct mnt_idmap *idmap)
{
	int ret;

	ret = bpf_xattr_inode_ready(inode);
	if (ret)
		return ret;

	/*
	 * security.bpf.* belongs to the LSM, so reading it is not gated on the
	 * accessing task's permission to the object, the same way SELinux
	 * reads security.selinux without consulting the subject. Requiring
	 * MAY_READ here would make it impossible to consult the label of an
	 * object the task cannot read, such as an executable being checked on
	 * the bprm hooks, or any directory.
	 */
	if (match_security_bpf_prefix(name))
		return 0;

	/* user.* is ordinary user data, so it stays behind the usual check. */
	if (strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN))
		return -EPERM;

	return inode_permission(idmap, inode, MAY_READ);
}

static int bpf_xattr_get(struct dentry *dentry, struct inode *inode,
			 struct mnt_idmap *idmap, const char *name__str,
			 struct bpf_dynptr *value_p)
{
	struct bpf_dynptr_kern *value_ptr = (struct bpf_dynptr_kern *)value_p;
	u32 value_len;
	void *value;
	int ret;

	value_len = __bpf_dynptr_size(value_ptr);
	value = __bpf_dynptr_data_rw(value_ptr, value_len);
	if (!value)
		return -EINVAL;

	ret = bpf_xattr_read_permission(name__str, inode, idmap);
	if (ret)
		return ret;
	return __vfs_getxattr(dentry, inode, name__str, value, value_len);
}

/**
 * bpf_get_dentry_xattr - get xattr of a dentry
 * @dentry: dentry to get xattr from
 * @name__str: name of the xattr
 * @value_p: output buffer of the xattr value
 *
 * Get xattr *name__str* of *dentry* and store the output in *value_ptr*.
 *
 * For security reasons, only *name__str* with prefixes "user." or
 * "security.bpf." are allowed.
 *
 * A dentry carries no mount, so "user." xattrs are checked against the
 * filesystem as if it were not idmapped. Use bpf_get_path_xattr() or
 * bpf_get_file_xattr() where a mount is available.
 *
 * Return: length of the xattr value on success, a negative value on error.
 */
__bpf_kfunc int bpf_get_dentry_xattr(struct dentry *dentry, const char *name__str,
				     struct bpf_dynptr *value_p)
{
	return bpf_xattr_get(dentry, d_inode(dentry), &nop_mnt_idmap,
			     name__str, value_p);
}

/**
 * bpf_get_file_xattr - get xattr of a file
 * @file: file to get xattr from
 * @name__str: name of the xattr
 * @value_p: output buffer of the xattr value
 *
 * Get xattr *name__str* of *file* and store the output in *value_ptr*.
 *
 * For security reasons, only *name__str* with prefixes "user." or
 * "security.bpf." are allowed.
 *
 * Return: length of the xattr value on success, a negative value on error.
 */
__bpf_kfunc int bpf_get_file_xattr(struct file *file, const char *name__str,
				   struct bpf_dynptr *value_p)
{
	struct dentry *dentry = file_dentry(file);

	return bpf_xattr_get(dentry, d_inode(dentry), file_mnt_idmap(file),
			     name__str, value_p);
}

/**
 * bpf_get_path_xattr - get xattr of a path
 * @path: path to get xattr from
 * @name__str: name of the xattr
 * @value_p: output buffer of the xattr value
 *
 * Get xattr *name__str* of *path* and store the output in *value_ptr*.
 *
 * For security reasons, only *name__str* with prefixes "user." or
 * "security.bpf." are allowed.
 *
 * Return: length of the xattr value on success, a negative value on error.
 */
__bpf_kfunc int bpf_get_path_xattr(const struct path *path, const char *name__str,
				   struct bpf_dynptr *value_p)
{
	return bpf_xattr_get(path->dentry, d_inode(path->dentry),
			     mnt_idmap(path->mnt), name__str, value_p);
}

/**
 * bpf_get_inode_xattr - get xattr of an inode
 * @inode: inode to get xattr from
 * @name__str: name of the xattr
 * @value_p: output buffer of the xattr value
 *
 * Get xattr *name__str* of *inode* and store the output in *value_ptr*. For
 * hooks such as bpf_lsm_inode_get_label() that are handed an inode and nothing
 * else; where a dentry, file or path is available, prefer those variants.
 *
 * The xattr handlers are reached through an arbitrary alias of *inode*, and
 * the lookup fails with -ENOENT if the inode has none. As with
 * bpf_get_dentry_xattr(), there is no mount to derive an idmap from.
 *
 * For security reasons, only *name__str* with prefixes "user." or
 * "security.bpf." are allowed.
 *
 * Return: length of the xattr value on success, a negative value on error.
 */
__bpf_kfunc int bpf_get_inode_xattr(struct inode *inode, const char *name__str,
				    struct bpf_dynptr *value_p)
{
	struct dentry *dentry;
	int ret;

	dentry = d_find_alias(inode);
	if (!dentry)
		return -ENOENT;
	ret = bpf_xattr_get(dentry, inode, &nop_mnt_idmap, name__str, value_p);
	dput(dentry);

	return ret;
}

/**
 * bpf_get_dentry_inode_xattr - get xattr of a dentry and inode pair
 * @dentry: dentry to get xattr from
 * @inode: inode backing @dentry
 * @name__str: name of the xattr
 * @value_p: output buffer of the xattr value
 *
 * Get xattr *name__str* of the (*dentry*, *inode*) pair and store the output in
 * *value_ptr*.
 *
 * Needed on hooks that are handed both because the two are not yet joined up,
 * most notably bpf_lsm_d_instantiate(), where d_inode() is still NULL and the
 * inode has no alias for bpf_get_inode_xattr() to find. This is the pair
 * SELinux resolves a label from when it caches one at instantiation time.
 *
 * For security reasons, only *name__str* with prefixes "user." or
 * "security.bpf." are allowed.
 *
 * Return: length of the xattr value on success, a negative value on error.
 */
__bpf_kfunc int bpf_get_dentry_inode_xattr(struct dentry *dentry,
					   struct inode *inode,
					   const char *name__str,
					   struct bpf_dynptr *value_p)
{
	return bpf_xattr_get(dentry, inode, &nop_mnt_idmap, name__str, value_p);
}

/**
 * bpf_list_dentry_xattr - list the xattr names of a dentry
 * @dentry: dentry to list the xattrs of
 * @buf_p: output buffer for the NUL-separated list of names
 *
 * Store the names of the xattrs of *dentry* in *buf_p* as a sequence of
 * NUL-terminated strings, so that a policy can discover which labels an object
 * carries instead of having to probe for names it already knows.
 *
 * This reports what the filesystem stores. It deliberately does not run the
 * inode_listxattr() and inode_listsecurity() hooks, both because a program on
 * those hooks would recurse into itself and because a policy wants to see the
 * unfiltered on-disk state.
 *
 * Return: length of the name list on success, a negative value on error.
 */
__bpf_kfunc int bpf_list_dentry_xattr(struct dentry *dentry,
				      struct bpf_dynptr *buf_p)
{
	struct bpf_dynptr_kern *buf_ptr = (struct bpf_dynptr_kern *)buf_p;
	struct inode *inode = d_inode(dentry);
	u32 buf_len;
	void *buf;
	int ret;

	ret = bpf_xattr_inode_ready(inode);
	if (ret)
		return ret;
	if (!inode->i_op->listxattr)
		return -EOPNOTSUPP;

	buf_len = __bpf_dynptr_size(buf_ptr);
	buf = __bpf_dynptr_data_rw(buf_ptr, buf_len);
	if (!buf)
		return -EINVAL;

	return inode->i_op->listxattr(dentry, buf, buf_len);
}

__bpf_kfunc_end_defs();

static int bpf_xattr_write_permission(const char *name, struct inode *inode,
				      struct mnt_idmap *idmap)
{
	int ret;

	ret = bpf_xattr_inode_ready(inode);
	if (ret)
		return ret;

	/* Only allow setting and removing security.bpf. xattrs */
	if (!match_security_bpf_prefix(name))
		return -EPERM;

	/*
	 * As on the read side, labelling an object is the LSM's business and
	 * not the accessing task's, so this does not check MAY_WRITE: a policy
	 * has to be able to label a file opened read-only, or one the task has
	 * no write access to at all. What does still apply is whether the
	 * inode can take an xattr write at all, which is what the VFS itself
	 * demands before any setxattr.
	 */
	return may_write_xattr(idmap, inode);
}

static int bpf_xattr_set(struct dentry *dentry, struct mnt_idmap *idmap,
			 const char *name__str, const struct bpf_dynptr *value_p,
			 int flags)
{
	const struct bpf_dynptr_kern *value_ptr = (struct bpf_dynptr_kern *)value_p;
	struct inode *inode = d_inode(dentry);
	const void *value;
	u32 value_len;
	int ret;

	value_len = __bpf_dynptr_size(value_ptr);
	value = __bpf_dynptr_data(value_ptr, value_len);
	if (!value)
		return -EINVAL;

	ret = bpf_xattr_write_permission(name__str, inode, idmap);
	if (ret)
		return ret;

	ret = __vfs_setxattr(idmap, dentry, inode, name__str,
			     value, value_len, flags);
	if (!ret) {
		fsnotify_xattr(dentry);

		/*
		 * This xattr is set by BPF LSM, so we do not call
		 * security_inode_post_setxattr. Otherwise, we would
		 * risk deadlocks by calling back to the same kfunc.
		 *
		 * This is the same as security_inode_setsecurity().
		 */
	}
	return ret;
}

static int bpf_xattr_remove(struct dentry *dentry, struct mnt_idmap *idmap,
			    const char *name__str)
{
	struct inode *inode = d_inode(dentry);
	int ret;

	ret = bpf_xattr_write_permission(name__str, inode, idmap);
	if (ret)
		return ret;

	ret = __vfs_removexattr(idmap, dentry, name__str);
	if (!ret) {
		fsnotify_xattr(dentry);

		/*
		 * This xattr is removed by BPF LSM, so we do not call
		 * security_inode_post_removexattr. Otherwise, we would
		 * risk deadlocks by calling back to the same kfunc.
		 */
	}
	return ret;
}

/**
 * bpf_set_dentry_xattr_locked - set a xattr of a dentry
 * @dentry: dentry to get xattr from
 * @name__str: name of the xattr
 * @value_p: xattr value
 * @flags: flags to pass into filesystem operations
 *
 * Set xattr *name__str* of *dentry* to the value in *value_ptr*.
 *
 * For security reasons, only *name__str* with prefix "security.bpf."
 * is allowed.
 *
 * The caller already locked dentry->d_inode.
 *
 * Return: 0 on success, a negative value on error.
 */
int bpf_set_dentry_xattr_locked(struct dentry *dentry, const char *name__str,
				const struct bpf_dynptr *value_p, int flags)
{
	return bpf_xattr_set(dentry, &nop_mnt_idmap, name__str, value_p, flags);
}

/**
 * bpf_remove_dentry_xattr_locked - remove a xattr of a dentry
 * @dentry: dentry to get xattr from
 * @name__str: name of the xattr
 *
 * Rmove xattr *name__str* of *dentry*.
 *
 * For security reasons, only *name__str* with prefix "security.bpf."
 * is allowed.
 *
 * The caller already locked dentry->d_inode.
 *
 * Return: 0 on success, a negative value on error.
 */
int bpf_remove_dentry_xattr_locked(struct dentry *dentry, const char *name__str)
{
	return bpf_xattr_remove(dentry, &nop_mnt_idmap, name__str);
}

/**
 * bpf_set_path_xattr_locked - set a xattr of a path
 * @path: path to set xattr on
 * @name__str: name of the xattr
 * @value_p: xattr value
 * @flags: flags to pass into filesystem operations
 *
 * Set xattr *name__str* of *path* to the value in *value_ptr*.
 *
 * For security reasons, only *name__str* with prefix "security.bpf."
 * is allowed.
 *
 * The caller already locked path->dentry->d_inode.
 *
 * Return: 0 on success, a negative value on error.
 */
int bpf_set_path_xattr_locked(const struct path *path, const char *name__str,
			      const struct bpf_dynptr *value_p, int flags)
{
	return bpf_xattr_set(path->dentry, mnt_idmap(path->mnt), name__str,
			     value_p, flags);
}

/**
 * bpf_remove_path_xattr_locked - remove a xattr of a path
 * @path: path to remove the xattr from
 * @name__str: name of the xattr
 *
 * Remove xattr *name__str* of *path*.
 *
 * For security reasons, only *name__str* with prefix "security.bpf."
 * is allowed.
 *
 * The caller already locked path->dentry->d_inode.
 *
 * Return: 0 on success, a negative value on error.
 */
int bpf_remove_path_xattr_locked(const struct path *path, const char *name__str)
{
	return bpf_xattr_remove(path->dentry, mnt_idmap(path->mnt), name__str);
}

__bpf_kfunc_start_defs();

/**
 * bpf_set_dentry_xattr - set a xattr of a dentry
 * @dentry: dentry to get xattr from
 * @name__str: name of the xattr
 * @value_p: xattr value
 * @flags: flags to pass into filesystem operations
 *
 * Set xattr *name__str* of *dentry* to the value in *value_ptr*.
 *
 * For security reasons, only *name__str* with prefix "security.bpf."
 * is allowed.
 *
 * The caller has not locked dentry->d_inode.
 *
 * Return: 0 on success, a negative value on error.
 */
__bpf_kfunc int bpf_set_dentry_xattr(struct dentry *dentry, const char *name__str,
				     const struct bpf_dynptr *value_p, int flags)
{
	struct inode *inode = d_inode(dentry);
	int ret;

	if (!inode)
		return -EINVAL;

	inode_lock(inode);
	ret = bpf_set_dentry_xattr_locked(dentry, name__str, value_p, flags);
	inode_unlock(inode);
	return ret;
}

/**
 * bpf_remove_dentry_xattr - remove a xattr of a dentry
 * @dentry: dentry to get xattr from
 * @name__str: name of the xattr
 *
 * Rmove xattr *name__str* of *dentry*.
 *
 * For security reasons, only *name__str* with prefix "security.bpf."
 * is allowed.
 *
 * The caller has not locked dentry->d_inode.
 *
 * Return: 0 on success, a negative value on error.
 */
__bpf_kfunc int bpf_remove_dentry_xattr(struct dentry *dentry, const char *name__str)
{
	struct inode *inode = d_inode(dentry);
	int ret;

	if (!inode)
		return -EINVAL;

	inode_lock(inode);
	ret = bpf_remove_dentry_xattr_locked(dentry, name__str);
	inode_unlock(inode);
	return ret;
}

/**
 * bpf_set_path_xattr - set a xattr of a path
 * @path: path to set the xattr on
 * @name__str: name of the xattr
 * @value_p: xattr value
 * @flags: flags to pass into filesystem operations
 *
 * Set xattr *name__str* of *path* to the value in *value_ptr*. Unlike
 * bpf_set_dentry_xattr() this knows the mount the object was reached through,
 * so it applies the idmapping of that mount.
 *
 * For security reasons, only *name__str* with prefix "security.bpf."
 * is allowed.
 *
 * The caller has not locked path->dentry->d_inode.
 *
 * Return: 0 on success, a negative value on error.
 */
__bpf_kfunc int bpf_set_path_xattr(const struct path *path, const char *name__str,
				   const struct bpf_dynptr *value_p, int flags)
{
	struct inode *inode = d_inode(path->dentry);
	int ret;

	if (!inode)
		return -EINVAL;

	inode_lock(inode);
	ret = bpf_set_path_xattr_locked(path, name__str, value_p, flags);
	inode_unlock(inode);
	return ret;
}

/**
 * bpf_remove_path_xattr - remove a xattr of a path
 * @path: path to remove the xattr from
 * @name__str: name of the xattr
 *
 * Remove xattr *name__str* of *path*.
 *
 * For security reasons, only *name__str* with prefix "security.bpf."
 * is allowed.
 *
 * The caller has not locked path->dentry->d_inode.
 *
 * Return: 0 on success, a negative value on error.
 */
__bpf_kfunc int bpf_remove_path_xattr(const struct path *path, const char *name__str)
{
	struct inode *inode = d_inode(path->dentry);
	int ret;

	if (!inode)
		return -EINVAL;

	inode_lock(inode);
	ret = bpf_remove_path_xattr_locked(path, name__str);
	inode_unlock(inode);
	return ret;
}

/**
 * bpf_inode_init_xattr - attach a xattr to an inode that is being created
 * @name__str: name of the xattr
 * @value_p: xattr value
 *
 * Claim one of the slots the BPF LSM reserved in the xattr array that
 * security_inode_init_security() hands to the filesystem, so that xattr
 * *name__str* is written out as part of the transaction creating the inode.
 * Compared to setting the xattr from a hook that runs after creation this
 * leaves no window in which the inode exists unlabelled.
 *
 * Only callable from a bpf_lsm_inode_init_label() program, and only for
 * *name__str* with prefix "security.bpf.". At most BPF_LSM_INODE_INIT_XATTRS
 * xattrs can be attached to one inode.
 *
 * Return: 0 on success, a negative value on error.
 */
__bpf_kfunc int bpf_inode_init_xattr(const char *name__str,
				     const struct bpf_dynptr *value_p)
{
	const struct bpf_dynptr_kern *value_ptr = (struct bpf_dynptr_kern *)value_p;
	struct bpf_lsm_label_ctx *lctx = current->bpf_lsm_label;
	const char *suffix;
	struct xattr *slot;
	const void *value;
	u32 value_len;
	size_t name_len;
	char *buf;

	if (!lctx || lctx->op != BPF_LSM_LABEL_OP_INIT)
		return -EINVAL;
	if (!match_security_bpf_prefix(name__str))
		return -EPERM;
	/*
	 * The array is only allocated when the filesystem supplied an
	 * initxattrs() callback, i.e. when it is able to store xattrs at all.
	 */
	if (!lctx->init.xattrs)
		return -EOPNOTSUPP;
	if (lctx->init.avail <= 0)
		return -ENOSPC;

	value_len = __bpf_dynptr_size(value_ptr);
	value = __bpf_dynptr_data(value_ptr, value_len);
	if (!value)
		return -EINVAL;
	if (value_len > XATTR_SIZE_MAX)
		return -E2BIG;

	/*
	 * The slot stores the name without the "security." prefix, which
	 * initxattrs() puts back. security_inode_init_security() releases
	 * ->value but not ->name, so carve both out of one allocation anchored
	 * at ->value and the trailing name copy is freed along with it.
	 */
	suffix = name__str + XATTR_SECURITY_PREFIX_LEN;
	name_len = strlen(suffix);

	buf = kmalloc(value_len + name_len + 1, GFP_NOFS);
	if (!buf)
		return -ENOMEM;
	memcpy(buf, value, value_len);
	memcpy(buf + value_len, suffix, name_len + 1);

	slot = lsm_get_xattr_slot(lctx->init.xattrs, lctx->init.count);
	slot->value = buf;
	slot->value_len = value_len;
	slot->name = buf + value_len;
	lctx->init.avail--;
	lctx->handled = true;

	return 0;
}

/**
 * bpf_set_label_value - supply the label value for a pending label read
 * @value_p: label value
 *
 * Answer the bpf_lsm_inode_get_label() call in progress with the contents of
 * *value_p*, which becomes the result of getxattr() for that label. This lets
 * a policy present something other than the raw bytes stored on disk, and lets
 * it present a label at all on a filesystem that cannot store xattrs.
 *
 * Not calling this leaves the read to fall back on the on-disk value, as does
 * returning an error from here without retrying.
 *
 * Return: 0 on success, a negative value on error.
 */
__bpf_kfunc int bpf_set_label_value(const struct bpf_dynptr *value_p)
{
	const struct bpf_dynptr_kern *value_ptr = (struct bpf_dynptr_kern *)value_p;
	struct bpf_lsm_label_ctx *lctx = current->bpf_lsm_label;
	const void *value;
	u32 value_len;

	if (!lctx || lctx->op != BPF_LSM_LABEL_OP_GET)
		return -EINVAL;

	value_len = __bpf_dynptr_size(value_ptr);
	value = __bpf_dynptr_data(value_ptr, value_len);
	if (!value)
		return -EINVAL;
	if (value_len > lctx->get.size)
		return -E2BIG;

	memcpy(lctx->get.buf, value, value_len);
	lctx->get.used = value_len;
	lctx->handled = true;

	return 0;
}

/**
 * bpf_add_label_name - advertise a label name for a pending label listing
 * @name__str: name of the label
 *
 * Append *name__str* to the name list being built by the
 * bpf_lsm_inode_list_labels() call in progress, so that listxattr() reports
 * the label even when nothing is stored on disk for it. May be called more
 * than once to advertise several labels.
 *
 * For security reasons, only *name__str* with prefix "security.bpf." is
 * allowed.
 *
 * Return: 0 on success, a negative value on error. -ERANGE means the caller
 * supplied buffer is too small, and is reported back to it.
 */
__bpf_kfunc int bpf_add_label_name(const char *name__str)
{
	struct bpf_lsm_label_ctx *lctx = current->bpf_lsm_label;
	int ret;

	if (!lctx || lctx->op != BPF_LSM_LABEL_OP_LIST)
		return -EINVAL;
	if (!match_security_bpf_prefix(name__str))
		return -EPERM;

	ret = xattr_list_one(lctx->list.buf, lctx->list.remaining, name__str);
	if (ret) {
		/*
		 * Whether the listing fits is the caller's business, not the
		 * policy's, so make sure it is reported even if the program
		 * ignores the return value.
		 */
		lctx->error = ret;
		return ret;
	}
	lctx->handled = true;

	return 0;
}

/**
 * bpf_claim_label - take responsibility for the pending label operation
 *
 * Tell the LSM layer that this policy answered for the inode, without handing
 * back a value. Needed on the bpf_lsm_inode_set_label() path, where the label
 * has nowhere on-disk to live and the program is expected to have stored it
 * itself, typically in inode local storage.
 *
 * Return: 0 on success, a negative value on error.
 */
__bpf_kfunc int bpf_claim_label(void)
{
	struct bpf_lsm_label_ctx *lctx = current->bpf_lsm_label;

	if (!lctx)
		return -EINVAL;
	lctx->handled = true;

	return 0;
}

#ifdef CONFIG_CGROUPS
/**
 * bpf_cgroup_read_xattr - read xattr of a cgroup's node in cgroupfs
 * @cgroup: cgroup to get xattr from
 * @name__str: name of the xattr
 * @value_p: output buffer of the xattr value
 *
 * Get xattr *name__str* of *cgroup* and store the output in *value_ptr*.
 *
 * For security reasons, only *name__str* with prefix "user." is allowed.
 *
 * Return: length of the xattr value on success, a negative value on error.
 */
__bpf_kfunc int bpf_cgroup_read_xattr(struct cgroup *cgroup, const char *name__str,
					struct bpf_dynptr *value_p)
{
	struct bpf_dynptr_kern *value_ptr = (struct bpf_dynptr_kern *)value_p;
	u32 value_len;
	void *value;

	/* Only allow reading "user.*" xattrs */
	if (strncmp(name__str, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN))
		return -EPERM;

	value_len = __bpf_dynptr_size(value_ptr);
	value = __bpf_dynptr_data_rw(value_ptr, value_len);
	if (!value)
		return -EINVAL;

	return kernfs_xattr_get(cgroup->kn, name__str, value, value_len);
}
#endif /* CONFIG_CGROUPS */

/**
 * bpf_real_data_inode - get the real inode hosting a file's data
 * @file: file to resolve
 *
 * Resolve @file to the inode that hosts its data. For a regular file on a
 * union/overlay filesystem this is the underlying (upper or lower) inode that
 * stores the data, not the overlay inode.
 *
 * Data resolution only applies to regular files. For a non-regular file (e.g.
 * a device node, fifo or socket) on a union/overlay filesystem the overlay
 * inode itself is returned; for any file on a non-union filesystem the inode
 * attached to @file is returned.
 *
 * Return: The inode hosting @file's data, or NULL.
 */
__bpf_kfunc struct inode *bpf_real_data_inode(struct file *file)
{
	return d_real_inode(file_dentry(file));
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_fs_kfunc_set_ids)
BTF_ID_FLAGS(func, bpf_get_task_exe_file, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_put_file, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_path_d_path)
BTF_ID_FLAGS(func, bpf_get_dentry_xattr, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_get_file_xattr, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_get_path_xattr, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_get_inode_xattr, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_get_dentry_inode_xattr, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_list_dentry_xattr, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_set_dentry_xattr, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_remove_dentry_xattr, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_set_path_xattr, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_remove_path_xattr, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_real_data_inode, KF_SLEEPABLE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_inode_init_xattr, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_set_label_value)
BTF_ID_FLAGS(func, bpf_add_label_name)
BTF_ID_FLAGS(func, bpf_claim_label)
BTF_KFUNCS_END(bpf_fs_kfunc_set_ids)

/*
 * These operate on the struct bpf_lsm_label_ctx that the shims in
 * bpf_lsm_proto.c publish on current, which only exists while one of the label
 * hooks is running. Restrict them to those hooks; which of the four kfuncs
 * suits which hook is then enforced at runtime against ctx->op.
 */
BTF_SET_START(label_kfunc_ids)
BTF_ID(func, bpf_inode_init_xattr)
BTF_ID(func, bpf_set_label_value)
BTF_ID(func, bpf_add_label_name)
BTF_ID(func, bpf_claim_label)
BTF_SET_END(label_kfunc_ids)

BTF_SET_START(label_hooks)
BTF_ID(func, bpf_lsm_inode_init_label)
BTF_ID(func, bpf_lsm_inode_get_label)
BTF_ID(func, bpf_lsm_inode_set_label)
BTF_ID(func, bpf_lsm_inode_list_labels)
BTF_SET_END(label_hooks)

static int bpf_fs_kfuncs_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
	if (!btf_id_set8_contains(&bpf_fs_kfunc_set_ids, kfunc_id))
		return 0;
	if (prog->type != BPF_PROG_TYPE_LSM)
		return -EACCES;
	if (btf_id_set_contains(&label_kfunc_ids, kfunc_id) &&
	    !btf_id_set_contains(&label_hooks, prog->aux->attach_btf_id))
		return -EACCES;
	return 0;
}

/* bpf_[set|remove]_dentry_xattr.* hooks have KF_SLEEPABLE, so they are only
 * available to sleepable hooks with dentry arguments.
 *
 * Setting and removing xattr requires exclusive lock on dentry->d_inode.
 * Some hooks already locked d_inode, while some hooks have not locked
 * d_inode. Therefore, we need different kfuncs for different hooks.
 * Specifically, hooks in the following list (d_inode_locked_hooks)
 * should call bpf_[set|remove]_dentry_xattr_locked; while other hooks
 * should call bpf_[set|remove]_dentry_xattr.
 */
BTF_SET_START(d_inode_locked_hooks)
BTF_ID(func, bpf_lsm_inode_post_removexattr)
BTF_ID(func, bpf_lsm_inode_post_setattr)
BTF_ID(func, bpf_lsm_inode_post_setxattr)
BTF_ID(func, bpf_lsm_inode_removexattr)
BTF_ID(func, bpf_lsm_inode_rmdir)
BTF_ID(func, bpf_lsm_inode_setattr)
BTF_ID(func, bpf_lsm_inode_setxattr)
BTF_ID(func, bpf_lsm_inode_unlink)
#ifdef CONFIG_SECURITY_PATH
BTF_ID(func, bpf_lsm_path_unlink)
BTF_ID(func, bpf_lsm_path_rmdir)
#endif /* CONFIG_SECURITY_PATH */
BTF_SET_END(d_inode_locked_hooks)

bool bpf_lsm_has_d_inode_locked(const struct bpf_prog *prog)
{
	return btf_id_set_contains(&d_inode_locked_hooks, prog->aux->attach_btf_id);
}

static const struct btf_kfunc_id_set bpf_fs_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_fs_kfunc_set_ids,
	.filter = bpf_fs_kfuncs_filter,
};

static int __init bpf_fs_kfuncs_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_LSM, &bpf_fs_kfunc_set);
}

late_initcall(bpf_fs_kfuncs_init);
