/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2020 Google LLC.
 */

#ifndef _LINUX_BPF_LSM_H
#define _LINUX_BPF_LSM_H

#include <linux/sched.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/lsm_hooks.h>

struct xattr;
struct qstr;

#ifdef CONFIG_BPF_LSM

extern bool bpf_lsm_initialized __ro_after_init;

#define LSM_HOOK(RET, DEFAULT, NAME, ...) \
	RET bpf_lsm_##NAME(__VA_ARGS__);
#include <linux/lsm_hook_defs.h>
#undef LSM_HOOK

struct bpf_storage_blob {
	struct bpf_local_storage __rcu *storage;
};

extern struct lsm_blob_sizes bpf_lsm_blob_sizes;

/*
 * Number of xattr slots the BPF LSM reserves in the array handed to
 * security_inode_init_security(), i.e. the maximum number of labels a policy
 * may attach to an inode while it is being created.
 */
#define BPF_LSM_INODE_INIT_XATTRS	2

/*
 * Upper bound on the size of a single label value a policy can hand back from
 * bpf_lsm_inode_get_label(). Security labels are short by nature, and the shim
 * has to have a buffer ready before it knows how much the program will write.
 */
#define BPF_LSM_LABEL_SIZE_MAX		1024

enum bpf_lsm_label_op {
	BPF_LSM_LABEL_OP_INIT,
	BPF_LSM_LABEL_OP_GET,
	BPF_LSM_LABEL_OP_SET,
	BPF_LSM_LABEL_OP_LIST,
};

/*
 * Scratch context handed to a BPF LSM program for the duration of one label
 * operation.
 *
 * Several LSM hooks expect the module to hand back memory it allocated itself
 * (struct xattr slots for inode_init_security(), a kmalloc'd buffer for
 * inode_getsecurity()). A BPF program cannot express that ownership transfer,
 * so the shims in bpf_lsm_proto.c own the allocation and let the program fill
 * it in through the bpf_inode_init_xattr(), bpf_set_label_value() and
 * bpf_add_label_name() kfuncs.
 *
 * The label hooks are all sleepable, so this cannot live in a per-CPU slot and
 * is anchored on current instead.
 *
 * @handled tells the shim that the policy answered for this inode, and @error
 * carries a failure out of a kfunc: the program return value cannot be used
 * for either, because BPF_MODIFY_RETURN only overrides the return value when a
 * program returns non-zero.
 */
struct bpf_lsm_label_ctx {
	enum bpf_lsm_label_op	op;
	bool			handled;
	int			error;
	union {
		/* BPF_LSM_LABEL_OP_INIT */
		struct {
			struct xattr	*xattrs;
			int		*count;
			int		 avail;
		} init;
		/* BPF_LSM_LABEL_OP_GET */
		struct {
			void		*buf;
			size_t		 size;
			ssize_t		 used;
		} get;
		/* BPF_LSM_LABEL_OP_LIST */
		struct {
			char		**buf;
			ssize_t		 *remaining;
		} list;
	};
};

/*
 * BPF-friendly counterparts of the LSM label hooks. These are not part of
 * lsm_hook_defs.h: they are driven by the strong hook overrides in
 * bpf_lsm_proto.c, which do the allocation the real hooks demand.
 *
 * They all default to returning 0 even where the hook they stand in for
 * defaults to -EOPNOTSUPP, so "the policy answered" is reported through
 * struct bpf_lsm_label_ctx instead of through the return value.
 */
int bpf_lsm_inode_init_label(struct inode *inode, struct inode *dir,
			     const struct qstr *qstr);
int bpf_lsm_inode_get_label(struct inode *inode, const char *name);
int bpf_lsm_inode_set_label(struct inode *inode, const char *name,
			    const void *value, size_t size, int flags);
int bpf_lsm_inode_list_labels(struct inode *inode);

int bpf_lsm_verify_prog(struct bpf_verifier_log *vlog,
			const struct bpf_prog *prog);

bool bpf_lsm_is_sleepable_hook(u32 btf_id);
bool bpf_lsm_is_trusted(const struct bpf_prog *prog);

static inline struct bpf_storage_blob *bpf_inode(
	const struct inode *inode)
{
	if (unlikely(!inode->i_security))
		return NULL;

	return inode->i_security + bpf_lsm_blob_sizes.lbs_inode;
}

static inline struct bpf_storage_blob *bpf_sb(
	const struct super_block *sb)
{
	if (unlikely(!sb->s_security))
		return NULL;

	return sb->s_security + bpf_lsm_blob_sizes.lbs_superblock;
}

extern const struct bpf_func_proto bpf_inode_storage_get_proto;
extern const struct bpf_func_proto bpf_inode_storage_delete_proto;
extern const struct bpf_func_proto bpf_sb_storage_get_proto;
extern const struct bpf_func_proto bpf_sb_storage_delete_proto;
void bpf_inode_storage_free(struct inode *inode);
void bpf_sb_storage_free(struct super_block *sb);

void bpf_lsm_find_cgroup_shim(const struct bpf_prog *prog, bpf_func_t *bpf_func);

int bpf_lsm_get_retval_range(const struct bpf_prog *prog,
			     struct bpf_retval_range *range);
int bpf_set_dentry_xattr_locked(struct dentry *dentry, const char *name__str,
				const struct bpf_dynptr *value_p, int flags);
int bpf_remove_dentry_xattr_locked(struct dentry *dentry, const char *name__str);
int bpf_set_path_xattr_locked(const struct path *path, const char *name__str,
			      const struct bpf_dynptr *value_p, int flags);
int bpf_remove_path_xattr_locked(const struct path *path, const char *name__str);
bool bpf_lsm_has_d_inode_locked(const struct bpf_prog *prog);
bool bpf_lsm_hook_returns_errno(u32 btf_id);

#else /* !CONFIG_BPF_LSM */

#define bpf_lsm_initialized false

static inline bool bpf_lsm_is_sleepable_hook(u32 btf_id)
{
	return false;
}

static inline bool bpf_lsm_is_trusted(const struct bpf_prog *prog)
{
	return false;
}

static inline int bpf_lsm_verify_prog(struct bpf_verifier_log *vlog,
				      const struct bpf_prog *prog)
{
	return -EOPNOTSUPP;
}

static inline struct bpf_storage_blob *bpf_inode(
	const struct inode *inode)
{
	return NULL;
}

static inline struct bpf_storage_blob *bpf_sb(
	const struct super_block *sb)
{
	return NULL;
}

static inline void bpf_inode_storage_free(struct inode *inode)
{
}

static inline void bpf_sb_storage_free(struct super_block *sb)
{
}

static inline void bpf_lsm_find_cgroup_shim(const struct bpf_prog *prog,
					   bpf_func_t *bpf_func)
{
}

static inline int bpf_lsm_get_retval_range(const struct bpf_prog *prog,
					   struct bpf_retval_range *range)
{
	return -EOPNOTSUPP;
}
static inline int bpf_set_dentry_xattr_locked(struct dentry *dentry, const char *name__str,
					      const struct bpf_dynptr *value_p, int flags)
{
	return -EOPNOTSUPP;
}
static inline int bpf_remove_dentry_xattr_locked(struct dentry *dentry, const char *name__str)
{
	return -EOPNOTSUPP;
}
static inline int bpf_set_path_xattr_locked(const struct path *path, const char *name__str,
					    const struct bpf_dynptr *value_p, int flags)
{
	return -EOPNOTSUPP;
}
static inline int bpf_remove_path_xattr_locked(const struct path *path, const char *name__str)
{
	return -EOPNOTSUPP;
}
static inline bool bpf_lsm_has_d_inode_locked(const struct bpf_prog *prog)
{
	return false;
}

static inline bool bpf_lsm_hook_returns_errno(u32 btf_id)
{
	return true;
}
#endif /* CONFIG_BPF_LSM */

#endif /* _LINUX_BPF_LSM_H */
