// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_kfuncs.h"
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

const char xattr_zone[] = "security.bpf.zone";
char value_buf[8] = "z";
int scratch_count;

SEC("lsm/inode_init_security")
__failure __msg("cannot write into rdonly_trusted_mem")
int BPF_PROG(reject_count_write, struct inode *inode, struct inode *dir,
	     const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
{
	*xattr_count = 0;
	return 0;
}

SEC("lsm/inode_init_security")
__success
int BPF_PROG(allow_count_read, struct inode *inode, struct inode *dir,
	     const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
{
	scratch_count = *xattr_count;
	return 0;
}

/*
 * The hook is handed a NULL array whenever the filesystem creating the inode
 * takes no xattrs, so the array has to be checked before it is passed on.
 */
SEC("lsm/inode_init_security")
__failure __msg("Possibly NULL pointer passed to trusted")
int BPF_PROG(reject_unchecked_xattrs, struct inode *inode, struct inode *dir,
	     const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
{
	struct bpf_dynptr value;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_inode_init_xattr(xattrs, xattr_count, xattr_zone, &value);
	return 0;
}

/* Same for the qstr, which is NULL for an inode created without a name. */
SEC("lsm/inode_init_security")
__failure __msg("invalid mem access 'trusted_ptr_or_null_'")
int BPF_PROG(reject_unchecked_qstr, struct inode *inode, struct inode *dir,
	     const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
{
	scratch_count = qstr->len;
	return 0;
}

SEC("lsm/inode_init_security")
__success
int BPF_PROG(allow_spilled_count, struct inode *inode, struct inode *dir,
	     const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
{
	struct bpf_dynptr value;
	int *saved = xattr_count;

	if (!xattrs)
		return 0;

	/* The call spills the pointer, it must keep its type across the fill. */
	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_inode_init_xattr(xattrs, saved, xattr_zone, &value);
	return 0;
}

SEC("lsm/inode_init_security")
__failure __msg("expected a hook output argument loaded from ctx")
int BPF_PROG(reject_forged_count, struct inode *inode, struct inode *dir,
	     const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
{
	struct bpf_dynptr value;

	if (!xattrs)
		return 0;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_inode_init_xattr(xattrs, &scratch_count, xattr_zone, &value);
	return 0;
}

SEC("lsm/inode_init_security")
__failure __msg("expected a hook output argument loaded from ctx")
int BPF_PROG(reject_stack_count, struct inode *inode, struct inode *dir,
	     const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
{
	struct bpf_dynptr value;
	int local = 0;

	if (!xattrs)
		return 0;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_inode_init_xattr(xattrs, &local, xattr_zone, &value);
	return 0;
}

SEC("lsm/inode_init_security")
__failure __msg("expected a hook output argument loaded from ctx")
int BPF_PROG(reject_other_ctx_arg, struct inode *inode, struct inode *dir,
	     const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
{
	struct bpf_dynptr value;

	if (!xattrs)
		return 0;

	/* Trusted, and from ctx, but not the output argument. */
	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_inode_init_xattr(xattrs, (int *)xattrs, xattr_zone, &value);
	return 0;
}

SEC("lsm/inode_init_security")
__failure __msg("Possibly NULL pointer passed to trusted")
int BPF_PROG(reject_null_count, struct inode *inode, struct inode *dir,
	     const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
{
	struct bpf_dynptr value;

	if (!xattrs)
		return 0;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_inode_init_xattr(xattrs, NULL, xattr_zone, &value);
	return 0;
}

SEC("lsm/inode_init_security")
__failure __msg("dereference of modified rdonly_trusted_mem ptr")
int BPF_PROG(reject_shifted_count, struct inode *inode, struct inode *dir,
	     const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
{
	struct bpf_dynptr value;

	if (!xattrs)
		return 0;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_inode_init_xattr(xattrs, xattr_count + 1, xattr_zone, &value);
	return 0;
}

/*
 * Storing into the context and reading the slot back would mint a pointer of
 * the hook's type with a value of the program's choosing. The context is
 * read-only, so the store is what gets rejected here.
 */
SEC("lsm/inode_init_security")
__failure __msg("invalid bpf_context access")
int reject_ctx_forged_count(unsigned long long *ctx)
{
	volatile unsigned long long *slot = ctx;
	struct bpf_dynptr value;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	slot[4] = 0;
	bpf_inode_init_xattr((struct xattr *)(long)slot[3],
			     (int *)(long)slot[4], xattr_zone, &value);
	return 0;
}

static __noinline int claim_via_subprog(struct xattr *xattrs, int *xattr_count,
					struct bpf_dynptr *value)
{
	return bpf_inode_init_xattr(xattrs, xattr_count, xattr_zone, value);
}

SEC("lsm/inode_init_security")
__success
int BPF_PROG(allow_count_via_subprog, struct inode *inode, struct inode *dir,
	     const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
{
	struct bpf_dynptr value;

	if (!xattrs)
		return 0;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	claim_via_subprog(xattrs, xattr_count, &value);
	return 0;
}

SEC("lsm/inode_init_security")
__failure __msg("access beyond struct xattr at off 24")
int BPF_PROG(reject_shifted_xattrs, struct inode *inode, struct inode *dir,
	     const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
{
	struct bpf_dynptr value;

	if (!xattrs)
		return 0;

	/* Would claim a slot past the end of the array the framework owns. */
	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_inode_init_xattr(xattrs + 1, xattr_count, xattr_zone, &value);
	return 0;
}

/*
 * The hook runs inside the transaction creating the inode, with a journal
 * handle held and the parent's i_rwsem down, so it takes no sleepable
 * programs.
 */
SEC("lsm.s/inode_init_security")
__failure __msg("bpf_lsm_inode_init_security is not sleepable")
int BPF_PROG(reject_sleepable, struct inode *inode, struct inode *dir,
	     const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
{
	return 0;
}

/*
 * A cgroup-scoped program on the hook is handed the same context, but its
 * return value follows the cgroup convention rather than the LSM one, so it is
 * kept away from a kfunc that mutates the array the framework owns.
 */
SEC("lsm_cgroup/inode_init_security")
__failure __msg("calling kernel function bpf_inode_init_xattr is not allowed")
int BPF_PROG(reject_lsm_cgroup, struct inode *inode, struct inode *dir,
	     const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
{
	struct bpf_dynptr value;

	if (!xattrs)
		return 0;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_inode_init_xattr(xattrs, xattr_count, xattr_zone, &value);
	return 0;
}

SEC("lsm/inode_setxattr")
__failure __msg("calling kernel function bpf_inode_init_xattr is not allowed")
int BPF_PROG(reject_wrong_hook, struct mnt_idmap *idmap, struct dentry *dentry,
	     const char *name, const void *value, size_t size, int flags)
{
	struct bpf_dynptr val;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &val);
	bpf_inode_init_xattr(NULL, &scratch_count, xattr_zone, &val);
	return 0;
}
