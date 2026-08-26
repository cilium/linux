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

SEC("lsm.s/inode_init_security")
__failure __msg("cannot write into rdonly_trusted_mem")
int BPF_PROG(reject_count_write, struct inode *inode, struct inode *dir,
	     const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
{
	*xattr_count = 0;
	return 0;
}

SEC("lsm.s/inode_init_security")
__success
int BPF_PROG(allow_count_read, struct inode *inode, struct inode *dir,
	     const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
{
	scratch_count = *xattr_count;
	return 0;
}

SEC("lsm.s/inode_init_security")
__failure __msg("expected a hook output argument loaded from ctx")
int BPF_PROG(reject_forged_count, struct inode *inode, struct inode *dir,
	     const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
{
	struct bpf_dynptr value;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_inode_init_xattr(xattrs, &scratch_count, xattr_zone, &value);
	return 0;
}

SEC("lsm.s/inode_init_security")
__failure __msg("expected a hook output argument loaded from ctx")
int BPF_PROG(reject_stack_count, struct inode *inode, struct inode *dir,
	     const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
{
	struct bpf_dynptr value;
	int local = 0;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_inode_init_xattr(xattrs, &local, xattr_zone, &value);
	return 0;
}

SEC("lsm.s/inode_setxattr")
__failure __msg("calling kernel function bpf_inode_init_xattr is not allowed")
int BPF_PROG(reject_wrong_hook, struct mnt_idmap *idmap, struct dentry *dentry,
	     const char *name, const void *value, size_t size, int flags)
{
	struct bpf_dynptr val;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &val);
	bpf_inode_init_xattr(NULL, &scratch_count, xattr_zone, &val);
	return 0;
}
