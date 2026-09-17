// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_kfuncs.h"
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

const char xattr_label[] = "security.bpf.label";
char value_buf[8] = "l";

/* A struct path handed to a hook pins its dentry, so the dentry is trusted. */
SEC("lsm.s/path_mkdir")
__success
int BPF_PROG(allow_path_dentry_read, const struct path *dir,
	     struct dentry *dentry, umode_t mode)
{
	struct bpf_dynptr value;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_get_dentry_xattr(dir->dentry, xattr_label, &value);
	return 0;
}

SEC("lsm.s/path_mknod")
__success
int BPF_PROG(allow_path_dentry_write, const struct path *dir,
	     struct dentry *dentry, umode_t mode, unsigned int dev)
{
	struct bpf_dynptr value;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_set_dentry_xattr(dir->dentry, xattr_label, &value, 0);
	return 0;
}

/* rename sees its parents locked and its dentries not: no writer fits. */
SEC("lsm.s/path_rename")
__failure __msg("calling kernel function bpf_set_dentry_xattr is not allowed")
int BPF_PROG(reject_mixed_write, const struct path *old_dir,
	     struct dentry *old_dentry, const struct path *new_dir,
	     struct dentry *new_dentry, unsigned int flags)
{
	struct bpf_dynptr value;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_set_dentry_xattr(old_dentry, xattr_label, &value, 0);
	return 0;
}

/* So do unlink and rmdir: the parent is locked, the victim is not yet. */
SEC("lsm.s/path_unlink")
__failure __msg("calling kernel function bpf_set_dentry_xattr is not allowed")
int BPF_PROG(reject_unlink_write, const struct path *dir,
	     struct dentry *dentry)
{
	struct bpf_dynptr value;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_set_dentry_xattr(dentry, xattr_label, &value, 0);
	return 0;
}

SEC("lsm.s/path_rmdir")
__failure __msg("calling kernel function bpf_remove_dentry_xattr is not allowed")
int BPF_PROG(reject_rmdir_remove, const struct path *dir,
	     struct dentry *dentry)
{
	bpf_remove_dentry_xattr(dentry, xattr_label);
	return 0;
}

/* Walking up from a dentry is not covered: d_parent stays untrusted. */
SEC("lsm.s/path_mkdir")
__failure __msg("must be referenced or trusted")
int BPF_PROG(reject_dentry_parent, const struct path *dir,
	     struct dentry *dentry, umode_t mode)
{
	struct bpf_dynptr value;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_get_dentry_xattr(dentry->d_parent, xattr_label, &value);
	return 0;
}

/* Nor is the path embedded in a file: that is what bpf_get_file_xattr() is for. */
SEC("lsm.s/file_open")
__failure __msg("must be referenced or trusted")
int BPF_PROG(reject_file_path_dentry, struct file *file)
{
	struct bpf_dynptr value;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_get_dentry_xattr(file->f_path.dentry, xattr_label, &value);
	return 0;
}
