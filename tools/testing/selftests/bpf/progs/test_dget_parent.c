// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include "bpf_kfuncs.h"

char _license[] SEC("license") = "GPL";

__u32 monitored_pid;
int parent_xattr_len;
char parent_xattr[32];

/* Read the label of the directory a new file is created in. */
SEC("lsm.s/inode_create")
int BPF_PROG(test_inode_create, struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry, umode_t mode)
{
	struct bpf_dynptr value_ptr;
	struct dentry *parent;

	if ((bpf_get_current_pid_tgid() >> 32) != monitored_pid)
		return 0;

	bpf_dynptr_from_mem(parent_xattr, sizeof(parent_xattr), 0, &value_ptr);
	parent = bpf_dget_parent(dentry);
	parent_xattr_len = bpf_get_dentry_xattr(parent, "security.bpf.dir", &value_ptr);
	bpf_dput(parent);
	return 0;
}
