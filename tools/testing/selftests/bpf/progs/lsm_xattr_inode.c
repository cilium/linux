// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_kfuncs.h"

char _license[] SEC("license") = "GPL";

#define LABEL_MAX	32
#define MAY_READ	0x4

/* What the hooks read while the runner exercises them. */
enum {
	OP_NONE,
	OP_READ,
	OP_MISSING,
	OP_SHORT,
	OP_PARENT,
	OP_RENAME,
	OP_ENFORCE,
};

struct label {
	char	v[LABEL_MAX];
	bool	deny;
};

struct {
	__uint(type, BPF_MAP_TYPE_INODE_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct label);
} labels SEC(".maps");

const char xattr_label[] = "security.bpf.label";
const char xattr_missing[] = "security.bpf.missing";
static const char label_deny[] = "deny";

__u32 monitored_pid;
__u32 op;
__s32 read_ret;
__s32 mkdir_ret;
__s32 create_ret;
__s32 rename_ret;
__u32 instantiated;
__u32 denied;
char read_value[32];
char parent_value[32];

/* The dentry is not attached to the inode yet, so the read goes by the
 * inode with the dentry the hook hands out.
 */
SEC("lsm.s/d_instantiate")
int BPF_PROG(on_instantiate, struct dentry *dentry, struct inode *inode)
{
	struct bpf_dynptr value;
	struct label *l;
	int len;

	if (bpf_get_current_pid_tgid() >> 32 != monitored_pid)
		return 0;

	switch (op) {
	case OP_READ:
		bpf_dynptr_from_mem(read_value, sizeof(read_value), 0, &value);
		read_ret = bpf_get_inode_xattr(inode, dentry, xattr_label,
					       &value);
		break;
	case OP_MISSING:
		bpf_dynptr_from_mem(read_value, sizeof(read_value), 0, &value);
		read_ret = bpf_get_inode_xattr(inode, dentry, xattr_missing,
					       &value);
		break;
	case OP_SHORT:
		bpf_dynptr_from_mem(read_value, 1, 0, &value);
		read_ret = bpf_get_inode_xattr(inode, dentry, xattr_label,
					       &value);
		break;
	case OP_ENFORCE:
		l = bpf_inode_storage_get(&labels, inode, 0,
					  BPF_LOCAL_STORAGE_GET_F_CREATE);
		if (!l)
			return 0;
		bpf_dynptr_from_mem(l->v, sizeof(l->v), 0, &value);
		len = bpf_get_inode_xattr(inode, dentry, xattr_label, &value);
		l->deny = len == sizeof(label_deny) &&
			  !bpf_strncmp(l->v, sizeof(label_deny), label_deny);
		instantiated++;
		break;
	}
	return 0;
}

/* The parent of a create is an inode with no dentry to go with it: an alias
 * of it is looked up instead.
 */
SEC("lsm.s/inode_mkdir")
int BPF_PROG(on_mkdir, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct bpf_dynptr value;

	if (bpf_get_current_pid_tgid() >> 32 != monitored_pid || op != OP_PARENT)
		return 0;
	bpf_dynptr_from_mem(parent_value, sizeof(parent_value), 0, &value);
	mkdir_ret = bpf_get_inode_xattr(dir, NULL, xattr_label, &value);
	return 0;
}

SEC("lsm.s/inode_create")
int BPF_PROG(on_create, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct bpf_dynptr value;

	if (bpf_get_current_pid_tgid() >> 32 != monitored_pid || op != OP_PARENT)
		return 0;
	bpf_dynptr_from_mem(parent_value, sizeof(parent_value), 0, &value);
	create_ret = bpf_get_inode_xattr(dir, NULL, xattr_label, &value);
	return 0;
}

/* A dentry that belongs to another inode is refused rather than read. */
SEC("lsm.s/inode_rename")
int BPF_PROG(on_rename, struct inode *old_dir, struct dentry *old_dentry,
	     struct inode *new_dir, struct dentry *new_dentry)
{
	struct bpf_dynptr value;

	if (bpf_get_current_pid_tgid() >> 32 != monitored_pid || op != OP_RENAME)
		return 0;
	bpf_dynptr_from_mem(read_value, sizeof(read_value), 0, &value);
	rename_ret = bpf_get_inode_xattr(old_dir, old_dentry, xattr_label,
					 &value);
	return 0;
}

/* Enforce from the cached label in a hook that cannot read the xattr. */
SEC("lsm/inode_permission")
int BPF_PROG(enforce, struct inode *inode, int mask)
{
	struct label *l;

	if (bpf_get_current_pid_tgid() >> 32 != monitored_pid || op != OP_ENFORCE)
		return 0;
	if (!(mask & MAY_READ))
		return 0;
	l = bpf_inode_storage_get(&labels, inode, 0, 0);
	if (!l || !l->deny)
		return 0;
	denied++;
	return -EPERM;
}
