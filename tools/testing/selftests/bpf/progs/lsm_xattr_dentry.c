// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_kfuncs.h"

char _license[] SEC("license") = "GPL";

/* vmlinux.h carries no uapi xattr flags. */
#define XATTR_CREATE	0x1
#define XATTR_REPLACE	0x2

/* What the hook does when the runner's trigger name is read. */
enum {
	OP_NONE,
	OP_SET,
	OP_GET,
	OP_REMOVE,
	OP_SET_CREATE,
	OP_SET_REPLACE,
	OP_SET_EMPTY,
	OP_GET_MISSING,
	OP_GET_SHORT,
	OP_SET_USER,
	OP_FOREIGN,
	OP_NEGATIVE,
	OP_NO_XATTR_FS,
	OP_LOCKED_SET,
	OP_LOCKED_REMOVE,
};

const char xattr_trigger[] = "security.bpf.trigger";
const char xattr_data[] = "security.bpf.data";
const char xattr_missing[] = "security.bpf.missing";
const char xattr_user[] = "user.data";
const char xattr_selinux[] = "security.selinux";
char value_hello[] = "hello";

__u32 monitored_pid;
__u32 op;
__s32 get_ret;
__s32 set_ret;
__s32 remove_ret;
char read_value[32];
static char name_buf[32];

/* Keyed by the name being read, so only the runner's trigger reaches the
 * policy and the assertions' own reads pass through.
 */
static __always_inline bool triggered(const char *name)
{
	if (bpf_probe_read_kernel_str(name_buf, sizeof(name_buf), name) < 0)
		return false;
	return !bpf_strncmp(name_buf, sizeof(xattr_trigger), xattr_trigger);
}

SEC("lsm.s/inode_getxattr")
int BPF_PROG(on_getxattr, struct dentry *dentry, const char *name)
{
	struct bpf_dynptr value;

	if (bpf_get_current_pid_tgid() >> 32 != monitored_pid)
		return 0;
	if (!triggered(name))
		return 0;

	switch (op) {
	case OP_SET:
		bpf_dynptr_from_mem(value_hello, sizeof(value_hello), 0, &value);
		set_ret = bpf_set_dentry_xattr(dentry, xattr_data, &value, 0);
		break;
	case OP_GET:
		bpf_dynptr_from_mem(read_value, sizeof(read_value), 0, &value);
		get_ret = bpf_get_dentry_xattr(dentry, xattr_data, &value);
		break;
	case OP_REMOVE:
		remove_ret = bpf_remove_dentry_xattr(dentry, xattr_data);
		break;
	case OP_SET_CREATE:
		bpf_dynptr_from_mem(value_hello, sizeof(value_hello), 0, &value);
		set_ret = bpf_set_dentry_xattr(dentry, xattr_data, &value,
					       XATTR_CREATE);
		break;
	case OP_SET_REPLACE:
		bpf_dynptr_from_mem(value_hello, sizeof(value_hello), 0, &value);
		set_ret = bpf_set_dentry_xattr(dentry, xattr_data, &value,
					       XATTR_REPLACE);
		break;
	case OP_SET_EMPTY:
		bpf_dynptr_from_mem(value_hello, 0, 0, &value);
		set_ret = bpf_set_dentry_xattr(dentry, xattr_data, &value, 0);
		break;
	case OP_GET_MISSING:
		bpf_dynptr_from_mem(read_value, sizeof(read_value), 0, &value);
		get_ret = bpf_get_dentry_xattr(dentry, xattr_missing, &value);
		break;
	case OP_GET_SHORT:
		bpf_dynptr_from_mem(read_value, 1, 0, &value);
		get_ret = bpf_get_dentry_xattr(dentry, xattr_data, &value);
		break;
	case OP_SET_USER:
		bpf_dynptr_from_mem(value_hello, sizeof(value_hello), 0, &value);
		set_ret = bpf_set_dentry_xattr(dentry, xattr_user, &value, 0);
		break;
	case OP_FOREIGN:
		bpf_dynptr_from_mem(read_value, sizeof(read_value), 0, &value);
		get_ret = bpf_get_dentry_xattr(dentry, xattr_selinux, &value);
		set_ret = bpf_set_dentry_xattr(dentry, xattr_selinux, &value, 0);
		break;
	case OP_NO_XATTR_FS:
		bpf_dynptr_from_mem(read_value, sizeof(read_value), 0, &value);
		get_ret = bpf_get_dentry_xattr(dentry, xattr_data, &value);
		bpf_dynptr_from_mem(value_hello, sizeof(value_hello), 0, &value);
		set_ret = bpf_set_dentry_xattr(dentry, xattr_data, &value, 0);
		break;
	}
	return 0;
}

/* The dentry a create hands out has no inode yet: the dentry kfuncs refuse
 * it rather than working on nothing.
 */
SEC("lsm.s/inode_create")
int BPF_PROG(on_create, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct bpf_dynptr value;

	if (bpf_get_current_pid_tgid() >> 32 != monitored_pid ||
	    op != OP_NEGATIVE)
		return 0;
	bpf_dynptr_from_mem(read_value, sizeof(read_value), 0, &value);
	get_ret = bpf_get_dentry_xattr(dentry, xattr_data, &value);
	set_ret = bpf_set_dentry_xattr(dentry, xattr_data, &value, 0);
	remove_ret = bpf_remove_dentry_xattr(dentry, xattr_data);
	return 0;
}

/* This hook is called with i_rwsem held, so the writers are fixed up to
 * their locked variants and do not take the lock again.
 */
SEC("lsm.s/inode_setxattr")
int BPF_PROG(on_setxattr, struct mnt_idmap *idmap, struct dentry *dentry,
	     const char *name, const void *value, size_t size, int flags)
{
	struct bpf_dynptr v;

	if (bpf_get_current_pid_tgid() >> 32 != monitored_pid)
		return 0;
	if (!triggered(name))
		return 0;

	switch (op) {
	case OP_LOCKED_SET:
		bpf_dynptr_from_mem(value_hello, sizeof(value_hello), 0, &v);
		set_ret = bpf_set_dentry_xattr(dentry, xattr_data, &v, 0);
		break;
	case OP_LOCKED_REMOVE:
		remove_ret = bpf_remove_dentry_xattr(dentry, xattr_data);
		break;
	}
	return 0;
}
