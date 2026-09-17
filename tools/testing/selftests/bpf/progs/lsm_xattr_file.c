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
#define MAY_WRITE	0x2

/* What the hooks do to the file the runner points them at. */
enum {
	OP_NONE,
	OP_SET,
	OP_REMOVE,
	OP_GET,
	OP_SET_CREATE,
	OP_SET_REPLACE,
	OP_SET_EMPTY,
	OP_GET_MISSING,
	OP_GET_SHORT,
	OP_SET_USER,
	OP_FOREIGN,
	OP_NO_XATTR_FS,
	OP_CLAIM,
	OP_RECEIVE,
};

const char xattr_data[] = "security.bpf.data";
const char xattr_claim[] = "security.bpf.claim";
const char xattr_missing[] = "security.bpf.missing";
const char xattr_user[] = "user.data";
const char xattr_selinux[] = "security.selinux";
static const char label_sealed[] = "sealed";
char value_hello[] = "hello";
char value_one[] = "1";

__u32 monitored_pid;
__u64 target_ino;
__u32 op;
__s32 get_ret;
__s32 set_ret;
__s32 remove_ret;
__s32 recv_len;
__u32 claims;
__u32 recv_seen;
__u32 recv_denied;
char read_value[32];

/* One file at a time is under test, named by its inode number. */
static __always_inline bool target(struct file *file)
{
	if (bpf_get_current_pid_tgid() >> 32 != monitored_pid)
		return false;
	return file->f_inode->i_ino == target_ino;
}

SEC("lsm.s/file_open")
int BPF_PROG(on_open, struct file *file)
{
	struct bpf_dynptr value;

	if (!target(file))
		return 0;

	switch (op) {
	case OP_SET:
		bpf_dynptr_from_mem(value_hello, sizeof(value_hello), 0, &value);
		set_ret = bpf_set_file_xattr(file, xattr_data, &value, 0);
		break;
	case OP_REMOVE:
		remove_ret = bpf_remove_file_xattr(file, xattr_data);
		break;
	case OP_GET:
		bpf_dynptr_from_mem(read_value, sizeof(read_value), 0, &value);
		get_ret = bpf_get_file_xattr(file, xattr_data, &value);
		break;
	case OP_SET_CREATE:
		bpf_dynptr_from_mem(value_hello, sizeof(value_hello), 0, &value);
		set_ret = bpf_set_file_xattr(file, xattr_data, &value,
					     XATTR_CREATE);
		break;
	case OP_SET_REPLACE:
		bpf_dynptr_from_mem(value_hello, sizeof(value_hello), 0, &value);
		set_ret = bpf_set_file_xattr(file, xattr_data, &value,
					     XATTR_REPLACE);
		break;
	case OP_SET_EMPTY:
		bpf_dynptr_from_mem(value_hello, 0, 0, &value);
		set_ret = bpf_set_file_xattr(file, xattr_data, &value, 0);
		break;
	case OP_GET_MISSING:
		bpf_dynptr_from_mem(read_value, sizeof(read_value), 0, &value);
		get_ret = bpf_get_file_xattr(file, xattr_missing, &value);
		break;
	case OP_GET_SHORT:
		bpf_dynptr_from_mem(read_value, 1, 0, &value);
		get_ret = bpf_get_file_xattr(file, xattr_data, &value);
		break;
	case OP_SET_USER:
		bpf_dynptr_from_mem(value_hello, sizeof(value_hello), 0, &value);
		set_ret = bpf_set_file_xattr(file, xattr_user, &value, 0);
		break;
	case OP_FOREIGN:
		bpf_dynptr_from_mem(read_value, sizeof(read_value), 0, &value);
		get_ret = bpf_get_file_xattr(file, xattr_selinux, &value);
		set_ret = bpf_set_file_xattr(file, xattr_selinux, &value, 0);
		break;
	case OP_NO_XATTR_FS:
		bpf_dynptr_from_mem(read_value, sizeof(read_value), 0, &value);
		get_ret = bpf_get_file_xattr(file, xattr_data, &value);
		bpf_dynptr_from_mem(value_hello, sizeof(value_hello), 0, &value);
		set_ret = bpf_set_file_xattr(file, xattr_data, &value, 0);
		break;
	}
	return 0;
}

/* A descriptor written through is claimed, whoever opened it. The hook runs
 * before the filesystem takes i_rwsem, so the writer takes it itself.
 */
SEC("lsm.s/file_permission")
int BPF_PROG(on_permission, struct file *file, int mask)
{
	struct bpf_dynptr value;

	if (op != OP_CLAIM || !target(file))
		return 0;
	if (!(mask & MAY_WRITE))
		return 0;
	bpf_dynptr_from_mem(value_one, sizeof(value_one), 0, &value);
	set_ret = bpf_set_file_xattr(file, xattr_claim, &value, 0);
	claims++;
	return 0;
}

/* The label of a descriptor passed over SCM_RIGHTS, read in the receiver. */
SEC("lsm.s/file_receive")
int BPF_PROG(on_receive, struct file *file)
{
	struct bpf_dynptr value;
	int len;

	if (bpf_get_current_pid_tgid() >> 32 != monitored_pid || op != OP_RECEIVE)
		return 0;
	bpf_dynptr_from_mem(read_value, sizeof(read_value), 0, &value);
	len = bpf_get_file_xattr(file, xattr_data, &value);
	recv_len = len;
	if (len == sizeof(label_sealed) &&
	    !bpf_strncmp(read_value, sizeof(label_sealed), label_sealed)) {
		recv_denied++;
		return -EPERM;
	}
	recv_seen++;
	return 0;
}
