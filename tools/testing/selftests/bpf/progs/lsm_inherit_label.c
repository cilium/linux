// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_kfuncs.h"

char _license[] SEC("license") = "GPL";

#define LABEL_MAX	32

/* The parent's label, carried from the path hook to inode_init_security. */
struct pending {
	char	v[LABEL_MAX];
	__u32	len;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct pending);
} pending SEC(".maps");

const char xattr_label[] = "security.bpf.label";
const char xattr_stamp[] = "security.bpf.stamp";
char stamp_value[] = "1";
__u32 monitored_pid;
__u32 remembered;
__u32 inherited;
__s32 init_err;

/* Read the parent's label off its dentry, reachable through the trusted
 * path, before the inode exists.
 */
static int remember(const struct path *dir)
{
	struct bpf_dynptr value;
	struct pending *p;
	int len;

	if (bpf_get_current_pid_tgid() >> 32 != monitored_pid)
		return 0;
	p = bpf_task_storage_get(&pending, bpf_get_current_task_btf(), 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!p)
		return 0;
	bpf_dynptr_from_mem(p->v, sizeof(p->v), 0, &value);
	len = bpf_get_dentry_xattr(dir->dentry, xattr_label, &value);
	p->len = len > 0 ? len : 0;
	if (p->len)
		remembered++;
	return 0;
}

/* The parent is locked here, so the write takes the locked variant. */
SEC("lsm.s/path_mkdir")
int BPF_PROG(remember_mkdir, const struct path *dir, struct dentry *dentry,
	     umode_t mode)
{
	struct bpf_dynptr stamp;

	if (bpf_get_current_pid_tgid() >> 32 == monitored_pid) {
		bpf_dynptr_from_mem(stamp_value, sizeof(stamp_value), 0, &stamp);
		bpf_set_dentry_xattr(dir->dentry, xattr_stamp, &stamp, 0);
	}
	return remember(dir);
}

SEC("lsm.s/path_mknod")
int BPF_PROG(remember_mknod, const struct path *dir, struct dentry *dentry,
	     umode_t mode, unsigned int dev)
{
	return remember(dir);
}

SEC("lsm/inode_init_security")
int BPF_PROG(inherit, struct inode *inode, struct inode *dir,
	     const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
{
	struct bpf_dynptr value;
	struct pending *p;
	__u32 len;

	if (bpf_get_current_pid_tgid() >> 32 != monitored_pid)
		return 0;
	p = bpf_task_storage_get(&pending, bpf_get_current_task_btf(), 0, 0);
	if (!p)
		return 0;
	len = p->len;
	p->len = 0;
	if (!len || len > LABEL_MAX || !xattrs)
		return 0;
	bpf_dynptr_from_mem(p->v, len, 0, &value);
	init_err = bpf_init_inode_xattr(xattrs, xattr_count, xattr_label, &value);
	if (!init_err)
		inherited++;
	return 0;
}
