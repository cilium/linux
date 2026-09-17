// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_kfuncs.h"

char _license[] SEC("license") = "GPL";

#define LABEL_MAX	32
#define MAY_READ	0x4

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
__u32 monitored_pid;
__u32 instantiated;
__u32 denied;

/* Load the label as the dentry is attached. It is not positive yet, so the
 * read goes by the inode the hook hands out.
 */
SEC("lsm.s/d_instantiate")
int BPF_PROG(load_label, struct dentry *dentry, struct inode *inode)
{
	struct bpf_dynptr value;
	struct label *l;
	int len;

	if (bpf_get_current_pid_tgid() >> 32 != monitored_pid)
		return 0;
	l = bpf_inode_storage_get(&labels, inode, 0,
				  BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!l)
		return 0;
	bpf_dynptr_from_mem(l->v, sizeof(l->v), 0, &value);
	len = bpf_get_inode_xattr(inode, dentry, xattr_label, &value);
	l->deny = len == sizeof("deny") &&
		  !bpf_strncmp(l->v, sizeof("deny"), "deny");
	instantiated++;
	return 0;
}

/* Enforce from the cached label in a hook that cannot read the xattr. */
SEC("lsm/inode_permission")
int BPF_PROG(enforce, struct inode *inode, int mask)
{
	struct label *l;

	if (bpf_get_current_pid_tgid() >> 32 != monitored_pid)
		return 0;
	if (!(mask & MAY_READ))
		return 0;
	l = bpf_inode_storage_get(&labels, inode, 0, 0);
	if (!l || !l->deny)
		return 0;
	denied++;
	return -EPERM;
}
