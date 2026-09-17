// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_kfuncs.h"

char _license[] SEC("license") = "GPL";

const char xattr_zone[] = "security.bpf.zone";
static const char label_locked[] = "locked";
char name_buf[32];
char label_buf[16];
__u32 monitored_pid;
__u32 claimed;
__u32 denied;

static __always_inline bool own_name(const char *name)
{
	if (bpf_get_current_pid_tgid() >> 32 != monitored_pid)
		return false;
	if (bpf_probe_read_kernel_str(name_buf, sizeof(name_buf), name) < 0)
		return false;
	return !bpf_strncmp(name_buf, sizeof(xattr_zone), xattr_zone);
}

/* Claim the label for the capability check: whether it may be written is
 * decided below, not by CAP_SYS_ADMIN. Every other security. name keeps
 * needing it.
 */
SEC("lsm/inode_xattr_skipcap")
int BPF_PROG(claim_zone, const char *name)
{
	if (!own_name(name))
		return 0;
	claimed++;
	return 1;
}

/* A file labelled "locked" keeps its label, whoever asks. */
static __always_inline int gate_write(struct dentry *dentry, const char *name)
{
	struct bpf_dynptr value;
	int len;

	if (!own_name(name))
		return 0;
	bpf_dynptr_from_mem(label_buf, sizeof(label_buf), 0, &value);
	len = bpf_get_dentry_xattr(dentry, xattr_zone, &value);
	if (len != sizeof(label_locked) ||
	    bpf_strncmp(label_buf, sizeof(label_locked), label_locked))
		return 0;
	denied++;
	return -EPERM;
}

SEC("lsm.s/inode_setxattr")
int BPF_PROG(gate_setxattr, struct mnt_idmap *idmap, struct dentry *dentry,
	     const char *name, const void *value, __u64 size, int flags)
{
	return gate_write(dentry, name);
}

SEC("lsm.s/inode_removexattr")
int BPF_PROG(gate_removexattr, struct mnt_idmap *idmap, struct dentry *dentry,
	     const char *name)
{
	return gate_write(dentry, name);
}
