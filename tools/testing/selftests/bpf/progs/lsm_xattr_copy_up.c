// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_kfuncs.h"

char _license[] SEC("license") = "GPL";

const char xattr_label[] = "security.bpf.label";
const char xattr_sealed[] = "security.bpf.sealed";
const char xattr_origin[] = "security.bpf.origin";
char origin_value[] = "upper";
__u32 monitored_pid;
__u32 seen;
__u32 discarded;
__u32 aborted;
__u32 stamped;
__s32 stamp_err;

/* Steer what overlayfs copies up: the label stays behind on the lower
 * layer, a sealed file is not copied up at all, and anything else is not
 * the policy's business and copied.
 */
SEC("lsm/inode_copy_up_xattr")
int BPF_PROG(steer, struct dentry *src, const char *name)
{
	char buf[32];

	if (bpf_get_current_pid_tgid() >> 32 != monitored_pid)
		return 0;
	if (bpf_probe_read_kernel_str(buf, sizeof(buf), name) < 0)
		return 0;
	seen++;
	if (!bpf_strncmp(buf, sizeof(xattr_label), xattr_label)) {
		discarded++;
		return -ECANCELED;
	}
	if (!bpf_strncmp(buf, sizeof(xattr_sealed), xattr_sealed)) {
		aborted++;
		return -EPERM;
	}
	return 0;
}

/* Stamp every inode the test creates. A file made through the overlay is a
 * new upper inode and carries this; so is the inode overlayfs makes for a
 * copy up, so both hooks run on that one operation.
 */
SEC("lsm/inode_init_security")
int BPF_PROG(stamp, struct inode *inode, struct inode *dir,
	     const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
{
	struct bpf_dynptr value;

	if (bpf_get_current_pid_tgid() >> 32 != monitored_pid)
		return 0;
	if (!xattrs)
		return 0;
	bpf_dynptr_from_mem(origin_value, sizeof(origin_value), 0, &value);
	stamp_err = bpf_init_inode_xattr(xattrs, xattr_count, xattr_origin,
					 &value);
	if (!stamp_err)
		stamped++;
	return 0;
}
