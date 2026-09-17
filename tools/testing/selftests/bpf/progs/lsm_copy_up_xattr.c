// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

const char xattr_label[] = "security.bpf.label";
const char xattr_sealed[] = "security.bpf.sealed";
__u32 monitored_pid;
__u32 seen;
__u32 discarded;
__u32 aborted;

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
