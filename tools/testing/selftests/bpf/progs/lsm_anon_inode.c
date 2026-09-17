// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

#define NAME_MAX_LEN	32

static const char name_uffd[] = "[userfaultfd]";
static const char name_memfd[] = "[memfd]";

char seen_name[NAME_MAX_LEN];
__u32 monitored_pid;
__u32 refuse_uffd;
__u32 uffd_seen;
__u32 uffd_refused;
__u32 memfd_seen;
__u32 other_seen;
__u32 inherited;

/* An anonymous inode is born here, named after its class and carrying no
 * xattrs at all: there is no array to claim a slot in, and the hook cannot
 * sleep, so neither writing nor reading a label is possible. What a policy
 * has is the name and the creating task, which is enough to refuse the
 * thing outright, the way SELinux gates the anon_inode class.
 */
SEC("lsm/inode_init_security_anon")
int BPF_PROG(guard_anon, struct inode *inode, const struct qstr *name,
	     const struct inode *context_inode)
{
	if (bpf_get_current_pid_tgid() >> 32 != monitored_pid)
		return 0;
	if (bpf_probe_read_kernel_str(seen_name, sizeof(seen_name),
				      name->name) < 0)
		return 0;
	/* A userfaultfd made by fork() inherits the parent's inode. */
	if (context_inode)
		inherited++;
	if (!bpf_strncmp(seen_name, sizeof(name_uffd), name_uffd)) {
		uffd_seen++;
		if (refuse_uffd) {
			uffd_refused++;
			return -EPERM;
		}
		return 0;
	}
	if (!bpf_strncmp(seen_name, sizeof(name_memfd), name_memfd)) {
		memfd_seen++;
		return 0;
	}
	other_seen++;
	return 0;
}
