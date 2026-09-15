// SPDX-License-Identifier: GPL-2.0
/*
 * BPF LSM policy that prevents CVE-2024-3094-style code smuggling by keying the
 * decision on a tamper-evident provenance label rather than a path.
 *
 * A path is not an identity: the same inode is reachable under many names via
 * hard links, symlinks, bind mounts and per-namespace mount trees, and a name
 * can be repointed at other content. So the policy here reads a security xattr,
 * "security.bpf.prov", from the file being mapped. The security.* namespace can
 * only be written with privilege, so an unprivileged attacker cannot forge the
 * label on a library they smuggle in, and the decision is independent of the
 * name the file is presented under.
 *
 * The label is best written atomically at inode creation by a BPF LSM program
 * on inode_init_security (bpf_inode_init_xattr()), so there is never a window in
 * which the file exists unlabeled.
 *
 * Enforced at the sleepable lsm.s/mmap_file hook: security_mmap_file() runs from
 * vm_mmap_pgoff() before mmap_lock is taken, so bpf_get_file_xattr() (sleepable)
 * is legal here, and a non-zero return denies the mapping. The default is
 * fail-closed: code with no trusted provenance is refused an executable mapping.
 */
#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_kfuncs.h"

char _license[] SEC("license") = "GPL";

#ifndef PROT_EXEC
#define PROT_EXEC 0x4
#endif

#define PROV_XATTR "security.bpf.prov"

/* The provenance value this daemon accepts. A production policy would compare
 * against a per-workload allowlist, or verify a signature carried in the label.
 */
static const char trusted_value[] = "trusted";

__u32 monitored_pid;
char value[64];

__u32 allow_hits;
__u32 deny_hits;

SEC("lsm.s/mmap_file")
int BPF_PROG(xz_mmap_guard, struct file *file, unsigned long reqprot,
	     unsigned long prot, unsigned long flags)
{
	struct bpf_dynptr value_ptr;
	__u32 pid;
	int ret;

	/* Scope: only file-backed, executable mappings by the protected task. */
	if (!file)
		return 0;
	if (!(prot & PROT_EXEC))
		return 0;
	pid = bpf_get_current_pid_tgid() >> 32;
	if (!monitored_pid || pid != monitored_pid)
		return 0;

	bpf_dynptr_from_mem(value, sizeof(value), 0, &value_ptr);
	ret = bpf_get_file_xattr(file, PROV_XATTR, &value_ptr);
	if (ret == sizeof(trusted_value) &&
	    bpf_strncmp(value, sizeof(trusted_value), trusted_value) == 0) {
		allow_hits++;
		return 0;
	}

	/* No trusted provenance label -> refuse to map this code executable. */
	deny_hits++;
	return -EPERM;
}
