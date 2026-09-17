// SPDX-License-Identifier: GPL-2.0
/* The task side of the zone policy.
 *
 * Two ways around W^X never reach the mapping hooks: a tracer and a write
 * through /proc/PID/mem copy attacker data into a private page of an
 * executable mapping with FOLL_FORCE, and a script is opened and run by its
 * interpreter. So attaching is refused from the default zone, and from no
 * zone to a trusted task; a writable open of /proc/PID/mem is refused in
 * the default zone by the identity of its file operations; and exec, as
 * well as the check an interpreter makes with AT_EXECVE_CHECK before running
 * a script, is held to the same provenance as a mapping: the file must carry
 * the trusted zone label itself.
 *
 * A program on inode_init_security stamps every new inode with the zone of
 * the task creating it, atomically with the inode's own creation. What a
 * default-zone task writes thus carries "default" from its first instant and
 * can never be run there. No administrator has to label files afterwards.
 */
#include "lsm_zone.h"

char _license[] SEC("license") = "GPL";

/* The file operations of /proc/PID/mem: its identity, without a path. */
extern const void proc_mem_operations __ksym;

__u32 monitored_pid;

/* What labelling at creation did. */
__u32 nr_stamped;
__s32 stamp_err = 1;
/* What enforcement did. */
__u32 mem_denied;
__u32 ptrace_denied;
__u32 exec_denied;
__u32 allowed;

static __always_inline bool monitored(void)
{
	return (bpf_get_current_pid_tgid() >> 32) == monitored_pid;
}

/*
 * Stamp a new inode with the zone of the task creating it, in the same
 * transaction as the inode itself. Nothing is stamped for a task outside the
 * policy, and nothing on a filesystem that takes no xattrs at creation.
 */
SEC("lsm/inode_init_security")
int BPF_PROG(stamp_zone, struct inode *inode, struct inode *dir,
	     const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
{
	struct bpf_dynptr value;
	struct scratch *s;
	int len;

	if (!monitored() || !xattrs)
		return 0;
	s = scratch();
	if (!s)
		return 0;
	len = current_zone_label(s);
	if (len <= 0 || len > ZONE_MAX)
		return 0;

	bpf_dynptr_from_mem(s->zone, len, 0, &value);
	stamp_err = bpf_init_inode_xattr(xattrs, xattr_count, xattr_zone, &value);
	if (!stamp_err)
		nr_stamped++;
	return 0;
}

/* Writing through /proc/PID/mem forces a copy of a private page past its
 * protection, and to one's own mem file no ptrace check applies: refuse the
 * writable open in the default zone, by the identity of the file operations.
 */
SEC("lsm.s/file_open")
int BPF_PROG(guard_mem_open, struct file *file)
{
	unsigned long fop = 0;
	struct scratch *s;

	if (!monitored() || !(file->f_mode & FMODE_WRITE))
		return 0;
	s = scratch();
	if (current_zone(s) != ZONE_DEFAULT)
		return 0;
	bpf_probe_read_kernel(&fop, sizeof(fop), &file->f_op);
	if (fop == (unsigned long)&proc_mem_operations) {
		mem_denied++;
		return -EPERM;
	}
	return 0;
}

/* A tracer writes into private mappings past every protection, as does
 * process_vm_writev(): no attaching from the default zone at all, and none
 * from outside the policy to a task in the trusted zone.
 */
SEC("lsm/ptrace_access_check")
int BPF_PROG(guard_ptrace, struct task_struct *child, unsigned int mode)
{
	struct scratch *s;
	int zone;

	if (!monitored() || !(mode & PTRACE_MODE_ATTACH))
		return 0;
	s = scratch();
	zone = current_zone(s);
	if (zone == ZONE_TRUSTED)
		return 0;
	if (zone == ZONE_NONE && task_zone(s, child) != ZONE_TRUSTED)
		return 0;
	ptrace_denied++;
	return -EPERM;
}

/* Exec, and the check an interpreter makes with AT_EXECVE_CHECK before it
 * runs a script, follow the file's zone like a mapping would: the label is
 * read off the file itself, and one that cannot be read fails closed.
 */
SEC("lsm.s/bprm_creds_for_exec")
int BPF_PROG(guard_exec, struct linux_binprm *bprm)
{
	struct scratch *s;
	int len;

	if (!monitored())
		return 0;
	s = scratch();
	if (current_zone(s) != ZONE_DEFAULT)
		return 0;
	if (!s)
		return -EPERM;
	len = file_zone_label(s, bprm->file);
	if (is_trusted(s->file, len)) {
		allowed++;
		return 0;
	}
	exec_denied++;
	return -EPERM;
}
