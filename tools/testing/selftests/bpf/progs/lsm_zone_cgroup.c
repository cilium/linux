// SPDX-License-Identifier: GPL-2.0
/* The cgroup side of the zone policy.
 *
 * A cgroup only ever comes into existence through a mkdir(2) in cgroupfs, so a
 * manager creating one for a container, whether directly or by way of a
 * transient unit, ends up in kernfs_init_security. The root of the managed
 * tree carries a security.bpf.zone label, and the hook pushes it onto every
 * cgroup created below before the node is linked in: a container's cgroups
 * are labelled from their first instant, and a mkdir in a delegated subtree
 * cannot produce an unlabelled one.
 *
 * The label is the policy's own control plane, so only the trusted zone may
 * write or remove it: the default zone cannot promote itself, and a task in
 * no zone cannot either. Migration is gated directly on task_cgroup_attach,
 * which sees both the task and its destination cgroup: nothing enters the
 * trusted zone from outside it, by cgroup.procs write or by clone3 alike,
 * and an enforced task cannot escape into an unlabelled cgroup to shed
 * enforcement. What the label protects is held the same way: a trusted
 * cgroup's control files cannot be opened for writing from outside, and a
 * mkdir below a trusted cgroup is refused. The tree is brought up before the
 * policy attaches, the root labelled "default" and a first pod "trusted",
 * and from then on trust is only minted from inside.
 */
#include "lsm_zone.h"

char _license[] SEC("license") = "GPL";

#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC	0x63677270
#endif

__u32 monitored_pid;

/* What labelling at creation did, of cgroups, their files, and inodes. */
__u32 nr_labelled;
__u32 nr_labelled_files;
__s32 label_err = 1;
__u32 nr_stamped;
__s32 stamp_err = 1;
/* What enforcement did. */
__u32 grow_denied;
__u32 enter_denied;
__u32 relabel_denied;
__u32 write_denied;

static __always_inline bool monitored(void)
{
	return (bpf_get_current_pid_tgid() >> 32) == monitored_pid;
}

/*
 * Push the zone of the cgroup a new node is created under onto the node
 * itself, the cgroup directory and its control files alike, so that a hook
 * holding an open control file can tell which zone its cgroup is in. A new
 * cgroup in the trusted zone may only be created from inside it.
 */
SEC("lsm.s/kernfs_init_security")
int BPF_PROG(inherit_zone, struct kernfs_node *kn_dir, struct kernfs_node *kn)
{
	struct bpf_dynptr value;
	struct scratch *s;
	int len;

	if (!monitored())
		return 0;
	s = scratch();
	if (!s)
		return -ENOMEM;	/* rather no node than an unlabelled one */

	bpf_dynptr_from_mem(s->file, sizeof(s->file), 0, &value);
	len = bpf_get_kernfs_xattr(kn_dir, xattr_zone, &value);
	if (len <= 0 || len > ZONE_MAX)
		return 0;
	if ((kn->flags & KERNFS_DIR) && is_trusted(s->file, len) &&
	    current_zone(s) != ZONE_TRUSTED) {
		grow_denied++;
		return -EPERM;
	}

	bpf_dynptr_from_mem(s->file, len, 0, &value);
	label_err = bpf_set_kernfs_xattr(kn, xattr_zone, &value);
	if (label_err)
		return 0;
	if (kn->flags & KERNFS_DIR)
		nr_labelled++;
	else
		nr_labelled_files++;
	return 0;
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

/* From any zone but the trusted one, refuse to open a trusted cgroup's control
 * file for writing: the file inherited its cgroup's zone at creation, so its
 * own label says which zone that is, without a path. A control file whose
 * label cannot be read is refused as well.
 */
SEC("lsm.s/file_open")
int BPF_PROG(guard_control_open, struct file *file)
{
	struct scratch *s;
	int len;

	if (!monitored() || !(file->f_mode & FMODE_WRITE))
		return 0;
	if (file->f_inode->i_sb->s_magic != CGROUP2_SUPER_MAGIC)
		return 0;
	s = scratch();
	if (current_zone(s) == ZONE_TRUSTED)
		return 0;
	if (!s)
		return -EPERM;
	len = file_zone_label(s, file);
	if (is_trusted(s->file, len)) {
		write_denied++;
		return -EPERM;
	}
	return 0;
}

/* Migration is gated where it happens, with the task and its destination
 * cgroup both in hand: this covers a cgroup.procs/threads write and a
 * clone3(CLONE_INTO_CGROUP) alike, whichever way a task changes cgroup. The
 * trusted zone is the control plane and may place a task anywhere; otherwise
 * nothing enters the trusted zone from outside it, and an enforced task may
 * not drop into an unlabelled cgroup to shed enforcement.
 */
SEC("lsm/task_cgroup_attach")
int BPF_PROG(guard_migrate, struct task_struct *task, struct cgroup *dst_cgrp)
{
	struct bpf_dynptr value;
	struct scratch *s;
	int mover, dst, len;

	if (!monitored())
		return 0;
	s = scratch();

	/* The decision is the mover's to make: for a cgroup.procs write that is
	 * the writer, for clone3(CLONE_INTO_CGROUP) the forking parent. The
	 * moved task is not a reliable source zone, since a clone child already
	 * carries the destination cgroup by the time this hook runs.
	 */
	mover = current_zone(s);
	if (mover == ZONE_TRUSTED)
		return 0;		/* the control plane may place anything */
	if (!s)
		return -EPERM;		/* cannot read the destination: fail closed */

	if (task_zone(s, task) == ZONE_TRUSTED) {
		enter_denied++;		/* only the trusted zone moves trusted tasks */
		return -EPERM;
	}
	bpf_dynptr_from_mem(s->zone, sizeof(s->zone), 0, &value);
	len = bpf_cgroup_read_xattr(dst_cgrp, xattr_zone, &value);
	dst = zone_of_label(s, len);
	if (dst == ZONE_TRUSTED) {
		enter_denied++;		/* no entry into the trusted zone */
		return -EPERM;
	}
	if (mover == ZONE_DEFAULT && dst == ZONE_NONE) {
		enter_denied++;		/* no escape out of enforcement */
		return -EPERM;
	}
	return 0;
}

/* Only the trusted zone writes or removes the label, on a file or a cgroup
 * alike. A name that cannot be read is refused rather than let through.
 */
static __always_inline int guard_relabel(const char *name)
{
	struct scratch *s;

	if (!monitored())
		return 0;
	s = scratch();
	if (!s)
		return -EPERM;
	if (bpf_probe_read_kernel_str(s->name, sizeof(s->name), name) < 0)
		return -EPERM;
	if (bpf_strncmp(s->name, sizeof(xattr_zone), xattr_zone))
		return 0;
	if (current_zone(s) == ZONE_TRUSTED)
		return 0;
	relabel_denied++;
	return -EPERM;
}

SEC("lsm/inode_setxattr")
int BPF_PROG(guard_setxattr, struct mnt_idmap *idmap, struct dentry *dentry,
	     const char *name, const void *value, __u64 size, int flags)
{
	return guard_relabel(name);
}

SEC("lsm/inode_removexattr")
int BPF_PROG(guard_removexattr, struct mnt_idmap *idmap,
	     struct dentry *dentry, const char *name)
{
	return guard_relabel(name);
}

/* Claim the label for the capability check: writing or removing it is
 * decided by the zone above, not by CAP_SYS_ADMIN. Every other security.
 * name keeps that requirement.
 */
SEC("lsm/inode_xattr_skipcap")
int BPF_PROG(skipcap_label, const char *name)
{
	struct scratch *s;

	if (!monitored())
		return 0;
	s = scratch();
	if (!s)
		return 0;
	if (bpf_probe_read_kernel_str(s->name, sizeof(s->name), name) < 0)
		return 0;
	return !bpf_strncmp(s->name, sizeof(xattr_zone), xattr_zone);
}
