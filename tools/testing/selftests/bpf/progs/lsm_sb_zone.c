// SPDX-License-Identifier: GPL-2.0
/* Labelling a mount, and enforcing on it from the objects it holds.
 *
 * A superblock is not an inode, so it cannot carry an xattr of its own --
 * but it has one inode that stands for the whole mount, the one behind its
 * root dentry, and that inode takes a label like any other. Reaching it is
 * the whole trick: inode->i_sb->s_root->d_inode, the chain the VFS itself
 * spells out in is_root_inode().
 *
 * Two labels live there, for the two things a policy means by "this mount":
 *
 *   security.bpf.zone   on the root inode, a property of the filesystem
 *                       image, written by whoever built it and persistent.
 *   inode storage       on the same inode, a property of this mount,
 *                       written by the mounter at sb_set_mnt_opts and gone
 *                       when the superblock is.
 *
 * They are not interchangeable. A policy that trusts an untrusted image's
 * own xattr has been told its zone by the thing it is judging; the mount
 * label is the one the mounter chose.
 */
#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_kfuncs.h"

char _license[] SEC("license") = "GPL";

#define ZONE_MAX	32

const char xattr_zone[] = "security.bpf.zone";

/* The mount's label, keyed by the inode that stands for the mount. */
struct {
	__uint(type, BPF_MAP_TYPE_INODE_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u32);
} mount_zone SEC(".maps");

__u32 monitored_pid;
__u32 mount_label;		/* what the runner asks us to stamp */
int mounts_labelled;
int open_ret = -999;		/* the mount label seen at file_open */
int image_ret = -999;		/* the image label read off the same inode */
char image_zone[ZONE_MAX];

static __always_inline bool monitored(void)
{
	return (bpf_get_current_pid_tgid() >> 32) == monitored_pid;
}

/* The inode that stands for the mount, or NULL before the tree is grown. */
static __always_inline struct inode *sb_root_inode(struct inode *inode)
{
	struct dentry *root;

	/* s_root is read once and that read is what gets checked: reading
	 * the field again after the check hands back a fresh nullable
	 * pointer, which the verifier refuses to walk.
	 */
	root = inode->i_sb->s_root;
	if (!root)
		return NULL;
	return root->d_inode;
}

/* sb_set_mnt_opts runs once per mount, after vfs_get_tree() has grown the
 * tree, so the root dentry is there. This is the mounter's context.
 */
SEC("lsm.s/sb_set_mnt_opts")
int BPF_PROG(label_at_mount, struct super_block *sb, void *mnt_opts,
	     unsigned long kern_flags, unsigned long *set_kern_flags)
{
	struct dentry *s_root;
	struct inode *root;
	__u32 *zone;

	if (!monitored() || !mount_label)
		return 0;
	s_root = sb->s_root;
	if (!s_root)
		return 0;
	root = s_root->d_inode;
	if (!root)
		return 0;

	zone = bpf_inode_storage_get(&mount_zone, root, NULL,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!zone)
		return 0;
	*zone = mount_label;
	mounts_labelled++;
	return 0;
}

/* Any file on that mount can be traced back to it, so a hook that sees only
 * the file can still act on the mount's label -- and on the image's, which
 * lives on the very same inode as an xattr.
 */
SEC("lsm.s/file_open")
int BPF_PROG(check_at_open, struct file *file)
{
	struct bpf_dynptr value;
	struct inode *root;
	__u32 *zone;

	if (!monitored())
		return 0;
	root = sb_root_inode(file->f_inode);
	if (!root)
		return 0;

	/* Only the mount the runner labelled; this hook sees every open. */
	zone = bpf_inode_storage_get(&mount_zone, root, NULL, 0);
	if (!zone)
		return 0;
	open_ret = *zone;

	bpf_dynptr_from_mem(image_zone, sizeof(image_zone), 0, &value);
	image_ret = bpf_get_inode_xattr(root, NULL, xattr_zone, &value);
	return 0;
}
