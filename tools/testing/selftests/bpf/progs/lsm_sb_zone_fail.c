// SPDX-License-Identifier: GPL-2.0
/* What the chain to a mount's inode does not give you.
 *
 * i_sb is trusted because an inode pins its superblock; s_root is only
 * trusted-or-null because a superblock has no root before its tree is grown
 * or after it is shut down. Neither makes anything further along the chain
 * trusted by itself.
 */
#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_kfuncs.h"
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

#define ZONE_MAX	32

const char xattr_zone[] = "security.bpf.zone";
char probe[ZONE_MAX];

struct {
	__uint(type, BPF_MAP_TYPE_INODE_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u32);
} mount_zone SEC(".maps");

/* A superblock has no root before its tree is grown and none after it is
 * shut down, so s_root comes back nullable and has to be checked before it
 * is walked.
 */
SEC("lsm.s/file_open")
__failure __msg("invalid mem access 'trusted_ptr_or_null_'")
int BPF_PROG(unchecked_s_root, struct file *file)
{
	struct bpf_dynptr value;
	struct inode *root = file->f_inode->i_sb->s_root->d_inode;

	bpf_dynptr_from_mem(probe, sizeof(probe), 0, &value);
	bpf_get_inode_xattr(root, NULL, xattr_zone, &value);
	return 0;
}

/* The root inode reached through the chain is trusted, but an inode found
 * any other way is not: s_dentry_lru is not part of the blessed path.
 */
SEC("lsm.s/file_open")
__failure __msg("must be referenced or trusted")
int BPF_PROG(unblessed_field, struct file *file)
{
	struct bpf_dynptr value;
	struct super_block *sb = file->f_inode->i_sb;

	bpf_dynptr_from_mem(probe, sizeof(probe), 0, &value);
	bpf_get_inode_xattr(sb->s_bdev_file->f_inode, NULL, xattr_zone, &value);
	return 0;
}
