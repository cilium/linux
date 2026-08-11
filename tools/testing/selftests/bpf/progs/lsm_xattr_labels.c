// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2026 Isovalent */

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_kfuncs.h"
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

#define LABEL_MAX	32

/*
 * A small MAC policy in the shape of a real one: every object gets a zone it
 * belongs to, inherited from its parent directory at creation time and
 * falling back to a per-mount default, plus a provenance label that must not
 * survive an overlayfs copy-up. On filesystems that cannot store xattrs the
 * zone is kept in inode local storage and served virtually.
 */
struct label {
	char	v[LABEL_MAX];
	__u32	len;
};

struct {
	__uint(type, BPF_MAP_TYPE_SB_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct label);
} sb_default_zone SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_INODE_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct label);
} inode_zone SEC(".maps");

__u32 monitored_pid;
__u32 monitored_exec_pid;

/* Full names, as used by the xattr kfuncs and the copy-up hook. */
const char xattr_zone[]    = "security.bpf.zone";
const char xattr_origin[]  = "security.bpf.origin";
const char xattr_state[]   = "security.bpf.state";
const char xattr_selinux[] = "security.selinux";

/* Suffixes, as seen by the get/set label hooks. */
static const char suffix_state[] = "bpf.state";

/*
 * bpf_dynptr_from_mem() only accepts a map value, which for these is the
 * program's own .bss and .data, so the scratch buffers cannot live on the
 * stack and origin_value cannot be const.
 */
char origin_value[] = "created";
char zone_scratch[LABEL_MAX];
char get_scratch[LABEL_MAX];
char inst_scratch[LABEL_MAX];
char name_scratch[LABEL_MAX];

/* Observations the test asserts on. */
__u32 init_labels_set;
__u32 init_selinux_err;
__u32 add_selinux_err;
__u32 copy_up_dropped;
__u32 copy_up_kept;
__u32 set_label_len;
__u32 get_label_served;
__u32 list_labels_served;
__u32 instantiated;
char  exec_zone[LABEL_MAX];
__u32 exec_zone_len;
__s32 exec_zone_err;

static __always_inline bool monitored(void)
{
	return (bpf_get_current_pid_tgid() >> 32) == monitored_pid;
}

static __always_inline bool name_eq(const char *name, const char *want, int len)
{
	if (len > LABEL_MAX)
		return false;
	if (bpf_probe_read_kernel_str(name_scratch, LABEL_MAX, name) < 0)
		return false;
	return !bpf_strncmp(name_scratch, len, want);
}

/*
 * Label an inode from within the transaction creating it. Exercises
 * bpf_inode_init_xattr() with two labels on one inode, reading the parent
 * directory's label through bpf_get_inode_xattr(), and the per-mount default
 * held in super_block local storage.
 */
SEC("lsm.s/inode_init_label")
int BPF_PROG(init_label, struct inode *inode, struct inode *dir,
	     struct qstr *qstr)
{
	struct bpf_dynptr value;
	struct label *def;
	int ret, len = 0;

	if (!monitored())
		return 0;

	__builtin_memset(zone_scratch, 0, LABEL_MAX);

	if (dir) {
		bpf_dynptr_from_mem(zone_scratch, LABEL_MAX, 0, &value);
		ret = bpf_get_inode_xattr(dir, xattr_zone, &value);
		if (ret > 0 && ret <= LABEL_MAX)
			len = ret;
	}
	if (!len) {
		def = bpf_sb_storage_get(&sb_default_zone, inode->i_sb, 0, 0);
		if (def && def->len > 0 && def->len <= LABEL_MAX) {
			len = def->len;
			__builtin_memcpy(zone_scratch, def->v, LABEL_MAX);
		}
	}
	if (len <= 0 || len > LABEL_MAX)
		return 0;

	bpf_dynptr_from_mem(zone_scratch, len, 0, &value);
	if (bpf_inode_init_xattr(xattr_zone, &value))
		return 0;
	init_labels_set++;

	/* A second label on the same inode, to prove the slots are not a single. */
	bpf_dynptr_from_mem(origin_value, sizeof(origin_value) - 1, 0, &value);
	if (!bpf_inode_init_xattr(xattr_origin, &value))
		init_labels_set++;

	/* Namespaces other than security.bpf. must stay refused. */
	if (bpf_inode_init_xattr(xattr_selinux, &value))
		init_selinux_err++;

	/* Mirror the zone into inode storage so the get/list hooks can serve it. */
	def = bpf_inode_storage_get(&inode_zone, inode, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (def) {
		__builtin_memcpy(def->v, zone_scratch, LABEL_MAX);
		def->len = len;
	}
	return 0;
}

/*
 * Resolve the on-disk label once, when the dentry is instantiated, and cache it
 * in inode local storage, which is what SELinux does from
 * selinux_d_instantiate(). Needs the hook to be sleepable, and needs the
 * (dentry, inode) pair: the dentry is not attached to the inode yet, so
 * d_inode() is NULL here and the inode has no alias to find either.
 */
SEC("lsm.s/d_instantiate")
int BPF_PROG(instantiate, struct dentry *dentry, struct inode *inode)
{
	struct bpf_dynptr value;
	struct label *st;
	int ret;

	if (!monitored())
		return 0;

	__builtin_memset(inst_scratch, 0, LABEL_MAX);
	bpf_dynptr_from_mem(inst_scratch, LABEL_MAX, 0, &value);
	ret = bpf_get_dentry_inode_xattr(dentry, inode, xattr_zone, &value);
	if (ret <= 0 || ret > LABEL_MAX)
		return 0;

	st = bpf_inode_storage_get(&inode_zone, inode, 0,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!st)
		return 0;
	__builtin_memcpy(st->v, inst_scratch, LABEL_MAX);
	st->len = ret;
	instantiated++;
	return 0;
}

/*
 * Serve a label that is not stored on disk. On a filesystem without xattr
 * support this is the only way a label can be read back at all.
 */
SEC("lsm.s/inode_get_label")
int BPF_PROG(get_label, struct inode *inode, const char *name)
{
	struct bpf_dynptr value;
	struct label *st;
	__u32 len;

	if (!monitored())
		return 0;
	if (!name_eq(name, suffix_state, sizeof(suffix_state)))
		return 0;

	st = bpf_inode_storage_get(&inode_zone, inode, 0, 0);
	if (!st)
		return 0;

	len = st->len;
	if (len == 0 || len > LABEL_MAX)
		return 0;
	__builtin_memcpy(get_scratch, st->v, LABEL_MAX);

	bpf_dynptr_from_mem(get_scratch, len, 0, &value);
	if (!bpf_set_label_value(&value))
		get_label_served++;
	return 0;
}

/*
 * Take a label for an inode on a filesystem that has nowhere to put it. The
 * VFS only reaches this after __vfs_setxattr_noperm() finds no xattr handler.
 */
SEC("lsm.s/inode_set_label")
int BPF_PROG(set_label, struct inode *inode, const char *name,
	     const void *value, __u64 size, int flags)
{
	struct label *st;
	__u32 len = size;

	if (!monitored())
		return 0;
	if (!name_eq(name, suffix_state, sizeof(suffix_state)))
		return 0;
	if (len == 0 || len > LABEL_MAX)
		return -EINVAL;

	st = bpf_inode_storage_get(&inode_zone, inode, 0,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!st)
		return -ENOMEM;
	if (bpf_probe_read_kernel(st->v, len, value))
		return -EFAULT;
	st->len = len;

	if (!bpf_claim_label())
		set_label_len = len;
	return 0;
}

/*
 * Advertise the virtual label so that listxattr() reports it even though the
 * filesystem stores nothing for it.
 */
SEC("lsm.s/inode_list_labels")
int BPF_PROG(list_labels, struct inode *inode)
{
	if (!monitored())
		return 0;
	if (!bpf_inode_storage_get(&inode_zone, inode, 0, 0))
		return 0;

	if (!bpf_add_label_name(xattr_state))
		list_labels_served++;

	/* Advertising somebody else's namespace must stay refused. */
	if (bpf_add_label_name(xattr_selinux))
		add_selinux_err++;
	return 0;
}

/*
 * Keep provenance from being inherited by an overlayfs copy-up, while letting
 * the zone through. Returning 0 leaves the default of -EOPNOTSUPP, i.e. copy.
 */
SEC("lsm.s/inode_copy_up_xattr")
int BPF_PROG(copy_up_xattr, struct dentry *src, const char *name)
{
	if (!monitored())
		return 0;

	if (name_eq(name, xattr_origin, sizeof(xattr_origin))) {
		copy_up_dropped++;
		return -ECANCELED;
	}
	if (name_eq(name, xattr_zone, sizeof(xattr_zone)))
		copy_up_kept++;
	return 0;
}

/*
 * Read the label of a binary the calling task has no read access to. This only
 * works because security.bpf.* reads are no longer gated on the subject's
 * permission to the object.
 */
SEC("lsm.s/bprm_check_security")
int BPF_PROG(check_exec, struct linux_binprm *bprm)
{
	struct bpf_dynptr value;
	int ret;

	if ((bpf_get_current_pid_tgid() >> 32) != monitored_exec_pid)
		return 0;

	bpf_dynptr_from_mem(exec_zone, sizeof(exec_zone), 0, &value);
	ret = bpf_get_file_xattr(bprm->file, xattr_zone, &value);
	if (ret > 0)
		exec_zone_len = ret;
	else
		exec_zone_err = ret;
	return 0;
}
