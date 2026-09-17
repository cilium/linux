// SPDX-License-Identifier: GPL-2.0
/* W^X and code provenance on files, scoped by the zone of the cgroup a task
 * runs in. In the "trusted" zone nothing is enforced. In any other zone the
 * task is held to W^X, no mapping both writable and executable and no memory
 * made executable after it was writable, and to code provenance: a file is
 * mapped executable, or made executable later, only if it carries the trusted
 * zone label itself.
 *
 * A program on inode_init_security stamps every new inode with the zone of
 * the task creating it, atomically with the inode's own creation. What a
 * default-zone task writes thus carries "default" from its first instant and
 * can never be mapped executable there, while what the trusted zone installs
 * carries "trusted" and can. No administrator has to label files afterwards.
 *
 * The label is the policy's own control plane, so only the trusted zone may
 * write or remove it: the default zone cannot promote its code, and a task in
 * no zone cannot either. What the label protects is held the same way. A
 * trusted file cannot be opened for writing or truncated from outside, nor
 * received as a writable descriptor, so the code the default zone may run
 * cannot be changed by it. What the trusted zone opens for writing, or writes
 * to through a descriptor it holds, is labelled trusted on the spot with
 * bpf_set_file_xattr(), so it becomes code the default zone may run and can
 * no longer open for writing.
 *
 * A file's zone is read by the sleepable hooks and cached in inode local
 * storage, keyed by the inode, because file_mprotect runs under mmap_lock and
 * cannot read the xattr itself. It reaches the backing file with
 * bpf_get_vma_file() and enforces the cached verdict, failing closed when
 * there is none.
 */
#include "lsm_zone.h"

char _license[] SEC("license") = "GPL";

__u32 monitored_pid;

struct verdict {
	__u8 trusted;
};

struct {
	__uint(type, BPF_MAP_TYPE_INODE_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct verdict);
} file_zone SEC(".maps");

/* What stamping at creation did. */
__u32 nr_stamped;
__s32 stamp_err = 1;
/* What enforcement did. */
__u32 wx_denied;
__u32 code_denied;
__u32 relabel_denied;
__u32 write_denied;
__u32 recv_denied;
__u32 nr_claimed;
__u32 allowed;

static __always_inline bool monitored(void)
{
	return (bpf_get_current_pid_tgid() >> 32) == monitored_pid;
}

/* Stamp a new inode with the zone of the task creating it, in the same
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

/* Sleepable only: read the file's zone and cache the verdict on the inode. */
static __always_inline struct verdict *measure(struct scratch *s,
					       struct file *file)
{
	struct verdict *v;
	int ret;

	if (!s)
		return NULL;
	v = bpf_inode_storage_get(&file_zone, file->f_inode, 0,
				  BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!v)
		return NULL;

	ret = file_zone_label(s, file);
	v->trusted = is_trusted(s->file, ret);
	return v;
}

/* What the trusted zone writes becomes trusted code: label a regular file
 * and refresh the cached verdict, once.
 */
static __always_inline void claim(struct scratch *s, struct file *file)
{
	struct bpf_dynptr value;
	struct verdict *v;

	if (!s || (file->f_inode->i_mode & S_IFMT) != S_IFREG)
		return;
	v = bpf_inode_storage_get(&file_zone, file->f_inode, 0,
				  BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (v && v->trusted)
		return;
	__builtin_memcpy(s->file, label_trusted, sizeof(label_trusted));
	bpf_dynptr_from_mem(s->file, sizeof(label_trusted), 0, &value);
	if (bpf_set_file_xattr(file, xattr_zone, &value, 0))
		return;
	if (v)
		v->trusted = 1;
	nr_claimed++;
}

/* A descriptor the trusted zone writes through is claimed too, whichever
 * zone opened it.
 */
SEC("lsm.s/file_permission")
int BPF_PROG(claim_on_write, struct file *file, int mask)
{
	struct scratch *s;

	if (!monitored() || !(mask & MAY_WRITE))
		return 0;
	s = scratch();
	if (current_zone(s) == ZONE_TRUSTED)
		claim(s, file);
	return 0;
}

/* Measure what the default zone opens, and from any zone but the trusted one
 * refuse to open a trusted file for writing: code the default zone may run.
 * Nothing can be told about a file that could not be measured, so that is
 * refused as well. What the trusted zone opens for writing, it claims.
 */
SEC("lsm.s/file_open")
int BPF_PROG(guard_open, struct file *file)
{
	struct scratch *s;
	struct verdict *v;
	int zone;

	if (!monitored())
		return 0;
	s = scratch();
	zone = current_zone(s);
	if (zone == ZONE_TRUSTED) {
		if (file->f_mode & FMODE_WRITE)
			claim(s, file);
		return 0;
	}
	if (zone == ZONE_NONE && !(file->f_mode & FMODE_WRITE))
		return 0;
	v = measure(s, file);
	if ((file->f_mode & FMODE_WRITE) && (!v || v->trusted)) {
		write_denied++;
		return -EPERM;
	}
	return 0;
}

/* Truncation needs no writable descriptor, so cover it too. */
SEC("lsm.s/inode_setattr")
int BPF_PROG(guard_setattr, struct mnt_idmap *idmap, struct dentry *dentry,
	     struct iattr *attr)
{
	struct bpf_dynptr value;
	struct scratch *s;
	int ret;

	if (!monitored() || !(attr->ia_valid & ATTR_SIZE))
		return 0;
	s = scratch();
	if (current_zone(s) == ZONE_TRUSTED)
		return 0;
	if (!s)
		return -EPERM;
	bpf_dynptr_from_mem(s->file, sizeof(s->file), 0, &value);
	ret = bpf_get_dentry_xattr(dentry, xattr_zone, &value);
	if (is_trusted(s->file, ret)) {
		write_denied++;
		return -EPERM;
	}
	return 0;
}

SEC("lsm.s/mmap_file")
int BPF_PROG(guard_mmap, struct file *file, unsigned long reqprot,
	     unsigned long prot, unsigned long flags)
{
	struct scratch *s;
	struct verdict *v;

	if (!monitored())
		return 0;
	s = scratch();
	if (current_zone(s) != ZONE_DEFAULT)
		return 0;
	if ((prot & PROT_WRITE) && (prot & PROT_EXEC)) {
		wx_denied++;
		return -EPERM;
	}
	/* Anonymous memory mapped executable holds zero pages only. It cannot
	 * be written without giving up PROT_EXEC, and cannot get it back below.
	 */
	if (!file)
		return 0;

	/* Every file-backed mapping is measured, so that a later mprotect on
	 * it finds a verdict whichever cgroup opened the file.
	 */
	v = measure(s, file);
	if (!(prot & PROT_EXEC))
		return 0;
	if (v && v->trusted) {
		allowed++;
		return 0;
	}
	code_denied++;
	return -EPERM;
}

/* Non-sleepable, runs under mmap_lock: enforce what the sleepable hooks cached. */
SEC("lsm/file_mprotect")
int BPF_PROG(guard_mprotect, struct vm_area_struct *vma, unsigned long reqprot,
	     unsigned long prot)
{
	struct scratch *s;
	struct verdict *v;
	struct file *file;
	int ret = -EPERM;

	if (!monitored())
		return 0;
	s = scratch();
	if (current_zone(s) != ZONE_DEFAULT)
		return 0;
	if ((prot & PROT_WRITE) && (prot & PROT_EXEC)) {
		wx_denied++;
		return -EPERM;
	}
	if (!(prot & PROT_EXEC) || (vma->vm_flags & VM_EXEC))
		return 0;

	/* Memory becoming executable. Anonymous memory and a private file
	 * mapping written through have both been writable, so W^X refuses
	 * them; a clean file mapping follows the file's cached zone.
	 */
	file = bpf_get_vma_file(vma);
	if (!file || vma->anon_vma) {
		if (file)
			bpf_put_file(file);
		wx_denied++;
		return -EPERM;
	}
	v = bpf_inode_storage_get(&file_zone, file->f_inode, 0, 0);
	if (v && v->trusted) {
		allowed++;
		ret = 0;
	} else {
		code_denied++;
	}
	bpf_put_file(file);
	return ret;
}

/* A writable descriptor to a trusted file, or to an unmeasurable one, must
 * not enter the default zone by SCM_RIGHTS: it would let code the default
 * zone may run be rewritten from within it, past the file_open write gate.
 */
SEC("lsm.s/file_receive")
int BPF_PROG(guard_receive, struct file *file)
{
	struct scratch *s;
	struct verdict *v;

	if (!monitored())
		return 0;
	s = scratch();
	if (current_zone(s) != ZONE_DEFAULT)
		return 0;
	if (!(file->f_mode & FMODE_WRITE))
		return 0;
	v = measure(s, file);
	if (!v || v->trusted) {
		recv_denied++;
		return -EPERM;
	}
	return 0;
}

/* Keep a cached verdict consistent when the file is relabeled after it was
 * measured. Reading the xattr with __vfs_getxattr does not take i_rwsem, so
 * it is safe here even though inode_post_setxattr holds it.
 */
SEC("lsm.s/inode_post_setxattr")
int BPF_PROG(refresh_on_setxattr, struct dentry *dentry, const char *name,
	     const void *val, __u64 size, int flags)
{
	struct bpf_dynptr value;
	struct scratch *s;
	struct verdict *v;
	int ret;

	if (!monitored())
		return 0;
	v = bpf_inode_storage_get(&file_zone, dentry->d_inode, 0, 0);
	if (!v)
		return 0;
	s = scratch();
	if (!s) {
		v->trusted = 0;	/* cannot re-read the label: drop the trust */
		return 0;
	}

	bpf_dynptr_from_mem(s->file, sizeof(s->file), 0, &value);
	ret = bpf_get_dentry_xattr(dentry, xattr_zone, &value);
	v->trusted = is_trusted(s->file, ret);
	return 0;
}

/* Only the trusted zone writes or removes the label. A name that cannot be
 * read is refused rather than let through.
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
