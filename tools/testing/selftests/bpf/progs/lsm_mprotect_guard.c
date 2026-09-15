// SPDX-License-Identifier: GPL-2.0
/*
 * Measure at open, enforce at mprotect.
 *
 * The mmap_file policy covers a library mapped executable directly. It does not
 * cover "map read-only, then mprotect(PROT_EXEC)" or anonymous RWX. That path
 * is file_mprotect, which runs under mmap_lock and so cannot sleep, so it cannot
 * read the I/O-bound provenance xattr itself.
 *
 * Split it: the sleepable file_open hook reads security.bpf.prov and caches a
 * verdict in inode local storage, keyed by the inode. The non-sleepable
 * file_mprotect hook reaches the backing file with bpf_get_vma_file() and reads
 * the cached verdict, refusing an executable transition on code without trusted
 * provenance. Keying on the inode rather than the address range makes the
 * lookup race-free: at enforce time we consult the verdict for the file that is
 * actually mapped.
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
static const char trusted_value[] = "trusted";

struct verdict {
	__u8 measured;
	__u8 trusted;
};

struct {
	__uint(type, BPF_MAP_TYPE_INODE_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct verdict);
} prov_cache SEC(".maps");

extern struct file *bpf_get_vma_file(struct vm_area_struct *vma) __ksym;

__u32 monitored_pid;
char value[64];
__u32 measure_hits;
__u32 allow_hits;
__u32 deny_hits;
__u32 refresh_hits;

/* Sleepable: read the provenance xattr and cache the verdict on the inode. */
SEC("lsm.s/file_open")
int BPF_PROG(measure_at_open, struct file *file)
{
	struct bpf_dynptr value_ptr;
	struct verdict *v;
	__u32 pid;
	int ret;

	pid = bpf_get_current_pid_tgid() >> 32;
	if (!monitored_pid || pid != monitored_pid)
		return 0;

	v = bpf_inode_storage_get(&prov_cache, file->f_inode, 0,
				  BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!v)
		return 0;

	bpf_dynptr_from_mem(value, sizeof(value), 0, &value_ptr);
	ret = bpf_get_file_xattr(file, PROV_XATTR, &value_ptr);
	v->trusted = ret == sizeof(trusted_value) &&
		     bpf_strncmp(value, sizeof(trusted_value), trusted_value) == 0;
	v->measured = 1;
	measure_hits++;
	return 0;
}

/* Non-sleepable, runs under mmap_lock: enforce the cached verdict. */
SEC("lsm/file_mprotect")
int BPF_PROG(enforce_at_mprotect, struct vm_area_struct *vma,
	     unsigned long reqprot, unsigned long prot)
{
	struct verdict *v;
	struct file *file;
	__u32 pid;
	int ret = 0;

	if (!(prot & PROT_EXEC))
		return 0;
	pid = bpf_get_current_pid_tgid() >> 32;
	if (!monitored_pid || pid != monitored_pid)
		return 0;

	file = bpf_get_vma_file(vma);
	if (!file)
		return 0;		/* anonymous mapping: out of scope here */

	v = bpf_inode_storage_get(&prov_cache, file->f_inode, 0, 0);
	if (v && v->measured && !v->trusted) {
		deny_hits++;
		ret = -EPERM;
	} else {
		allow_hits++;
	}
	bpf_put_file(file);
	return ret;
}

/* Keep the cached verdict consistent when a file is relabeled after it was
 * measured, closing the measure-time-of-use race for the xattr. Reading the
 * xattr with __vfs_getxattr does not take i_rwsem, so it is safe here even
 * though inode_post_setxattr holds it.
 */
SEC("lsm.s/inode_post_setxattr")
int BPF_PROG(refresh_on_setxattr, struct dentry *dentry, const char *name,
	     const void *val, __u64 size, int flags)
{
	struct bpf_dynptr value_ptr;
	struct verdict *v;
	__u32 pid;
	int ret;

	pid = bpf_get_current_pid_tgid() >> 32;
	if (!monitored_pid || pid != monitored_pid)
		return 0;

	/* Only refresh files we have already measured. */
	v = bpf_inode_storage_get(&prov_cache, dentry->d_inode, 0, 0);
	if (!v)
		return 0;

	bpf_dynptr_from_mem(value, sizeof(value), 0, &value_ptr);
	ret = bpf_get_dentry_xattr(dentry, PROV_XATTR, &value_ptr);
	v->trusted = ret == sizeof(trusted_value) &&
		     bpf_strncmp(value, sizeof(trusted_value), trusted_value) == 0;
	refresh_hits++;
	return 0;
}
