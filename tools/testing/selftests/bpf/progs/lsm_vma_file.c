// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

extern struct file *bpf_get_vma_file(struct vm_area_struct *vma) __ksym;
extern void bpf_put_file(struct file *file) __ksym;

/* What the sleepable hook measured, keyed by the inode, for the atomic one
 * to enforce: file_mprotect runs under mmap_lock and cannot read a file.
 */
struct {
	__uint(type, BPF_MAP_TYPE_INODE_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u64);
} mapped SEC(".maps");

__u32 monitored_pid;
__u64 target_ino;
__u64 mmap_ino;
__u64 mprotect_ino;
__u32 mapped_seen;
__u32 anon_seen;
__u32 matched;
__u32 mprotects;
bool cow;
bool enabled;

SEC("lsm.s/mmap_file")
int BPF_PROG(on_mmap, struct file *file, unsigned long reqprot,
	     unsigned long prot, unsigned long flags)
{
	__u64 *rec;

	if (bpf_get_current_pid_tgid() >> 32 != monitored_pid || !enabled)
		return 0;
	/* An anonymous mapping is backed by no file at all. */
	if (!file || file->f_inode->i_ino != target_ino)
		return 0;
	rec = bpf_inode_storage_get(&mapped, file->f_inode, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!rec)
		return 0;
	*rec = file->f_inode->i_ino;
	mmap_ino = *rec;
	mapped_seen++;
	return 0;
}

/* The backing file is reached through the vma, and the reference taken on it
 * keeps the inode alive for the lookup.
 */
SEC("lsm/file_mprotect")
int BPF_PROG(on_mprotect, struct vm_area_struct *vma, unsigned long reqprot,
	     unsigned long prot)
{
	struct file *file;
	__u64 *rec;

	if (bpf_get_current_pid_tgid() >> 32 != monitored_pid || !enabled)
		return 0;
	file = bpf_get_vma_file(vma);
	if (!file) {
		anon_seen++;
		return 0;
	}
	rec = bpf_inode_storage_get(&mapped, file->f_inode, 0, 0);
	if (rec) {
		mprotect_ino = *rec;
		/* A mapping written through has been given an anon_vma. */
		cow = vma->anon_vma != NULL;
		matched++;
	}
	mprotects++;
	bpf_put_file(file);
	return 0;
}
