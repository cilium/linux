// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

extern struct file *bpf_get_vma_file(struct vm_area_struct *vma) __ksym;
extern void bpf_put_file(struct file *file) __ksym;

__u64 ino;

/* The file backing a mapping is acquired, so it has to be released. */
SEC("lsm/file_mprotect")
__failure __msg("Unreleased reference")
int BPF_PROG(missing_put, struct vm_area_struct *vma, unsigned long reqprot,
	     unsigned long prot)
{
	struct file *file;

	file = bpf_get_vma_file(vma);
	if (file)
		ino = file->f_inode->i_ino;
	return 0;
}

/* An anonymous mapping has no file, so the result has to be checked. */
SEC("lsm/file_mprotect")
__failure __msg("invalid mem access 'trusted_ptr_or_null_'")
int BPF_PROG(null_deref, struct vm_area_struct *vma, unsigned long reqprot,
	     unsigned long prot)
{
	struct file *file;

	file = bpf_get_vma_file(vma);
	ino = file->f_inode->i_ino;
	bpf_put_file(file);
	return 0;
}

SEC("lsm/file_mprotect")
__success
int BPF_PROG(allow, struct vm_area_struct *vma, unsigned long reqprot,
	     unsigned long prot)
{
	struct file *file;

	file = bpf_get_vma_file(vma);
	if (!file)
		return 0;
	ino = file->f_inode->i_ino;
	bpf_put_file(file);
	return 0;
}
