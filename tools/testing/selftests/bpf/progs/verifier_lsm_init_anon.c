// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_kfuncs.h"
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

const char xattr_origin[] = "security.bpf.origin";
char value_buf[8] = "o";
char name_buf[32];
int scratch_count;

/* An anonymous inode has no xattrs: the hook is handed the inode and the
 * name of its class, and a policy decides from those alone.
 */
SEC("lsm/inode_init_security_anon")
__success
int BPF_PROG(allow_name_read, struct inode *inode, const struct qstr *name,
	     const struct inode *context_inode)
{
	bpf_probe_read_kernel_str(name_buf, sizeof(name_buf), name->name);
	return 0;
}

/* The hook runs where it cannot sleep, so the xattr readers are out of
 * reach: an anonymous inode's label cannot be read here.
 */
SEC("lsm/inode_init_security_anon")
__failure __msg("program must be sleepable to call sleepable kfunc")
int BPF_PROG(reject_get_inode_xattr, struct inode *inode,
	     const struct qstr *name, const struct inode *context_inode)
{
	struct bpf_dynptr value;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_get_inode_xattr(inode, NULL, xattr_origin, &value);
	return 0;
}

/* Nor may the program ask to be sleepable: the hook is not. */
SEC("lsm.s/inode_init_security_anon")
__failure __msg("bpf_lsm_inode_init_security_anon is not sleepable")
int BPF_PROG(reject_sleepable, struct inode *inode, const struct qstr *name,
	     const struct inode *context_inode)
{
	return 0;
}

/* And there is no slot to write one into: bpf_init_inode_xattr() belongs to
 * inode_init_security, which is handed an xattr array.
 */
SEC("lsm/inode_init_security_anon")
__failure __msg("calling kernel function bpf_init_inode_xattr is not allowed")
int BPF_PROG(reject_init_inode_xattr, struct inode *inode,
	     const struct qstr *name, const struct inode *context_inode)
{
	struct bpf_dynptr value;

	bpf_dynptr_from_mem(value_buf, sizeof(value_buf), 0, &value);
	bpf_init_inode_xattr(NULL, &scratch_count, xattr_origin, &value);
	return 0;
}
