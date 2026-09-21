// SPDX-License-Identifier: GPL-2.0
/* Only the read side came out of the hook restriction.
 *
 * bpf_set_kernfs_xattr() sleeps and mutates a node that is already published
 * by the time any other hook sees it, so it stays admitted on
 * kernfs_init_security alone.
 */
#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_kfuncs.h"
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

#define LABEL_MAX	32

extern struct cgroup *bpf_cgroup_from_id(__u64 cgid) __ksym;
extern void bpf_cgroup_release(struct cgroup *cgrp) __ksym;

const char xattr_zone[] = "security.bpf.zone";
char probe[LABEL_MAX];

SEC("lsm.s/socket_connect")
__failure __msg("calling kernel function bpf_set_kernfs_xattr is not allowed")
int BPF_PROG(set_at_connect, struct socket *sock)
{
	struct bpf_dynptr value;
	struct cgroup *cgrp;

	cgrp = bpf_cgroup_from_id(bpf_get_current_cgroup_id());
	if (!cgrp)
		return 0;
	bpf_dynptr_from_mem(probe, sizeof(probe), 0, &value);
	bpf_set_kernfs_xattr(cgrp->kn, xattr_zone, &value);
	bpf_cgroup_release(cgrp);
	return 0;
}
