// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include "bpf_misc.h"

/*
 * This test has to load unprivileged, so unlike mem_rdonly_untrusted.c it
 * cannot pull in test_kmods kfuncs: resolving module BTF takes CAP_SYS_ADMIN.
 *
 * A void type ID turns any value into unsized rdonly untrusted memory, and
 * reads from it are unbounded, so it takes CAP_PERFMON just like reading
 * through a PTR_TO_BTF_ID does.
 */
SEC("socket")
__success
__caps_unpriv(CAP_BPF)
__failure_unpriv
__msg_unpriv("kfunc bpf_rdonly_cast with void type ID is allowed only to CAP_PERFMON and CAP_SYS_ADMIN")
int rdonly_cast_to_void_noperfmon(void *ctx)
{
	char *p;

	if (!bpf_core_enum_value_exists(enum bpf_features, BPF_FEAT_RDONLY_CAST_TO_VOID))
		return 42;

	p = bpf_rdonly_cast(0, 0);
	return p[0x7fff];
}

char _license[] SEC("license") = "GPL";
