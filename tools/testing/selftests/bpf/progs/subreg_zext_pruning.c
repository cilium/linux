// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

/*
 * r6 is defined twice: by a 64-bit write on the path the verifier explores
 * first, which records the state at l0_%=, and by a 32-bit write on the path
 * explored second, which is pruned there because r7 is dead and r6 holds the
 * same value on both. The 64-bit read of r6 below l0_%= therefore only runs on
 * the first path, so the zero extension the second path needs for its 32-bit
 * definition has to be marked where the walk stops.
 *
 * Loaded with BPF_F_TEST_RND_HI32, so a definition that was not marked gets a
 * random upper half instead of a zero extension, and returning r6 >> 32 makes
 * that visible. Which of the two paths runs depends on bpf_get_prandom_u32(),
 * hence the caller runs this many times rather than once.
 */
SEC("socket")
__naked void subreg_def_survives_pruning(void)
{
	asm volatile ("					\
	r0 = 0;						\
	r8 = r1;					\
	call %[bpf_get_prandom_u32];			\
	r7 = r0;					\
	r7 &= 1;					\
	r6 = 0;			/* 64-bit define */	\
	if r7 != 0 goto l1_%=;				\
	goto l0_%=;					\
l1_%=:	w6 = 0;			/* 32-bit define */	\
l0_%=:	r0 = r6;		/* 64-bit read */	\
	r0 >>= 32;					\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
