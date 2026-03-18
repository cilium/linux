// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <limits.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("socket")
__description("scalars: find linked scalars")
__failure
__msg("math between fp pointer and 2147483647 is not allowed")
__naked void scalars(void)
{
	asm volatile ("				\
	r0 = 0;					\
	r1 = 0x80000001 ll;			\
	r1 /= 1;				\
	r2 = r1;				\
	r4 = r1;				\
	w2 += 0x7FFFFFFF;			\
	w4 += 0;				\
	if r2 == 0 goto l0_%=;			\
	exit;					\
l0_%=:						\
	r4 >>= 63;				\
	r3 = 1;					\
	r3 -= r4;				\
	r3 *= 0x7FFFFFFF;			\
	r3 += r10;				\
	*(u8*)(r3 - 1) = r0;			\
	exit;					\
"	::: __clobber_all);
}

/*
 * Test that sync_linked_regs() preserves register IDs.
 *
 * The sync_linked_regs() function copies bounds from known_reg to linked
 * registers. When doing so, it must preserve each register's original id
 * to allow subsequent syncs from the same source to work correctly.
 *
 */
SEC("socket")
__success
__naked void sync_linked_regs_preserves_id(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r0 &= 0xff;	/* r0 in [0, 255] */			\
	r1 = r0;	/* r0, r1 linked with id 1 */		\
	r1 += 4;	/* r1 has id=1 and off=4 in [4, 259] */ \
	if r1 < 10 goto l0_%=;					\
	/* r1 in [10, 259], r0 synced to [6, 255] */		\
	r2 = r0;	/* r2 has id=1 and in [6, 255] */	\
	if r1 < 14 goto l0_%=;					\
	/* r1 in [14, 259], r0 synced to [10, 255] */		\
	if r0 >= 10 goto l0_%=;					\
	/* Never executed */					\
	r0 /= 0;						\
l0_%=:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__success
__naked void scalars_neg(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 0xff;					\
	r1 = r0;					\
	r1 += -4;					\
	if r1 s< 0 goto l0_%=;				\
	if r0 != 0 goto l0_%=;				\
	r0 /= 0;					\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* Same test but using BPF_SUB instead of BPF_ADD with negative immediate */
SEC("socket")
__success
__naked void scalars_neg_sub(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 0xff;					\
	r1 = r0;					\
	r1 -= 4;					\
	if r1 s< 0 goto l0_%=;				\
	if r0 != 0 goto l0_%=;				\
	r0 /= 0;					\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* alu32 with negative offset */
SEC("socket")
__success
__naked void scalars_neg_alu32_add(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	w0 &= 0xff;					\
	w1 = w0;					\
	w1 += -4;					\
	if w1 s< 0 goto l0_%=;				\
	if w0 != 0 goto l0_%=;				\
	r0 /= 0;					\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* alu32 with negative offset using SUB */
SEC("socket")
__success
__naked void scalars_neg_alu32_sub(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	w0 &= 0xff;					\
	w1 = w0;					\
	w1 -= 4;					\
	if w1 s< 0 goto l0_%=;				\
	if w0 != 0 goto l0_%=;				\
	r0 /= 0;					\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* Positive offset: r1 = r0 + 4, then if r1 >= 6, r0 >= 2, so r0 != 0 */
SEC("socket")
__success
__naked void scalars_pos(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 0xff;					\
	r1 = r0;					\
	r1 += 4;					\
	if r1 < 6 goto l0_%=;				\
	if r0 != 0 goto l0_%=;				\
	r0 /= 0;					\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* SUB with negative immediate: r1 -= -4 is equivalent to r1 += 4 */
SEC("socket")
__success
__naked void scalars_sub_neg_imm(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 0xff;					\
	r1 = r0;					\
	r1 -= -4;					\
	if r1 < 6 goto l0_%=;				\
	if r0 != 0 goto l0_%=;				\
	r0 /= 0;					\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* Double ADD clears the ID (can't accumulate offsets) */
SEC("socket")
__failure
__msg("div by zero")
__naked void scalars_double_add(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 0xff;					\
	r1 = r0;					\
	r1 += 2;					\
	r1 += 2;					\
	if r1 < 6 goto l0_%=;				\
	if r0 != 0 goto l0_%=;				\
	r0 /= 0;					\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Test that sync_linked_regs() correctly handles large offset differences.
 * r1.off = S32_MIN, r2.off = 1, delta = S32_MIN - 1 requires 64-bit math.
 */
SEC("socket")
__success
__naked void scalars_sync_delta_overflow(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 0xff;					\
	r1 = r0;					\
	r2 = r0;					\
	r1 += %[s32_min];				\
	r2 += 1;					\
	if r2 s< 100 goto l0_%=;			\
	if r1 s< 0 goto l0_%=;				\
	r0 /= 0;					\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32),
	  [s32_min]"i"(INT_MIN)
	: __clobber_all);
}

/*
 * Another large delta case: r1.off = S32_MAX, r2.off = -1.
 * delta = S32_MAX - (-1) = S32_MAX + 1 requires 64-bit math.
 */
SEC("socket")
__success
__naked void scalars_sync_delta_overflow_large_range(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 0xff;					\
	r1 = r0;					\
	r2 = r0;					\
	r1 += %[s32_max];				\
	r2 += -1;					\
	if r2 s< 0 goto l0_%=;				\
	if r1 s>= 0 goto l0_%=;				\
	r0 /= 0;					\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32),
	  [s32_max]"i"(INT_MAX)
	: __clobber_all);
}

/*
 * Test linked scalar tracking with alu32 and large positive offset (0x7FFFFFFF).
 * After w1 += 0x7FFFFFFF, w1 wraps to negative for any r0 >= 1.
 * If w1 is signed-negative, then r0 >= 1, so r0 != 0.
 */
SEC("socket")
__success
__naked void scalars_alu32_big_offset(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	w0 &= 0xff;					\
	w1 = w0;					\
	w1 += 0x7FFFFFFF;				\
	if w1 s>= 0 goto l0_%=;				\
	if w0 != 0 goto l0_%=;				\
	r0 /= 0;					\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__failure
__msg("div by zero")
__naked void scalars_alu32_basic(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r1 = r0;					\
	w1 += 1;					\
	if r1 > 10 goto 1f;				\
	r0 >>= 32;					\
	if r0 == 0 goto 1f;				\
	r0 /= 0;					\
1:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Test alu32 linked register tracking with wrapping.
 * R0 is bounded to [0xffffff00, 0xffffffff] (high 32-bit values)
 * w1 += 0x100 causes R1 to wrap to [0, 0xff]
 *
 * After sync_linked_regs, if bounds are computed correctly:
 *   R0 should be [0x00000000_ffffff00, 0x00000000_ffffff80]
 *   R0 >> 32 == 0, so div by zero is unreachable
 *
 * If bounds are computed incorrectly (64-bit underflow):
 *   R0 becomes [0xffffffff_ffffff00, 0xffffffff_ffffff80]
 *   R0 >> 32 == 0xffffffff != 0, so div by zero is reachable
 */
SEC("socket")
__success
__naked void scalars_alu32_wrap(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	w0 |= 0xffffff00;				\
	r1 = r0;					\
	w1 += 0x100;					\
	if r1 > 0x80 goto l0_%=;			\
	r2 = r0;					\
	r2 >>= 32;					\
	if r2 == 0 goto l0_%=;				\
	r0 /= 0;					\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Test that regsafe() prevents pruning when two paths reach the same program
 * point with linked registers carrying different ADD_CONST flags (one
 * BPF_ADD_CONST32 from alu32, another BPF_ADD_CONST64 from alu64).
 *
 * Path A (fall-through): w7 += 1  -> BPF_ADD_CONST32 on r7
 * Path B (branch taken): r7 += 1  -> BPF_ADD_CONST64 on r7
 *
 * BPF_F_TEST_STATE_FREQ forces checkpoints at every instruction, ensuring
 * the merge point is a potential pruning point. The verifier must not prune
 * path B based on path A's cached state, because the ADD_CONST flag
 * difference means sync_linked_regs() would behave differently in the
 * continuation (alu32 applies zext, alu64 does not).
 *
 * Path A: after sync with r6 = 0xFFFFFFFF, r7 = zext(0x100000000) = 0,
 *   so r7 >> 32 == 0 -> exits safely.
 * Path B: after sync with r6 = 0xFFFFFFFF, r7 = 0x100000000 (no zext),
 *   so r7 >> 32 == 1 -> reaches div/0.
 *
 * Overall: program must be rejected because path B is unsafe.
 */
SEC("socket")
__failure __msg("div by zero")
__flag(BPF_F_TEST_STATE_FREQ)
__naked void scalars_alu32_alu64_regsafe_pruning(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	/* Constrain r6 to [0, U32_MAX] so alu32 link is preserved */ \
	r9 = 1;						\
	r9 <<= 32;		/* r9 = 0x100000000 */		\
	if r6 >= r9 goto l0_%=;				\
	/* r6 in [0, 0xFFFFFFFF] */				\
	r7 = r6;		/* linked: same id as r6 */	\
	/* Get another random value for the path branch */	\
	call %[bpf_get_prandom_u32];				\
	if r0 > 0 goto l_pathb_%=;				\
	/* Path A: alu32 */					\
	w7 += 1;		/* BPF_ADD_CONST32, delta = 1 */\
	goto l_merge_%=;					\
l_pathb_%=:							\
	/* Path B: alu64 */					\
	r7 += 1;		/* BPF_ADD_CONST64, delta = 1 */\
l_merge_%=:							\
	/* Merge point: regsafe() compares path B against cached path A. */ \
	/* Narrow r6 to trigger sync_linked_regs for r7 */	\
	r9 -= 1;		/* r9 = 0xFFFFFFFF */		\
	if r6 < r9 goto l0_%=;					\
	/* r6 = 0xFFFFFFFF */					\
	/* sync: r7 = 0xFFFFFFFF + 1 = 0x100000000 */		\
	/* Path A: zext -> r7 = 0 */				\
	/* Path B: no zext -> r7 = 0x100000000 */		\
	r7 >>= 32;						\
	if r7 == 0 goto l0_%=;					\
	r0 /= 0;		/* div by zero on path B */	\
l0_%=:								\
	r0 = 0;						\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__success
void alu32_negative_offset(void)
{
	volatile char path[5];
	volatile int offset = bpf_get_prandom_u32();
	int off = offset;

	if (off >= 5 && off < 10)
		path[off - 5] = '.';

	/* So compiler doesn't say: error: variable 'path' set but not used */
	__sink(path[0]);
}

void dummy_calls(void)
{
	bpf_iter_num_new(0, 0, 0);
	bpf_iter_num_next(0);
	bpf_iter_num_destroy(0);
}

SEC("socket")
__success
__flag(BPF_F_TEST_STATE_FREQ)
int spurious_precision_marks(void *ctx)
{
	struct bpf_iter_num iter;

	asm volatile(
		"r1 = %[iter];"
		"r2 = 0;"
		"r3 = 10;"
		"call %[bpf_iter_num_new];"
	"1:"
		"r1 = %[iter];"
		"call %[bpf_iter_num_next];"
		"if r0 == 0 goto 4f;"
		"r7 = *(u32 *)(r0 + 0);"
		"r8 = *(u32 *)(r0 + 0);"
		/* This jump can't be predicted and does not change r7 or r8 state. */
		"if r7 > r8 goto 2f;"
		/* Branch explored first ties r2 and r7 as having the same id. */
		"r2 = r7;"
		"goto 3f;"
	"2:"
		/* Branch explored second does not tie r2 and r7 but has a function call. */
		"call %[bpf_get_prandom_u32];"
	"3:"
		/*
		 * A checkpoint.
		 * When first branch is explored, this would inject linked registers
		 * r2 and r7 into the jump history.
		 * When second branch is explored, this would be a cache hit point,
		 * triggering propagate_precision().
		 */
		"if r7 <= 42 goto +0;"
		/*
		 * Mark r7 as precise using an if condition that is always true.
		 * When reached via the second branch, this triggered a bug in the backtrack_insn()
		 * because r2 (tied to r7) was propagated as precise to a call.
		 */
		"if r7 <= 0xffffFFFF goto +0;"
		"goto 1b;"
	"4:"
		"r1 = %[iter];"
		"call %[bpf_iter_num_destroy];"
		:
		: __imm_ptr(iter),
		  __imm(bpf_iter_num_new),
		  __imm(bpf_iter_num_next),
		  __imm(bpf_iter_num_destroy),
		  __imm(bpf_get_prandom_u32)
		: __clobber_common, "r7", "r8"
	);

	return 0;
}

/*
 * Test that sync_linked_regs() checks reg->id (the target linked register)
 * rather than known_reg->id (the narrowed register from the conditional) for
 * the BPF_ADD_CONST32 flag when deciding whether to call zext_32_to_64().
 *
 * r0 = bpf_get_prandom_u32()   [0, U32_MAX]
 * r1 = r0                      linked, same ID
 * w1 += 5                      alu32: r1.id gets BPF_ADD_CONST32
 * if w0 < 0xFFFFFFFC goto out  JMP32 narrows r0 to [0xFFFFFFFC, 0xFFFFFFFF]
 *                               sync_linked_regs() propagates to r1
 *
 * Fixed:  reg->id (r1) has BPF_ADD_CONST32  -> zext_32_to_64() called
 *         r1 = [1, 4], r1 >> 32 = 0, div-by-zero is dead code  -> accepted
 *
 * Bug:    known_reg->id (r0) lacks BPF_ADD_CONST32 -> zext_32_to_64() skipped
 *         r1 = [0x100000001, 0x100000004], r1 >> 32 = 1                -> rejected
 */
SEC("socket")
__description("sync_linked_regs: zext on alu32-derived linked reg")
__success
__naked void sync_linked_regs_zext_alu32(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r1 = r0;					\
	w1 += 5;					\
	if w0 < 0xFFFFFFFC goto l0_%=;			\
	r1 >>= 32;					\
	if r1 == 0 goto l0_%=;				\
	r0 /= 0;					\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Mixed BPF_ADD_CONST32/CONST64: sync_linked_regs() must skip registers
 * whose ADD_CONST flavor differs from known_reg's, because the delta
 * between a 32-bit wrapping offset and a 64-bit offset produces wrong
 * bounds.
 *
 * Here reg (r2) has CONST32 and known_reg (r1) has CONST64. Without
 * the skip, the sync would copy r1's narrowed 64-bit bounds and add
 * a delta, producing r2 = [0x100000001, 0x100000004] (above u32 range)
 * even though the alu32 zero-extends r2 to [1, 4] at runtime.
 *
 * With the skip, r2 retains its original alu32-derived bounds (within
 * u32 range), so r2 >> 32 = 0.
 */
SEC("socket")
__description("sync_linked_regs: skip CONST32 reg when known_reg is CONST64")
__success
__naked void sync_linked_regs_skip_mixed_const64_known(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r1 = r0;					\
	r2 = r0;					\
	r1 += 3;					\
	w2 += 5;					\
	r3 = 1;						\
	r3 <<= 32;					\
	r3 -= 1;					\
	if r1 < r3 goto l0_%=;				\
	r2 >>= 32;					\
	if r2 == 0 goto l0_%=;				\
	r0 /= 0;					\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Mixed BPF_ADD_CONST32/CONST64 (reverse direction): reg (r1) has CONST64,
 * known_reg (r2) has CONST32. Without the skip, the sync would copy r2's
 * zero-extended bounds and add a delta, then the old code would call zext
 * (because known_reg has CONST32), unsoundly truncating r1's 64-bit bounds
 * even though r1 genuinely exceeds u32 (from alu64 on a high base value).
 *
 * With the skip, r1 retains its original alu64 bounds where r1 >> 32 = 1,
 * so the verifier correctly knows the upper 32 bits are non-zero.
 */
SEC("socket")
__description("sync_linked_regs: skip CONST64 reg when known_reg is CONST32")
__success
__naked void sync_linked_regs_skip_mixed_const32_known(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	w0 |= 0xffffff00;				\
	r1 = r0;					\
	r2 = r0;					\
	r1 += 0x100;					\
	w2 += 3;					\
	if w2 < 0xffffff03 goto l0_%=;			\
	r1 >>= 32;					\
	if r1 > 0 goto l0_%=;				\
	r0 /= 0;					\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
