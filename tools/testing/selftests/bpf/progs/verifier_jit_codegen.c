// SPDX-License-Identifier: GPL-2.0
/*
 * JIT code generation for instruction patterns with a shorter or faster
 * native form. The results are checked at run time on all architectures,
 * the selected instructions on the disassembly of the x86-64 JIT.
 */
#define BPF_NO_KFUNC_PROTOTYPES
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bpf_misc.h"
#include "bpf_kfuncs.h"
#include "bpf_experimental.h"
#include "bpf_arena_common.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1);
} arena SEC(".maps");

/* Inputs the verifier cannot fold, so that all the branches stay */
__u64 vals[] = { 0x1122334455667788, 0xc5, 3, 0x7f };

SEC("socket")
__description("zero offset loads and stores")
__arch_x86_64
__jited("...")
__jited("	movq	%rsi, (%rdi)")
__jited("	movq	(%rdi), %rax")
__jited("...")
__jited("	movzbl	(%rdi), %edx")
__jited("...")
__jited("	movzwl	(%rdi), %ecx")
__jited("...")
__jited("	movl	(%rdi), %r8d")
__jited("...")
__jited("	movq	(%r13), %r13")
__jited("...")
__jited("	movb	$-0x67, (%rdi)")
__jited("	movzbl	-0x8(%rbp), %r14d")
__jited("...")
__jited("	movl	%esi, (%rdi)")
__jited("...")
__jited("	movq	$-0x1, (%rdi)")
__arch_arm64 __arch_riscv64 __arch_s390x __arch_loongarch
__success __retval(0)
__naked void zero_offset_ldx_stx(void)
{
	asm volatile ("					\
	r1 = r10;					\
	r1 += -8;					\
	r2 = %[vals] ll;				\
	r2 = *(u64 *)(r2 + 0);				\
	*(u64 *)(r1 + 0) = r2;				\
	r0 = *(u64 *)(r1 + 0);				\
	if r0 != r2 goto l0_%=;				\
	r3 = *(u8 *)(r1 + 0);				\
	if r3 != 0x88 goto l0_%=;			\
	r4 = *(u16 *)(r1 + 0);				\
	if r4 != 0x7788 goto l0_%=;			\
	r5 = *(u32 *)(r1 + 0);				\
	if r5 != 0x55667788 goto l0_%=;			\
	r7 = r1;					\
	r7 = *(u64 *)(r7 + 0);				\
	if r7 != r2 goto l0_%=;				\
	*(u8 *)(r1 + 0) = 0x99;				\
	r8 = *(u8 *)(r10 - 8);				\
	if r8 != 0x99 goto l0_%=;			\
	*(u32 *)(r1 + 0) = r2;				\
	r0 = *(u32 *)(r10 - 8);				\
	if r0 != r5 goto l0_%=;				\
	*(u64 *)(r1 + 0) = -1;				\
	r0 = *(u64 *)(r10 - 8);				\
	r0 += 1;					\
	exit;						\
l0_%=:							\
	r0 = 1;						\
	exit;						\
"	:
	: __imm_addr(vals)
	: __clobber_all);
}

#if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
SEC("syscall")
__description("arena access with zero offset")
__arch_x86_64
__jited("...")
__jited("	movq	%r14, (%r13,%r12)")
__jited("	movq	(%r13,%r12), %r15")
__jited("...")
__jited("	movq	%r14, (%rdi,%r12)")
__jited("	movq	(%rdi,%r12), %rsi")
__jited("...")
__jited("	movzbl	(%rdi,%r12), %edx")
__jited("...")
__jited("	movzwl	(%rdi,%r12), %ecx")
__jited("...")
__jited("	movl	(%rdi,%r12), %r8d")
__jited("...")
__jited("	movl	$0x1234, (%rdi,%r12)")
__jited("	lock")
__jited("	addq	%r14, (%r13,%r12)")
__jited("	movq	(%rdi,%r12), %rsi")
__arch_arm64 __arch_riscv64 __arch_s390x __arch_loongarch
__success __retval(0)
int arena_zero_off(void *ctx)
{
	void __arena *page;
	__u64 res;

	page = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	if (!page)
		return 1;
	res = (__u32)(__u64)page;
	/* r13 as base keeps its displacement byte, rdi drops it */
	asm volatile ("					\
	r7 = %[res];					\
	r7 = addr_space_cast(r7, 0x0, 0x1);		\
	r1 = r7;					\
	r8 = 0x1122334455667788 ll;			\
	*(u64 *)(r7 + 0) = r8;				\
	r9 = *(u64 *)(r7 + 0);				\
	r9 ^= r8;					\
	*(u64 *)(r1 + 0) = r8;				\
	r2 = *(u64 *)(r1 + 0);				\
	r2 ^= r8;					\
	r9 |= r2;					\
	r3 = *(u8 *)(r1 + 0);				\
	r3 ^= 0x88;					\
	r9 |= r3;					\
	r4 = *(u16 *)(r1 + 0);				\
	r4 ^= 0x7788;					\
	r9 |= r4;					\
	r5 = *(u32 *)(r1 + 0);				\
	r5 ^= 0x55667788;				\
	r9 |= r5;					\
	*(u32 *)(r1 + 0) = 0x1234;			\
	lock *(u64 *)(r7 + 0) += r8;			\
	r2 = *(u64 *)(r1 + 0);				\
	r8 = 0x22446688556689bc ll;			\
	r2 ^= r8;					\
	r9 |= r2;					\
	%[res] = r9;					\
"	: [res]"+r"(res)
	:
	: "r1", "r2", "r3", "r4", "r5", "r7", "r8", "r9");
	return res != 0;
}
#endif

SEC("socket")
__description("test and cmp immediates")
__arch_x86_64
__jited("...")
__jited("	testb	$-0x1, %dil")
__jited("	jne	{{.*}}")
__jited("...")
__jited("	testq	$0x200, %rdi")
__jited("	jne	{{.*}}")
__jited("	testb	$0x40, %dil")
__jited("	jne	{{.*}}")
__jited("...")
__jited("	testb	$-0x80, %al")
__jited("	jne	{{.*}}")
__jited("...")
__jited("	testb	$0x2, %r14b")
__jited("	jne	{{.*}}")
__jited("	testb	$0x10, %r14b")
__jited("	jne	{{.*}}")
__jited("...")
__jited("	testq	$0x1000, %rdi")
__jited("	jne	{{.*}}")
__jited("...")
__jited("	testq	$0x2000, %rax")
__jited("	jne	{{.*}}")
__jited("	testl	$0x100, %eax")
__jited("	jne	{{.*}}")
__jited("	cmpq	$0x40c0, %rax")
__jited("	je	{{.*}}")
__jited("	cmpl	$0x80c0, %eax")
__jited("	je	{{.*}}")
__jited("	cmpq	$0x100c0, %rdi")
__jited("	je	{{.*}}")
__jited("...")
__jited("	cmpq	$0x80, %rax")
__jited("	je	{{.*}}")
__jited("	cmpq	$0x80, %rsi")
__jited("	je	{{.*}}")
__jited("	cmpq	$0x7f, %rax")
__jited("	jne	{{.*}}")
__arch_arm64 __arch_riscv64 __arch_s390x __arch_loongarch
__success __retval(0)
__naked void test_cmp_imm(void)
{
	asm volatile ("					\
	r6 = %[vals] ll;				\
	r7 = *(u64 *)(r6 + 24);				\
	r6 = *(u64 *)(r6 + 8);				\
	r1 = r6;					\
	if r1 & 0xff goto l3_%=;			\
	goto l0_%=;					\
l3_%=:							\
	if r1 & 0x200 goto l0_%=;			\
	if r1 & 0x40 goto l1_%=;			\
	goto l0_%=;					\
l1_%=:							\
	r0 = r6;					\
	if r0 & 0x80 goto l2_%=;			\
	goto l0_%=;					\
l2_%=:							\
	r8 = r6;					\
	if r8 & 0x2 goto l0_%=;				\
	if w8 & 0x10 goto l0_%=;			\
	r1 = r6;					\
	if r1 & 0x1000 goto l0_%=;			\
	r0 = r6;					\
	if r0 & 0x2000 goto l0_%=;			\
	if w0 & 0x100 goto l0_%=;			\
	if r0 == 0x40c0 goto l0_%=;			\
	if w0 == 0x80c0 goto l0_%=;			\
	if r1 == 0x100c0 goto l0_%=;			\
	r0 = r7;					\
	r2 = r7;					\
	if r0 == 0x80 goto l0_%=;			\
	if r2 == 0x80 goto l0_%=;			\
	if r0 != 0x7f goto l0_%=;			\
	r0 = 0;						\
	exit;						\
l0_%=:							\
	r0 = 1;						\
	exit;						\
"	:
	: __imm_addr(vals)
	: __clobber_all);
}

SEC("socket")
__description("atomics with zero offset")
__arch_x86_64
__jited("...")
__jited("	lock")
__jited("	addq	%rsi, (%rdi)")
__jited("...")
__jited("	lock")
__jited("	xaddq	%rdx, (%rdi)")
__jited("...")
__jited("	xchgq	%rcx, (%rdi)")
__jited("...")
__jited("	lock")
__jited("	cmpxchgq	%r8, (%rdi)")
__jited("...")
__jited("	lock")
__jited("	addq	%r14, (%r13)")
__jited("	lock")
__jited("	orl	%r14d, (%rdi)")
__arch_arm64 __arch_riscv64 __arch_s390x __arch_loongarch
__success __retval(0)
__naked void atomics_zero_off(void)
{
	asm volatile ("					\
	r6 = %[vals] ll;				\
	r6 = *(u64 *)(r6 + 0);				\
	r1 = r10;					\
	r1 += -8;					\
	*(u64 *)(r1 + 0) = r6;				\
	r2 = 1;						\
	lock *(u64 *)(r1 + 0) += r2;			\
	r3 = 2;						\
	r3 = atomic_fetch_add((u64 *)(r1 + 0), r3);	\
	r4 = 0x10;					\
	r4 = xchg_64(r1 + 0, r4);			\
	r0 = 0x10;					\
	r5 = 0x20;					\
	r0 = cmpxchg_64(r1 + 0, r0, r5);		\
	r7 = r1;					\
	r8 = 1;						\
	lock *(u64 *)(r7 + 0) += r8;			\
	lock *(u32 *)(r1 + 0) |= w8;			\
	r6 += 1;					\
	if r3 != r6 goto l0_%=;				\
	r6 += 2;					\
	if r4 != r6 goto l0_%=;				\
	if r0 != 0x10 goto l0_%=;			\
	r0 = *(u64 *)(r10 - 8);				\
	if r0 != 0x21 goto l0_%=;			\
	r0 = 0;						\
	exit;						\
l0_%=:							\
	r0 = 1;						\
	exit;						\
"	:
	: __imm_addr(vals)
	: __clobber_all);
}

SEC("socket")
__description("byte and word masks, not")
__arch_x86_64
__jited("...")
__jited("	movzbl	%dil, %edi")
__jited("...")
__jited("	movzwl	%ax, %eax")
__jited("...")
__jited("	movzbl	%r14b, %r14d")
__jited("...")
__jited("	movzwl	%r13w, %r13d")
__jited("...")
__jited("	notq	%rdi")
__jited("...")
__jited("	notl	%eax")
__arch_arm64 __arch_riscv64 __arch_s390x __arch_loongarch
__success __retval(0)
__naked void masks_not(void)
{
	asm volatile ("					\
	r6 = %[vals] ll;				\
	r6 = *(u64 *)(r6 + 0);				\
	r1 = r6;					\
	r1 &= 0xff;					\
	if r1 != 0x88 goto l0_%=;			\
	r0 = r6;					\
	r0 &= 0xffff;					\
	if r0 != 0x7788 goto l0_%=;			\
	r8 = r6;					\
	w8 &= 0xff;					\
	if r8 != 0x88 goto l0_%=;			\
	r7 = r6;					\
	w7 &= 0xffff;					\
	if r7 != 0x7788 goto l0_%=;			\
	r1 = r6;					\
	r1 ^= -1;					\
	r2 = 0xeeddccbbaa998877 ll;			\
	if r1 != r2 goto l0_%=;				\
	r0 = r6;					\
	w0 ^= -1;					\
	r2 = 0xaa998877 ll;				\
	if r0 != r2 goto l0_%=;				\
	r0 = 0;						\
	exit;						\
l0_%=:							\
	r0 = 1;						\
	exit;						\
"	:
	: __imm_addr(vals)
	: __clobber_all);
}

SEC("socket")
__description("16-bit byte swap")
__arch_x86_64
__jited("...")
__jited("	bswapl	%edi")
__jited("	shrl	$0x10, %edi")
__jited("...")
__jited("	bswapl	%eax")
__jited("	shrl	$0x10, %eax")
__jited("...")
__jited("	bswapl	%r14d")
__jited("	shrl	$0x10, %r14d")
__jited("...")
__jited("	movzwl	%r13w, %r13d")
__arch_arm64 __arch_riscv64 __arch_s390x __arch_loongarch
__success __retval(0)
__naked void bswap16(void)
{
	asm volatile ("					\
	r6 = %[vals] ll;				\
	r6 = *(u64 *)(r6 + 0);				\
	r1 = r6;					\
	r1 = be16 r1;					\
	if r1 != 0x8877 goto l0_%=;			\
	r0 = r6;					\
	r0 = be16 r0;					\
	if r0 != 0x8877 goto l0_%=;			\
	r8 = r6;					\
	r8 = be16 r8;					\
	if r8 != 0x8877 goto l0_%=;			\
	r7 = r6;					\
	r7 = le16 r7;					\
	if r7 != 0x7788 goto l0_%=;			\
	r0 = 0;						\
	exit;						\
l0_%=:							\
	r0 = 1;						\
	exit;						\
"	:
	: __imm_addr(vals)
	: __clobber_all);
}

SEC("socket")
__description("shifts with the count in a register")
__arch_x86_64
__jited("...")
__jited("	{{(shlxq	%rcx, %rdi, %rdi|shlq	%cl, %rdi)}}")
__jited("...")
__jited("	{{(shrxl	%ecx, %eax, %eax|shrl	%cl, %eax)}}")
__jited("...")
__jited("	{{(sarxq	%rcx, %rcx, %rcx|sarq	%cl, %rcx)}}")
__arch_arm64 __arch_riscv64 __arch_s390x __arch_loongarch
__success __retval(0)
__naked void shifts_by_reg(void)
{
	asm volatile ("					\
	r6 = %[vals] ll;				\
	r4 = *(u64 *)(r6 + 16);				\
	r6 = *(u64 *)(r6 + 8);				\
	r1 = r6;					\
	r1 <<= r4;					\
	if r1 != 0x628 goto l0_%=;			\
	r0 = r6;					\
	w0 >>= w4;					\
	if r0 != 0x18 goto l0_%=;			\
	r4 s>>= r4;					\
	if r4 != 0 goto l0_%=;				\
	r0 = 0;						\
	exit;						\
l0_%=:							\
	r0 = 1;						\
	exit;						\
"	:
	: __imm_addr(vals)
	: __clobber_all);
}

SEC("tc")
__description("probe_mem address check")
__arch_x86_64
__jited("...")
__jited("	leaq	0x{{[0-9a-f]+}}(%r{{[a-z0-9]+}}), %r11")
__jited("	shrq	$0x{{(30|39)}}, %r11")
__jited("	jne	{{.*}}")
__jited("	xorl	%{{[a-z0-9]+}}, %{{[a-z0-9]+}}")
__jited("	jmp	{{.*}}")
__arch_arm64 __arch_riscv64 __arch_s390x __arch_loongarch
__success __retval(0)
int probe_mem_check(struct __sk_buff *ctx)
{
	__u32 id = bpf_core_type_id_kernel(struct sk_buff);
	struct sk_buff *skb = bpf_rdonly_cast(ctx, id);
	struct sk_buff *null = bpf_rdonly_cast((void *)0, id);
	struct sk_buff *user = bpf_rdonly_cast((void *)0x00007ffffffff000, id);
	struct sk_buff *noncanon = bpf_rdonly_cast((void *)0x0000900000000000, id);
	struct sk_buff *vsyscall = bpf_rdonly_cast((void *)0xffffffffff600000, id);

	/* Kernel address, the load goes through */
	if (skb->len != ctx->len)
		return 1;
	/* Everything else is zeroed without touching the address */
	return null->len | user->len | noncanon->len | vsyscall->len;
}

SEC("tc")
__description("probe_mem with extended registers")
__arch_x86_64
__jited("...")
__jited("	leaq	0xa0{{[0-9a-f]+}}(%r13), %r11")
__jited("	shrq	$0x{{(30|39)}}, %r11")
__jited("	jne	{{.*}}")
__jited("	xorl	%r14d, %r14d")
__jited("	jmp	{{.*}}")
__jited("	movl	{{.*}}(%r13), %r14d")
__arch_arm64 __arch_riscv64 __arch_s390x __arch_loongarch
__success __retval(0)
int probe_mem_ereg(struct __sk_buff *ctx)
{
	struct sk_buff *skb = bpf_rdonly_cast(ctx, bpf_core_type_id_kernel(struct sk_buff));
	__u64 len;

	/* Pin the base and destination to r13 and r14 */
	asm volatile ("					\
	r7 = %[skb];					\
	r8 = *(u32 *)(r7 + %[off]);			\
	%[len] = r8;					\
"	: [len]"=r"(len)
	: [skb]"r"(skb), [off]"i"(offsetof(struct sk_buff, len))
	: "r7", "r8");
	return len != ctx->len;
}

SEC("socket")
__description("multiplication by constants")
__arch_x86_64
__jited("...")
__jited("	leaq	(%rdi,%rdi,2), %rdi")
__jited("...")
__jited("	leal	(%rax,%rax,4), %eax")
__jited("...")
__jited("	leaq	(%r13,%r13,8), %r13")
__jited("...")
__jited("	shlq	$0x3, %r14")
__jited("...")
__jited("	leal	(%r14,%r14,4), %r14d")
__jited("...")
__jited("	shll	%edi")
__jited("...")
__jited("	imulq	$0x7, %rsi, %rsi")
__arch_arm64 __arch_riscv64 __arch_s390x __arch_loongarch
__success __retval(0)
__naked void mul_const(void)
{
	asm volatile ("					\
	r6 = %[vals] ll;				\
	r6 = *(u64 *)(r6 + 0);				\
	r1 = r6;					\
	r1 *= 3;					\
	r2 = 0x336699cd00336698 ll;			\
	if r1 != r2 goto l0_%=;				\
	r0 = r6;					\
	w0 *= 5;					\
	r2 = 0xab0055a8 ll;				\
	if r0 != r2 goto l0_%=;				\
	r7 = r6;					\
	r7 *= 9;					\
	r2 = 0x9a33cd67009a33c8 ll;			\
	if r7 != r2 goto l0_%=;				\
	r8 = r6;					\
	r8 *= 8;					\
	r2 = 0x89119a22ab33bc40 ll;			\
	if r8 != r2 goto l0_%=;				\
	r8 = r6;					\
	w8 *= 5;					\
	r2 = 0xab0055a8 ll;				\
	if r8 != r2 goto l0_%=;				\
	r1 = r6;					\
	w1 *= 2;					\
	r2 = 0xaaccef10 ll;				\
	if r1 != r2 goto l0_%=;				\
	r2 = r6;					\
	r2 *= 7;					\
	r3 = 0x77ef66de55cd44b8 ll;			\
	if r2 != r3 goto l0_%=;				\
	r0 = 0;						\
	exit;						\
l0_%=:							\
	r0 = 1;						\
	exit;						\
"	:
	: __imm_addr(vals)
	: __clobber_all);
}

SEC("socket")
__description("division by constants")
__arch_x86_64
__jited("...")
__jited("	movabsq	$0x624dd2f1a9fbe77, %r11")
__jited("	mulq	%r11")
__jited("	movq	%rdi, %rax")
__jited("	subq	%rdx, %rax")
__jited("	shrq	%rax")
__jited("	addq	%rdx, %rax")
__jited("	shrq	$0x9, %rax")
__jited("	movq	%rax, %rdi")
__jited("...")
__jited("	movabsq	$0x4924924924924925, %r11")
__jited("	imulq	%r11")
__jited("	sarq	%rdx")
__jited("	movq	%rdx, %rax")
__jited("	shrq	$0x3f, %rax")
__jited("	addq	%rax, %rdx")
__jited("	movq	%rdx, %rax")
__jited("...")
__jited("	movl	%r13d, %eax")
__jited("	movl	$0x24924925, %r11d")
__jited("	imulq	%r11, %rax")
__jited("	shrq	$0x20, %rax")
__jited("	movl	%r13d, %edx")
__jited("	subl	%eax, %edx")
__jited("	shrl	%edx")
__jited("	addl	%eax, %edx")
__jited("	shrl	$0x2, %edx")
__jited("	movl	%edx, %r13d")
__jited("...")
__jited("	movq	%rdx, %r10")
__jited("	movq	%rdx, %rax")
__jited("	movabsq	$-0x3333333333333333, %r11")
__jited("	mulq	%r11")
__jited("	shrq	$0x3, %rdx")
__jited("	imulq	$0xa, %rdx, %rdx")
__jited("	subq	%rdx, %r10")
__jited("	movq	%r10, %rdx")
__arch_arm64 __arch_riscv64 __arch_s390x __arch_loongarch
__success __retval(0)
__naked void div_const(void)
{
	asm volatile ("					\
	r6 = %[vals] ll;				\
	r6 = *(u64 *)(r6 + 0);				\
	r1 = r6;					\
	r1 /= 1000;					\
	r2 = 0x462de0534951c ll;				\
	if r1 != r2 goto l0_%=;				\
	r0 = r6;					\
	r0 s/= 7;					\
	r2 = 0x272999c0c3335a5 ll;			\
	if r0 != r2 goto l0_%=;				\
	r7 = r6;					\
	w7 /= 7;					\
	if r7 != 0xc3335a5 goto l0_%=;			\
	r3 = r6;					\
	r3 %%= 10;					\
	if r3 != 2 goto l0_%=;				\
	r0 = 0;						\
	exit;						\
l0_%=:							\
	r0 = 1;						\
	exit;						\
"	:
	: __imm_addr(vals)
	: __clobber_all);
}

void tail_call_target(void);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__array(values, void (void));
} jmp_table SEC(".maps") = {
	.values = {
		[0] = (void *)&tail_call_target,
	},
};

SEC("tc")
__auxiliary
__naked void tail_call_target(void)
{
	asm volatile ("r0 = 0; exit;");
}

__noinline __auxiliary
static __naked int tail_call_sub(void)
{
	asm volatile ("					\
	*(u64 *)(r10 - 128) = r1;			\
	r2 = %[jmp_table] ll;				\
	r3 = 0;						\
	call 12;					\
	exit;						\
"	:
	: __imm_addr(jmp_table)
	: __clobber_all);
}

/*
 * With 128 bytes of stack in both programs the stack adjustments take
 * the imm32 form and the tail call counter pointer at rbp[-144] a 32-bit
 * displacement.
 */
SEC("tc")
__description("tail call with a deep stack")
__arch_x86_64
__jited("...")
__jited("	subq	$0x80, %rsp")
__jited("	cmpq	$0x21, %rax")
__jited("	ja	L0")
__jited("	pushq	%rax")
__jited("	movq	%rsp, %rax")
__jited("	jmp	L1")
__jited("L0:	pushq	%rax")
__jited("L1:	pushq	%rax")
__jited("	movq	%rdi, -0x80(%rbp)")
__jited("	movq	-0x90(%rbp), %rax")
__jited("	callq	0x{{.*}}")
__jited("	xorl	%eax, %eax")
__jited("	leave")
__jited("	{{(retq|jmp	0x)}}")
__jited("...")
__jited("	subq	$0x80, %rsp")
__jited("	pushq	%rax")
__jited("	pushq	%rax")
__jited("	movq	%rdi, -0x80(%rbp)")
__jited("	movabsq	${{.*}}, %rsi")
__jited("	xorl	%edx, %edx")
__jited("	movq	-0x90(%rbp), %rax")
__jited("	cmpq	$0x21, (%rax)")
__jited("	jae	L0")
__jited("	nopl	(%rax,%rax)")
__jited("	addq	$0x1, (%rax)")
__jited("	popq	%rax")
__jited("	popq	%rax")
__jited("	addq	$0x80, %rsp")
__jited("	jmp	{{.*}}")
__jited("L0:	leave")
__jited("	{{(retq|jmp	0x)}}")
__arch_arm64 __arch_riscv64 __arch_s390x __arch_loongarch
__success
__naked int tail_call_deep(void)
{
	asm volatile ("					\
	*(u64 *)(r10 - 128) = r1;			\
	call %[tail_call_sub];				\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(tail_call_sub)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
