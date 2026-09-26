// SPDX-License-Identifier: GPL-2.0
/*
 * Division and modulo by constants for every width, signedness and
 * destination register with a set of divisors and dividends around the
 * multiple boundaries and the extremes of each range. This covers a JIT
 * replacing the division with a multiplication by a magic number in all
 * of its forms: magic numbers needing the extra add step, zero shifts,
 * both signed corrections, and the divisors like 1, -1 and the ones
 * above 2^63 that are still emitted as a real division. The dividends
 * of the 32-bit operations carry garbage in the upper 32 bits.
 */
#include <test_progs.h>
#include <linux/filter.h>

struct div_ctx {
	__u64 n;
	__u64 res;
};

static const __s32 unsigned_divisors[] = {
	2, 3, 7, 10, 25, 641, 1000, 4096, 65536, 1000000007, 0x7fffffff,
	-2, -10, -0x7fffffff - 1, -1, 1,
};

static const __s32 signed_divisors[] = {
	2, 3, 7, 25, 1000, 0x40000000, 0x7fffffff,
	-2, -3, -5, -7, -1000, -0x7fffffff, -0x7fffffff - 1, 1, -1,
};

static char log[4096];

/* r6 holds the ctx */
static const int dst_regs[] = {
	BPF_REG_0, BPF_REG_1, BPF_REG_2, BPF_REG_3, BPF_REG_4,
	BPF_REG_5, BPF_REG_7, BPF_REG_8, BPF_REG_9,
};

static __u64 expected(bool is64, bool is_signed, bool is_mod, __s32 imm, __u64 n)
{
	__u64 d64 = (__s64)imm;
	__u32 n32 = n, d32 = imm;
	__s64 sn64 = n;
	__s32 sn32 = n;

	if (!is_signed)
		return is64 ? (is_mod ? n % d64 : n / d64) :
			      (is_mod ? n32 % d32 : n32 / d32);
	/* LLONG_MIN / -1 == LLONG_MIN, LLONG_MIN % -1 == 0, same for INT_MIN */
	if (imm == -1)
		return is_mod ? 0 : (is64 ? 0 - n : (__u32)(0 - n32));
	return is64 ? (is_mod ? sn64 % imm : sn64 / imm) :
		      (__u32)(is_mod ? sn32 % imm : sn32 / imm);
}

static int dividends(bool is64, bool is_signed, __s32 imm, __u64 *n)
{
	__u64 d = is_signed ? (imm < 0 ? -(__s64)imm : imm) :
		  is64 ? (__u64)(__s64)imm : (__u32)imm;
	int cnt = 0, i;

	n[cnt++] = 0;
	n[cnt++] = d - 1;
	n[cnt++] = d + 1;
	n[cnt++] = 3 * d + 2;
	if (is64) {
		n[cnt++] = (d << 40) - 1;
		n[cnt++] = (d << 40) + 1;
		n[cnt++] = (1ULL << 63) - 1;
		n[cnt++] = 1ULL << 63;
		n[cnt++] = ~0ULL;
		n[cnt++] = 0xdaeb8ebd244a330cULL;
	} else {
		n[cnt++] = (d << 16) - 1;
		n[cnt++] = (d << 16) + 1;
		n[cnt++] = (1ULL << 31) - 1;
		n[cnt++] = 1ULL << 31;
		n[cnt++] = ~0U;
		n[cnt++] = 0x8c1e86f1;
	}
	if (is_signed) {
		n[cnt++] = -1;
		n[cnt++] = -d - 1;
		n[cnt++] = -3 * d - 2;
		n[cnt++] = is64 ? -(1ULL << 63) + 1 : -(1ULL << 31) + 1;
	}
	if (!is64)
		for (i = 0; i < cnt; i++)
			n[i] = (__u32)n[i] | ((0xa5a50000ULL + i) << 32);
	return cnt;
}

static void run_divisor(bool is64, bool is_signed, bool is_mod, __s32 imm)
{
	LIBBPF_OPTS(bpf_prog_load_opts, lopts,
		.prog_flags = BPF_F_SLEEPABLE,
		.log_buf = log,
		.log_size = sizeof(log),
	);
	int fd, i, j, err, cnt;
	__u64 n[16];
	char buf[80];

	for (i = 0; i < ARRAY_SIZE(dst_regs); i++) {
		int dst = dst_regs[i];
		struct bpf_insn insns[] = {
			BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
			BPF_LDX_MEM(BPF_DW, dst, BPF_REG_6, offsetof(struct div_ctx, n)),
			BPF_RAW_INSN((is64 ? BPF_ALU64 : BPF_ALU) |
				     (is_mod ? BPF_MOD : BPF_DIV) | BPF_K,
				     dst, 0, is_signed, imm),
			BPF_STX_MEM(BPF_DW, BPF_REG_6, dst, offsetof(struct div_ctx, res)),
			BPF_MOV64_IMM(BPF_REG_0, 0),
			BPF_EXIT_INSN(),
		};

		fd = bpf_prog_load(BPF_PROG_TYPE_SYSCALL, NULL, "GPL", insns,
				   ARRAY_SIZE(insns), &lopts);
		snprintf(buf, sizeof(buf), "load imm=%d dst=r%d", imm, dst);
		if (!ASSERT_GE(fd, 0, buf)) {
			fprintf(stderr, "%s", log);
			return;
		}

		cnt = dividends(is64, is_signed, imm, n);
		for (j = 0; j < cnt; j++) {
			struct div_ctx ctx = { .n = n[j] };
			LIBBPF_OPTS(bpf_test_run_opts, opts,
				.ctx_in = &ctx,
				.ctx_size_in = sizeof(ctx),
			);

			err = bpf_prog_test_run_opts(fd, &opts);
			snprintf(buf, sizeof(buf), "run 0x%llx imm=%d dst=r%d",
				 n[j], imm, dst);
			if (!ASSERT_OK(err, buf))
				break;
			ASSERT_EQ(ctx.res, expected(is64, is_signed, is_mod, imm, n[j]), buf);
		}
		close(fd);
	}
}

static void run_op(bool is64, bool is_signed, bool is_mod)
{
	const __s32 *divs = is_signed ? signed_divisors : unsigned_divisors;
	int cnt = is_signed ? ARRAY_SIZE(signed_divisors) : ARRAY_SIZE(unsigned_divisors);
	int i;

	for (i = 0; i < cnt; i++)
		run_divisor(is64, is_signed, is_mod, divs[i]);
}

void test_div_const(void)
{
	if (test__start_subtest("udiv64"))
		run_op(true, false, false);
	if (test__start_subtest("umod64"))
		run_op(true, false, true);
	if (test__start_subtest("sdiv64"))
		run_op(true, true, false);
	if (test__start_subtest("smod64"))
		run_op(true, true, true);
	if (test__start_subtest("udiv32"))
		run_op(false, false, false);
	if (test__start_subtest("umod32"))
		run_op(false, false, true);
	if (test__start_subtest("sdiv32"))
		run_op(false, true, false);
	if (test__start_subtest("smod32"))
		run_op(false, true, true);
}
