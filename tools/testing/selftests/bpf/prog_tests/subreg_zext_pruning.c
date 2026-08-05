// SPDX-License-Identifier: GPL-2.0
#include "test_progs.h"
#include "subreg_zext_pruning.skel.h"

/*
 * The program returns the upper half of a register defined by a 32-bit write
 * on a pruned path, which has to be zero. Under BPF_F_TEST_RND_HI32 a
 * definition whose zero extension was not marked returns random bits instead.
 *
 * Which path runs is decided by bpf_get_prandom_u32(), so a single run only
 * catches the bug about half the time. Run it often enough that it does not.
 */
#define RUNS 512

void test_subreg_zext_pruning(void)
{
	struct subreg_zext_pruning *skel;
	char data_in[64] = {};
	int err, i, prog_fd;
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = data_in,
		.data_size_in = sizeof(data_in),
		.repeat = 1,
	);

	skel = subreg_zext_pruning__open();
	if (!ASSERT_OK_PTR(skel, "subreg_zext_pruning open"))
		return;

	bpf_program__set_flags(skel->progs.subreg_def_survives_pruning,
			       BPF_F_TEST_RND_HI32);

	err = subreg_zext_pruning__load(skel);
	if (!ASSERT_OK(err, "subreg_zext_pruning load"))
		goto out;

	prog_fd = bpf_program__fd(skel->progs.subreg_def_survives_pruning);
	for (i = 0; i < RUNS; i++) {
		err = bpf_prog_test_run_opts(prog_fd, &topts);
		if (!ASSERT_OK(err, "test_run"))
			goto out;
		if (!ASSERT_EQ(topts.retval, 0, "upper half of r6"))
			goto out;
	}
out:
	subreg_zext_pruning__destroy(skel);
}
