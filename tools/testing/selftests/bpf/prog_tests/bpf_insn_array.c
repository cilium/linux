// SPDX-License-Identifier: GPL-2.0

#include <bpf/bpf.h>
#include <test_progs.h>

#if defined(__x86_64__) || defined(__powerpc__) || defined(__aarch64__)
static int map_create(__u32 map_type, __u32 max_entries)
{
	const char *map_name = "insn_array";
	__u32 key_size = 4;
	__u32 value_size = sizeof(struct bpf_insn_array_value);

	return bpf_map_create(map_type, map_name, key_size, value_size, max_entries, NULL);
}

static int prog_load(struct bpf_insn *insns, __u32 insn_cnt, int *fd_array, __u32 fd_array_cnt)
{
	LIBBPF_OPTS(bpf_prog_load_opts, opts);

	opts.fd_array = fd_array;
	opts.fd_array_cnt = fd_array_cnt;

	return bpf_prog_load(BPF_PROG_TYPE_XDP, NULL, "GPL", insns, insn_cnt, &opts);
}

static void __check_success(struct bpf_insn *insns, __u32 insn_cnt, __u32 *map_in, __u32 *map_out)
{
	struct bpf_insn_array_value val = {};
	int prog_fd = -1, map_fd, i;

	map_fd = map_create(BPF_MAP_TYPE_INSN_ARRAY, insn_cnt);
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return;

	for (i = 0; i < insn_cnt; i++) {
		val.orig_off = map_in[i];
		if (!ASSERT_EQ(bpf_map_update_elem(map_fd, &i, &val, 0), 0, "bpf_map_update_elem"))
			goto cleanup;
	}

	if (!ASSERT_EQ(bpf_map_freeze(map_fd), 0, "bpf_map_freeze"))
		goto cleanup;

	prog_fd = prog_load(insns, insn_cnt, &map_fd, 1);
	if (!ASSERT_GE(prog_fd, 0, "bpf(BPF_PROG_LOAD)"))
		goto cleanup;

	for (i = 0; i < insn_cnt; i++) {
		char buf[64];

		if (!ASSERT_EQ(bpf_map_lookup_elem(map_fd, &i, &val), 0, "bpf_map_lookup_elem"))
			goto cleanup;

		snprintf(buf, sizeof(buf), "val.xlated_off should be equal map_out[%d]", i);
		ASSERT_EQ(val.xlated_off, map_out[i], buf);
	}

cleanup:
	close(prog_fd);
	close(map_fd);
}

/*
 * Load a program, which will not be anyhow mangled by the verifier.  Add an
 * insn_array map pointing to every instruction. Check that it hasn't changed
 * after the program load.
 */
static void check_one_to_one_mapping(void)
{
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 4),
		BPF_MOV64_IMM(BPF_REG_0, 3),
		BPF_MOV64_IMM(BPF_REG_0, 2),
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	__u32 map_in[] = {0, 1, 2, 3, 4, 5};
	__u32 map_out[] = {0, 1, 2, 3, 4, 5};

	__check_success(insns, ARRAY_SIZE(insns), map_in, map_out);
}

/*
 * Load a program with two patches (get jiffies, for simplicity). Add an
 * insn_array map pointing to every instruction. Check how it was changed
 * after the program load.
 */
static void check_simple(void)
{
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 2),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_jiffies64),
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_jiffies64),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	__u32 map_in[] = {0, 1, 2, 3, 4, 5};
	__u32 map_out[] = {0, 1, 4, 5, 8, 9};

	__check_success(insns, ARRAY_SIZE(insns), map_in, map_out);
}

/*
 * Verifier can delete code in two cases: nops & dead code. From insn
 * array's point of view, the two cases are the same, so test using
 * the simplest method: by loading some nops
 */
static void check_deletions(void)
{
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 2),
		BPF_JMP_IMM(BPF_JA, 0, 0, 0), /* nop */
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_JMP_IMM(BPF_JA, 0, 0, 0), /* nop */
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	__u32 map_in[] = {0, 1, 2, 3, 4, 5};
	__u32 map_out[] = {0, -1, 1, -1, 2, 3};

	__check_success(insns, ARRAY_SIZE(insns), map_in, map_out);
}

/*
 * Same test as check_deletions, but also add code which adds instructions
 */
static void check_deletions_with_functions(void)
{
	struct bpf_insn insns[] = {
		BPF_JMP_IMM(BPF_JA, 0, 0, 0), /* nop */
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_jiffies64),
		BPF_JMP_IMM(BPF_JA, 0, 0, 0), /* nop */
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 1, 0, 2),
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_EXIT_INSN(),
		BPF_JMP_IMM(BPF_JA, 0, 0, 0), /* nop */
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_jiffies64),
		BPF_JMP_IMM(BPF_JA, 0, 0, 0), /* nop */
		BPF_MOV64_IMM(BPF_REG_0, 2),
		BPF_EXIT_INSN(),
	};
	__u32 map_in[] =  { 0, 1,  2, 3, 4, 5, /* func */  6, 7,  8, 9, 10};
	__u32 map_out[] = {-1, 0, -1, 3, 4, 5, /* func */ -1, 6, -1, 9, 10};

	__check_success(insns, ARRAY_SIZE(insns), map_in, map_out);
}

/*
 * Try to load a program with a map which points to outside of the program
 */
static void check_out_of_bounds_index(void)
{
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 4),
		BPF_MOV64_IMM(BPF_REG_0, 3),
		BPF_MOV64_IMM(BPF_REG_0, 2),
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	int prog_fd, map_fd;
	struct bpf_insn_array_value val = {};
	int key;

	map_fd = map_create(BPF_MAP_TYPE_INSN_ARRAY, 1);
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return;

	key = 0;
	val.orig_off = ARRAY_SIZE(insns); /* too big */
	if (!ASSERT_EQ(bpf_map_update_elem(map_fd, &key, &val, 0), 0, "bpf_map_update_elem"))
		goto cleanup;

	if (!ASSERT_EQ(bpf_map_freeze(map_fd), 0, "bpf_map_freeze"))
		goto cleanup;

	prog_fd = prog_load(insns, ARRAY_SIZE(insns), &map_fd, 1);
	if (!ASSERT_EQ(prog_fd, -EINVAL, "program should have been rejected (prog_fd != -EINVAL)")) {
		close(prog_fd);
		goto cleanup;
	}

cleanup:
	close(map_fd);
}

/*
 * Try to load a program with a map which points to the middle of 16-bit insn
 */
static void check_mid_insn_index(void)
{
	struct bpf_insn insns[] = {
		BPF_LD_IMM64(BPF_REG_0, 0), /* 2 x 8 */
		BPF_EXIT_INSN(),
	};
	int prog_fd, map_fd;
	struct bpf_insn_array_value val = {};
	int key;

	map_fd = map_create(BPF_MAP_TYPE_INSN_ARRAY, 1);
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return;

	key = 0;
	val.orig_off = 1; /* middle of 16-byte instruction */
	if (!ASSERT_EQ(bpf_map_update_elem(map_fd, &key, &val, 0), 0, "bpf_map_update_elem"))
		goto cleanup;

	if (!ASSERT_EQ(bpf_map_freeze(map_fd), 0, "bpf_map_freeze"))
		goto cleanup;

	prog_fd = prog_load(insns, ARRAY_SIZE(insns), &map_fd, 1);
	if (!ASSERT_EQ(prog_fd, -EINVAL, "program should have been rejected (prog_fd != -EINVAL)")) {
		close(prog_fd);
		goto cleanup;
	}

cleanup:
	close(map_fd);
}

static void check_incorrect_index(void)
{
	check_out_of_bounds_index();
	check_mid_insn_index();
}

static int set_bpf_jit_harden(char *level)
{
	char old_level;
	int err = -1;
	int fd = -1;

	fd = open("/proc/sys/net/core/bpf_jit_harden", O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		ASSERT_FAIL("open .../bpf_jit_harden returned %d (errno=%d)", fd, errno);
		return -1;
	}

	err = read(fd, &old_level, 1);
	if (err != 1) {
		ASSERT_FAIL("read from .../bpf_jit_harden returned %d (errno=%d)", err, errno);
		err = -1;
		goto end;
	}

	lseek(fd, 0, SEEK_SET);

	err = write(fd, level, 1);
	if (err != 1) {
		ASSERT_FAIL("write to .../bpf_jit_harden returned %d (errno=%d)", err, errno);
		err = -1;
		goto end;
	}

	err = 0;
	*level = old_level;
end:
	if (fd >= 0)
		close(fd);
	return err;
}

static void check_blindness(void)
{
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 4),
		BPF_MOV64_IMM(BPF_REG_0, 3),
		BPF_MOV64_IMM(BPF_REG_0, 2),
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_EXIT_INSN(),
	};
	int prog_fd = -1, map_fd;
	struct bpf_insn_array_value val = {};
	char bpf_jit_harden = '@'; /* non-exizsting value */
	int i;

	map_fd = map_create(BPF_MAP_TYPE_INSN_ARRAY, ARRAY_SIZE(insns));
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return;

	for (i = 0; i < ARRAY_SIZE(insns); i++) {
		val.orig_off = i;
		if (!ASSERT_EQ(bpf_map_update_elem(map_fd, &i, &val, 0), 0, "bpf_map_update_elem"))
			goto cleanup;
	}

	if (!ASSERT_EQ(bpf_map_freeze(map_fd), 0, "bpf_map_freeze"))
		goto cleanup;

	bpf_jit_harden = '2';
	if (set_bpf_jit_harden(&bpf_jit_harden)) {
		bpf_jit_harden = '@'; /* open, read or write failed => no write was done */
		goto cleanup;
	}

	prog_fd = prog_load(insns, ARRAY_SIZE(insns), &map_fd, 1);
	if (!ASSERT_GE(prog_fd, 0, "bpf(BPF_PROG_LOAD)"))
		goto cleanup;

	for (i = 0; i < ARRAY_SIZE(insns); i++) {
		char fmt[32];

		if (!ASSERT_EQ(bpf_map_lookup_elem(map_fd, &i, &val), 0, "bpf_map_lookup_elem"))
			goto cleanup;

		snprintf(fmt, sizeof(fmt), "val should be equal 3*%d", i);
		ASSERT_EQ(val.xlated_off, i * 3, fmt);
	}

cleanup:
	/* restore the old one */
	if (bpf_jit_harden != '@')
		set_bpf_jit_harden(&bpf_jit_harden);

	close(prog_fd);
	close(map_fd);
}

/* Once map was initialized, it should be frozen */
static void check_load_unfrozen_map(void)
{
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	int prog_fd = -1, map_fd;
	struct bpf_insn_array_value val = {};
	int i;

	map_fd = map_create(BPF_MAP_TYPE_INSN_ARRAY, ARRAY_SIZE(insns));
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return;

	for (i = 0; i < ARRAY_SIZE(insns); i++) {
		val.orig_off = i;
		if (!ASSERT_EQ(bpf_map_update_elem(map_fd, &i, &val, 0), 0, "bpf_map_update_elem"))
			goto cleanup;
	}

	prog_fd = prog_load(insns, ARRAY_SIZE(insns), &map_fd, 1);
	if (!ASSERT_EQ(prog_fd, -EINVAL, "program should have been rejected (prog_fd != -EINVAL)"))
		goto cleanup;

	/* correctness: now freeze the map, the program should load fine */

	if (!ASSERT_EQ(bpf_map_freeze(map_fd), 0, "bpf_map_freeze"))
		goto cleanup;

	prog_fd = prog_load(insns, ARRAY_SIZE(insns), &map_fd, 1);
	if (!ASSERT_GE(prog_fd, 0, "bpf(BPF_PROG_LOAD)"))
		goto cleanup;

	for (i = 0; i < ARRAY_SIZE(insns); i++) {
		if (!ASSERT_EQ(bpf_map_lookup_elem(map_fd, &i, &val), 0, "bpf_map_lookup_elem"))
			goto cleanup;

		ASSERT_EQ(val.xlated_off, i, "val should be equal i");
	}

cleanup:
	close(prog_fd);
	close(map_fd);
}

/* Map can be used only by one BPF program */
static void check_no_map_reuse(void)
{
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	int prog_fd = -1, map_fd, extra_fd = -1;
	struct bpf_insn_array_value val = {};
	int i;

	map_fd = map_create(BPF_MAP_TYPE_INSN_ARRAY, ARRAY_SIZE(insns));
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return;

	for (i = 0; i < ARRAY_SIZE(insns); i++) {
		val.orig_off = i;
		if (!ASSERT_EQ(bpf_map_update_elem(map_fd, &i, &val, 0), 0, "bpf_map_update_elem"))
			goto cleanup;
	}

	if (!ASSERT_EQ(bpf_map_freeze(map_fd), 0, "bpf_map_freeze"))
		goto cleanup;

	prog_fd = prog_load(insns, ARRAY_SIZE(insns), &map_fd, 1);
	if (!ASSERT_GE(prog_fd, 0, "bpf(BPF_PROG_LOAD)"))
		goto cleanup;

	for (i = 0; i < ARRAY_SIZE(insns); i++) {
		if (!ASSERT_EQ(bpf_map_lookup_elem(map_fd, &i, &val), 0, "bpf_map_lookup_elem"))
			goto cleanup;

		ASSERT_EQ(val.xlated_off, i, "val should be equal i");
	}

	extra_fd = prog_load(insns, ARRAY_SIZE(insns), &map_fd, 1);
	if (!ASSERT_EQ(extra_fd, -EBUSY, "program should have been rejected (extra_fd != -EBUSY)"))
		goto cleanup;

	/* correctness: check that prog is still loadable without fd_array */
	extra_fd = prog_load(insns, ARRAY_SIZE(insns), NULL, 0);
	if (!ASSERT_GE(extra_fd, 0, "bpf(BPF_PROG_LOAD): expected no error"))
		goto cleanup;

cleanup:
	close(extra_fd);
	close(prog_fd);
	close(map_fd);
}

static void check_bpf_no_lookup(void)
{
	struct bpf_insn insns[] = {
		BPF_LD_MAP_FD(BPF_REG_1, 0),
		BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
		BPF_EXIT_INSN(),
	};
	int prog_fd = -1, map_fd;

	map_fd = map_create(BPF_MAP_TYPE_INSN_ARRAY, 1);
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return;

	insns[0].imm = map_fd;

	if (!ASSERT_EQ(bpf_map_freeze(map_fd), 0, "bpf_map_freeze"))
		goto cleanup;

	prog_fd = prog_load(insns, ARRAY_SIZE(insns), NULL, 0);
	if (!ASSERT_EQ(prog_fd, -EINVAL, "program should have been rejected (prog_fd != -EINVAL)"))
		goto cleanup;

	/* correctness: check that prog is still loadable with normal map */
	close(map_fd);
	map_fd = map_create(BPF_MAP_TYPE_ARRAY, 1);
	insns[0].imm = map_fd;
	prog_fd = prog_load(insns, ARRAY_SIZE(insns), NULL, 0);
	if (!ASSERT_GE(prog_fd, 0, "bpf(BPF_PROG_LOAD)"))
		goto cleanup;

cleanup:
	close(prog_fd);
	close(map_fd);
}

/*
 * A gotox instruction has one CFG successor per distinct jump table target,
 * and every gotox in a subprogram gets its own copy of that table, so the
 * number of edges is the count of gotox instructions times the number of
 * distinct targets. check_cfg(), bpf_compute_postorder(), bpf_compute_scc()
 * and the liveness computation each walk all of them, hence the limit on the
 * total.
 *
 * Note jt_from_map() collects unique offsets, so a large jump table of
 * repeated targets costs nothing: what has to grow is the distinct count.
 * The programs below get that by making the gotox instructions their own
 * jump table targets, which also keeps every one of them reachable, so the
 * edge count is quadratic in a program only a few instructions longer than
 * the gotox run.
 *
 * The limit is BPF_COMPLEXITY_LIMIT_INSNS and is a property of the whole
 * program, not of one jump table, one gotox or one subprogram.
 */
#define GOTOX_EDGE_LIMIT	1000000
#define GOTOX_LOG_SZ		(256 * 1024)

static const char gotox_limit_msg[] =
	"number of indirect jump targets in the program exceeds";

static struct bpf_insn gotox_insn(void)
{
	return (struct bpf_insn)BPF_RAW_INSN(BPF_JMP | BPF_JA | BPF_X,
					     BPF_REG_1, 0, 0, 0);
}

/*
 * A frozen insn_array whose entries are the 'gotox_cnt' gotox instructions
 * starting at 'first_gotox', plus the instruction just past them when
 * 'target_exit' is set. Every entry is distinct, so the table contributes
 * gotox_cnt (+1) successors to each gotox that uses it.
 */
static int gotox_jt_create(__u32 first_gotox, __u32 gotox_cnt, bool target_exit)
{
	const __u32 jt_cnt = gotox_cnt + (target_exit ? 1 : 0);
	struct bpf_insn_array_value val = {};
	int map_fd;
	__u32 i;

	map_fd = map_create(BPF_MAP_TYPE_INSN_ARRAY, jt_cnt);
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return map_fd;

	for (i = 0; i < jt_cnt; i++) {
		val.orig_off = first_gotox + i;
		if (!ASSERT_EQ(bpf_map_update_elem(map_fd, &i, &val, 0), 0,
			       "bpf_map_update_elem"))
			goto err;
	}

	if (!ASSERT_EQ(bpf_map_freeze(map_fd), 0, "bpf_map_freeze"))
		goto err;

	return map_fd;
err:
	close(map_fd);
	return -1;
}

static int gotox_prog_load(struct bpf_insn *insns, __u32 insn_cnt,
			   int *fd_array, __u32 fd_array_cnt, char *log)
{
	LIBBPF_OPTS(bpf_prog_load_opts, opts);
	int prog_fd;

	log[0] = 0;
	opts.fd_array = fd_array;
	opts.fd_array_cnt = fd_array_cnt;
	opts.log_buf = log;
	opts.log_size = GOTOX_LOG_SZ;
	opts.log_level = 1;

	prog_fd = bpf_prog_load(BPF_PROG_TYPE_XDP, NULL, "GPL", insns, insn_cnt, &opts);
	if (prog_fd >= 0) {
		close(prog_fd);
		return 0;
	}
	return prog_fd;
}

/* Fill in 'r1 = 0; gotox_cnt x gotox r1' at 'insns'. */
static void gotox_run_fill(struct bpf_insn *insns, __u32 gotox_cnt)
{
	__u32 i;

	insns[0] = (struct bpf_insn)BPF_MOV64_IMM(BPF_REG_1, 0);
	for (i = 1; i <= gotox_cnt; i++)
		insns[i] = gotox_insn();
}

static void check_gotox_limit_hit(const char *log, int err, bool expect_hit)
{
	if (expect_hit) {
		ASSERT_EQ(err, -E2BIG, "program should have been rejected");
		/*
		 * Check the message too: the DFS in the same file returns
		 * -E2BIG on a stack overrun as well, so the errno alone does
		 * not say which limit was hit.
		 */
		ASSERT_HAS_SUBSTR(log, gotox_limit_msg, "verifier log");
		return;
	}

	ASSERT_NEQ(err, -E2BIG, "program should not have hit a limit");
	if (!ASSERT_FALSE(strstr(log, gotox_limit_msg),
			  "indirect jump target limit hit"))
		fprintf(stderr, "verifier log: %s\n", log);
}

/*
 * One subprogram of 'gotox_cnt' gotox instructions, each with a jump table of
 * the gotox themselves and, if 'target_exit', the instruction after them:
 * gotox_cnt * (gotox_cnt + 1) or gotox_cnt * gotox_cnt edges in gotox_cnt + 3
 * instructions.
 *
 * Returns false if the setup failed, otherwise true with the load result in
 * 'err' and the verifier log in 'log'.
 */
static bool load_gotox_prog(__u32 gotox_cnt, bool target_exit, char *log, int *err)
{
	const __u32 insn_cnt = gotox_cnt + 3;
	int map_fd, ret = -1;
	struct bpf_insn *insns;

	insns = calloc(insn_cnt, sizeof(*insns));
	if (!ASSERT_OK_PTR(insns, "calloc insns"))
		return false;

	gotox_run_fill(insns, gotox_cnt);
	insns[gotox_cnt + 1] = (struct bpf_insn)BPF_MOV64_IMM(BPF_REG_0, 0);
	insns[gotox_cnt + 2] = (struct bpf_insn)BPF_EXIT_INSN();

	map_fd = gotox_jt_create(1, gotox_cnt, target_exit);
	if (map_fd < 0)
		goto free_insns;

	ret = gotox_prog_load(insns, insn_cnt, &map_fd, 1, log);
	close(map_fd);
free_insns:
	free(insns);
	if (ret != -1)
		*err = ret;
	return ret != -1;
}

/*
 * 1000 gotox over a table of the 1000 gotox plus the exit path is 1001000
 * edges, 1000 past the limit, so the program has to be rejected rather than
 * walked four times over.
 */
static void check_too_many_gotox_edges(void)
{
	char *log;
	int err;

	log = malloc(GOTOX_LOG_SZ);
	if (!ASSERT_OK_PTR(log, "malloc log"))
		return;

	if (load_gotox_prog(1000, true, log, &err))
		check_gotox_limit_hit(log, err, true);

	free(log);
}

/*
 * Dropping the exit path from the table leaves exactly 1000000 edges, which
 * is still allowed: the check rejects above the limit, not at it. The program
 * is refused later on anyway, since nothing reaches the exit, so this checks
 * that the limit did not fire rather than that the load succeeds. Without it
 * nothing would catch the limit becoming too tight by an off-by-one or by
 * counting an edge more than once.
 */
static void check_gotox_edges_at_limit(void)
{
	char *log;
	int err;

	log = malloc(GOTOX_LOG_SZ);
	if (!ASSERT_OK_PTR(log, "malloc log"))
		return;

	if (load_gotox_prog(1000, false, log, &err))
		check_gotox_limit_hit(log, err, false);

	free(log);
}

/*
 * The limit is a property of the program, so two subprograms that each stay
 * under it on their own still have to be rejected together. Each one gets its
 * own jump table, since jt_from_subprog() picks the maps whose targets fall
 * inside the subprogram.
 */
static void check_gotox_edges_across_subprogs(void)
{
	const __u32 gotox_cnt = 750;
	const __u32 sub_start = gotox_cnt + 3;
	const __u32 insn_cnt = 2 * (gotox_cnt + 3);
	const __u32 edges = gotox_cnt * (gotox_cnt + 1);
	int map_fd[2] = { -1, -1 };
	struct bpf_insn *insns;
	char *log;
	int err;

	/* Each half is 563250 edges, together 1126500, i.e. over the limit. */
	if (!ASSERT_LT(edges, GOTOX_EDGE_LIMIT, "one subprog under limit"))
		return;
	if (!ASSERT_GT(2 * edges, GOTOX_EDGE_LIMIT, "both subprogs over limit"))
		return;

	log = malloc(GOTOX_LOG_SZ);
	if (!ASSERT_OK_PTR(log, "malloc log"))
		return;

	insns = calloc(insn_cnt, sizeof(*insns));
	if (!ASSERT_OK_PTR(insns, "calloc insns"))
		goto free_log;

	/*
	 * main: r1 = 0; gotox_cnt x gotox r1; call sub; exit
	 * sub:  r1 = 0; gotox_cnt x gotox r1; r0 = 0; exit
	 */
	gotox_run_fill(insns, gotox_cnt);
	insns[gotox_cnt + 1] = (struct bpf_insn)BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0,
							     BPF_PSEUDO_CALL, 0,
							     sub_start - (gotox_cnt + 1) - 1);
	insns[gotox_cnt + 2] = (struct bpf_insn)BPF_EXIT_INSN();

	gotox_run_fill(insns + sub_start, gotox_cnt);
	insns[sub_start + gotox_cnt + 1] = (struct bpf_insn)BPF_MOV64_IMM(BPF_REG_0, 0);
	insns[sub_start + gotox_cnt + 2] = (struct bpf_insn)BPF_EXIT_INSN();

	map_fd[0] = gotox_jt_create(1, gotox_cnt, true);
	if (map_fd[0] < 0)
		goto free_insns;
	map_fd[1] = gotox_jt_create(sub_start + 1, gotox_cnt, true);
	if (map_fd[1] < 0)
		goto close_maps;

	err = gotox_prog_load(insns, insn_cnt, map_fd, 2, log);
	check_gotox_limit_hit(log, err, true);

close_maps:
	close(map_fd[0]);
	close(map_fd[1]);
free_insns:
	free(insns);
free_log:
	free(log);
}

static void check_bpf_side(void)
{
	check_bpf_no_lookup();
}

static void __test_bpf_insn_array(void)
{
	/* Test if offsets are adjusted properly */

	if (test__start_subtest("one2one"))
		check_one_to_one_mapping();

	if (test__start_subtest("simple"))
		check_simple();

	if (test__start_subtest("deletions"))
		check_deletions();

	if (test__start_subtest("deletions-with-functions"))
		check_deletions_with_functions();

	if (test__start_subtest("blindness"))
		check_blindness();

	/* Check all kinds of operations and related restrictions */

	if (test__start_subtest("incorrect-index"))
		check_incorrect_index();

	if (test__start_subtest("load-unfrozen-map"))
		check_load_unfrozen_map();

	if (test__start_subtest("no-map-reuse"))
		check_no_map_reuse();

	if (test__start_subtest("bpf-side-ops"))
		check_bpf_side();

	if (test__start_subtest("too-many-gotox-edges"))
		check_too_many_gotox_edges();

	if (test__start_subtest("gotox-edges-at-limit"))
		check_gotox_edges_at_limit();

	if (test__start_subtest("gotox-edges-across-subprogs"))
		check_gotox_edges_across_subprogs();
}
#else
static void __test_bpf_insn_array(void)
{
	test__skip();
}
#endif

void test_bpf_insn_array(void)
{
	__test_bpf_insn_array();
}
