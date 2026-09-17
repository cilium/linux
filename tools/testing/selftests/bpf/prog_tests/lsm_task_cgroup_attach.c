// SPDX-License-Identifier: GPL-2.0
/*
 * task_cgroup_attach, the hook every change of a task's cgroup goes through,
 * whichever way it was asked for: a cgroup.procs or cgroup.threads write and
 * a clone3(CLONE_INTO_CGROUP) alike. The policy refuses moving anything into
 * a cgroup labelled "sealed" unless the mover's own cgroup is sealed, and
 * records the task it is handed together with its destination.
 *
 * The test process is its own mover: it stays in one cgroup and puts the
 * label on it or takes it off again, since once the policy runs it could not
 * move itself into a sealed cgroup to begin with.
 */
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <test_progs.h>
#include "cgroup_helpers.h"
#include "lsm_task_cgroup_attach.skel.h"

#define ZONE		"security.bpf.zone"
#define MOVER_CG	"/tca_mover/"
#define CHILD_CG	"/tca_child/"
#define SEALED_CG	"/tca_sealed/"
#define PLAIN_CG	"/tca_plain/"
#define DOM_CG		"/tca_dom/"
#define T_SRC_CG	DOM_CG "src/"
#define T_DST_CG	DOM_CG "dst/"

#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP 0x200000000ULL
#endif

/* The clone3 argument block, to the size that carries a cgroup. */
struct clone3_args {
	__u64 flags, pidfd, child_tid, parent_tid, exit_signal, stack;
	__u64 stack_size, tls, set_tid, set_tid_size, cgroup;
};

static int mover_fd = -1, child_fd = -1, sealed_fd = -1, plain_fd = -1;
static pid_t child = -1;

/* Write @pid into a control file of the cgroup behind @cgroup_fd: 0 or
 * -errno, so that what the policy returned is visible.
 */
static int write_pid(int cgroup_fd, const char *file, pid_t pid)
{
	char buf[16];
	int fd, n;

	fd = openat(cgroup_fd, file, O_WRONLY);
	if (fd < 0)
		return -errno;
	n = snprintf(buf, sizeof(buf), "%d", pid);
	n = write(fd, buf, n);
	close(fd);
	return n < 0 ? -errno : 0;
}

/* Whether @pid is listed in the cgroup behind @cgroup_fd. */
static bool in_cgroup(int cgroup_fd, pid_t pid)
{
	char buf[4096] = {}, want[16];
	char *line, *rest;
	int fd, n;

	fd = openat(cgroup_fd, "cgroup.procs", O_RDONLY);
	if (fd < 0)
		return false;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return false;
	snprintf(want, sizeof(want), "%d", pid);
	rest = buf;
	while ((line = strtok_r(rest, "\n", &rest)))
		if (!strcmp(line, want))
			return true;
	return false;
}

/* clone3 a child straight into the cgroup behind @cgroup_fd: 0 or -errno. */
static int clone_into(int cgroup_fd)
{
	struct clone3_args args = {
		.flags = CLONE_INTO_CGROUP,
		.exit_signal = SIGCHLD,
		.cgroup = cgroup_fd,
	};
	pid_t pid;

	pid = syscall(__NR_clone3, &args, sizeof(args));
	if (pid < 0)
		return -errno;
	if (pid == 0)
		_exit(0);
	waitpid(pid, NULL, 0);
	return 0;
}

static int seal_mover(void)
{
	return set_cgroup_xattr(MOVER_CG, ZONE, "sealed") ? -errno : 0;
}

static int unseal_mover(void)
{
	int ret = fremovexattr(mover_fd, ZONE);

	return ret && errno != ENODATA ? -errno : 0;
}

/* Nothing enters a sealed cgroup from an unsealed mover. */
static void test_procs_write_denied(struct lsm_task_cgroup_attach *skel)
{
	__u32 denied = skel->bss->denied;

	if (!ASSERT_OK(unseal_mover(), "unseal the mover"))
		return;
	ASSERT_EQ(write_pid(sealed_fd, "cgroup.procs", child), -EPERM,
		  "move into a sealed cgroup");
	ASSERT_FALSE(in_cgroup(sealed_fd, child), "the child stayed out");
	ASSERT_EQ(skel->bss->denied, denied + 1, "denied");
}

/* A mover in a sealed cgroup places tasks there. */
static void test_procs_write_allowed(struct lsm_task_cgroup_attach *skel)
{
	if (!ASSERT_OK(seal_mover(), "seal the mover"))
		return;
	ASSERT_OK(write_pid(sealed_fd, "cgroup.procs", child),
		  "move into a sealed cgroup");
	ASSERT_TRUE(in_cgroup(sealed_fd, child), "the child moved");
	ASSERT_OK(write_pid(child_fd, "cgroup.procs", child), "move it back");
}

/* A thread write reaches the same hook, within one threaded domain. */
static void test_threads_write_denied(struct lsm_task_cgroup_attach *skel)
{
	__u32 denied = skel->bss->denied;
	int src_fd, dst_fd;

	if (!ASSERT_OK(unseal_mover(), "unseal the mover"))
		return;
	src_fd = create_and_get_cgroup(T_SRC_CG);
	dst_fd = create_and_get_cgroup(T_DST_CG);
	if (!ASSERT_OK_FD(src_fd, "create the source") ||
	    !ASSERT_OK_FD(dst_fd, "create the destination"))
		goto out;
	/* Both sides have to share a threaded domain for a thread to move
	 * between them at all; the label goes on once they do.
	 */
	if (!ASSERT_OK(write_cgroup_file(T_SRC_CG, "cgroup.type", "threaded"),
		       "thread the source") ||
	    !ASSERT_OK(write_cgroup_file(T_DST_CG, "cgroup.type", "threaded"),
		       "thread the destination") ||
	    !ASSERT_OK(set_cgroup_xattr(T_DST_CG, ZONE, "sealed"), "seal it"))
		goto out;
	if (!ASSERT_OK(write_pid(src_fd, "cgroup.procs", child),
		       "park the child in the source"))
		goto out;
	ASSERT_EQ(write_pid(dst_fd, "cgroup.threads", child), -EPERM,
		  "move a thread into a sealed cgroup");
	ASSERT_FALSE(in_cgroup(dst_fd, child), "the child stayed out");
	ASSERT_EQ(skel->bss->denied, denied + 1, "denied");
	ASSERT_OK(write_pid(child_fd, "cgroup.procs", child), "move it back");
out:
	if (dst_fd >= 0)
		close(dst_fd);
	if (src_fd >= 0)
		close(src_fd);
	remove_cgroup(T_DST_CG);
	remove_cgroup(T_SRC_CG);
}

/* A fork straight into a sealed cgroup is gated the same way. */
static void test_clone3_denied(struct lsm_task_cgroup_attach *skel)
{
	__u32 denied = skel->bss->denied;

	if (!ASSERT_OK(unseal_mover(), "unseal the mover"))
		return;
	ASSERT_EQ(clone_into(sealed_fd), -EPERM, "clone3 into a sealed cgroup");
	ASSERT_EQ(skel->bss->denied, denied + 1, "denied");
}

static void test_clone3_allowed(struct lsm_task_cgroup_attach *skel)
{
	if (!ASSERT_OK(seal_mover(), "seal the mover"))
		return;
	ASSERT_OK(clone_into(sealed_fd), "clone3 into a sealed cgroup");
}

/* The hook is handed the task that moves, not the one asking, and the
 * cgroup it moves to.
 */
static void test_hook_sees_task_and_destination(struct lsm_task_cgroup_attach *skel)
{
	unsigned long long id = get_cgroup_id(SEALED_CG);

	if (!ASSERT_OK(seal_mover(), "seal the mover"))
		return;
	skel->bss->moved_pid = 0;
	skel->bss->moved_to = 0;
	if (!ASSERT_OK(write_pid(sealed_fd, "cgroup.procs", child),
		       "move into a sealed cgroup"))
		return;
	ASSERT_EQ(skel->bss->moved_pid, child, "the moved task");
	ASSERT_EQ(skel->bss->moved_to, id, "the destination cgroup");
	ASSERT_NEQ(skel->bss->moved_pid, getpid(), "not the mover");
	ASSERT_OK(write_pid(child_fd, "cgroup.procs", child), "move it back");
}

/* Only the destination is gated, so leaving a sealed cgroup is allowed
 * even from a mover that could not move anything into one.
 */
static void test_move_out_allowed(struct lsm_task_cgroup_attach *skel)
{
	if (!ASSERT_OK(seal_mover(), "seal the mover"))
		return;
	if (!ASSERT_OK(write_pid(sealed_fd, "cgroup.procs", child),
		       "move into a sealed cgroup"))
		return;
	if (!ASSERT_OK(unseal_mover(), "unseal the mover"))
		return;
	ASSERT_OK(write_pid(plain_fd, "cgroup.procs", child),
		  "move out of a sealed cgroup");
	ASSERT_TRUE(in_cgroup(plain_fd, child), "the child moved out");
	ASSERT_OK(write_pid(child_fd, "cgroup.procs", child), "move it back");
}

void test_lsm_task_cgroup_attach(void)
{
	struct lsm_task_cgroup_attach *skel = NULL;
	int dom_fd = -1;

	if (!ASSERT_OK(setup_cgroup_environment(), "setup cgroup environment"))
		return;

	mover_fd = create_and_get_cgroup(MOVER_CG);
	if (!ASSERT_OK_FD(mover_fd, "create the mover cgroup"))
		goto out;
	if (set_cgroup_xattr(MOVER_CG, ZONE, "sealed")) {
		printf("%s:SKIP:cannot set %s on a cgroup (errno %d)\n",
		       __func__, ZONE, errno);
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(join_cgroup(MOVER_CG), "join the mover cgroup"))
		goto out;
	child_fd = create_and_get_cgroup(CHILD_CG);
	sealed_fd = create_and_get_cgroup(SEALED_CG);
	plain_fd = create_and_get_cgroup(PLAIN_CG);
	dom_fd = create_and_get_cgroup(DOM_CG);
	if (!ASSERT_OK_FD(child_fd, "create the child cgroup") ||
	    !ASSERT_OK_FD(sealed_fd, "create the sealed cgroup") ||
	    !ASSERT_OK_FD(plain_fd, "create the unlabelled cgroup") ||
	    !ASSERT_OK_FD(dom_fd, "create the threaded domain"))
		goto out;
	if (!ASSERT_OK(set_cgroup_xattr(SEALED_CG, ZONE, "sealed"),
		       "seal a cgroup"))
		goto out;

	/* The task that is moved about, parked out of the way. */
	child = fork();
	if (child == 0) {
		for (;;)
			pause();
	}
	if (!ASSERT_GE(child, 0, "fork the child"))
		goto out;

	skel = lsm_task_cgroup_attach__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open and load"))
		goto out;
	skel->bss->monitored_pid = getpid();
	if (!ASSERT_OK(lsm_task_cgroup_attach__attach(skel), "attach"))
		goto out;
	if (!ASSERT_OK(write_pid(child_fd, "cgroup.procs", child),
		       "park the child"))
		goto out;

	if (test__start_subtest("procs_write_denied"))
		test_procs_write_denied(skel);
	if (test__start_subtest("procs_write_allowed"))
		test_procs_write_allowed(skel);
	if (test__start_subtest("threads_write_denied"))
		test_threads_write_denied(skel);
	if (test__start_subtest("clone3_denied"))
		test_clone3_denied(skel);
	if (test__start_subtest("clone3_allowed"))
		test_clone3_allowed(skel);
	if (test__start_subtest("hook_sees_task_and_destination"))
		test_hook_sees_task_and_destination(skel);
	if (test__start_subtest("move_out_allowed"))
		test_move_out_allowed(skel);
out:
	lsm_task_cgroup_attach__destroy(skel);
	if (child > 0) {
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		child = -1;
	}
	if (dom_fd >= 0)
		close(dom_fd);
	if (plain_fd >= 0)
		close(plain_fd);
	if (sealed_fd >= 0)
		close(sealed_fd);
	if (child_fd >= 0)
		close(child_fd);
	if (mover_fd >= 0)
		close(mover_fd);
	mover_fd = child_fd = sealed_fd = plain_fd = -1;
	cleanup_cgroup_environment();
}
