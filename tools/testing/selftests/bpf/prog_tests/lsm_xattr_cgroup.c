// SPDX-License-Identifier: GPL-2.0
/*
 * bpf_cgroup_read_xattr: a policy reads the label of the cgroup a task runs
 * in, from an LSM hook and from a tracing program alike, since the kfunc is
 * in the common set, and reads another task's cgroup through the task it is
 * handed on task_cgroup_attach.
 */
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <test_progs.h>
#include "cgroup_helpers.h"
#include "lsm_xattr_cgroup.skel.h"

#define ZONE		"security.bpf.zone"
#define USER_NOTE	"user.note"
#define SELF_CG		"/xattr_cgroup_self/"
#define SRC_CG		"/xattr_cgroup_src/"
#define DST_CG		"/xattr_cgroup_dst/"
#define TMPFILE		"/tmp/test_progs_xattr_cgroup"

enum {
	MODE_NONE,
	MODE_ZONE,
	MODE_USER,
	MODE_MISSING,
	MODE_SHORT,
	MODE_FOREIGN,
};

/* Open a file with the hook asking for @mode: 0, or the -errno the policy
 * handed back through the open.
 */
static int open_under_policy(struct lsm_xattr_cgroup *skel, int mode)
{
	int fd;

	skel->bss->own_ret = 0;
	skel->bss->mode = mode;
	fd = open(TMPFILE, O_RDONLY);
	skel->bss->mode = MODE_NONE;
	if (fd < 0)
		return -errno;
	close(fd);
	return 0;
}

/* A label the policy owns is read back off the current task's cgroup. */
static void test_read_security_bpf(struct lsm_xattr_cgroup *skel)
{
	ASSERT_OK(open_under_policy(skel, MODE_ZONE), "open");
	ASSERT_EQ(skel->bss->own_ret, (int)sizeof("alpha"), "own_ret");
	ASSERT_STREQ(skel->bss->own_buf, "alpha", "label read");
}

/* The getter takes user. names too. */
static void test_read_user(struct lsm_xattr_cgroup *skel)
{
	ASSERT_OK(open_under_policy(skel, MODE_USER), "open");
	ASSERT_EQ(skel->bss->own_ret, (int)sizeof("hello"), "own_ret");
	ASSERT_STREQ(skel->bss->own_buf, "hello", "note read");
}

/* A name that is not there reads -ENODATA, which the open hands on. */
static void test_missing(struct lsm_xattr_cgroup *skel)
{
	ASSERT_EQ(open_under_policy(skel, MODE_MISSING), -ENODATA, "open");
	ASSERT_EQ(skel->bss->own_ret, -ENODATA, "own_ret");
}

/* A buffer shorter than the value reads -ERANGE. */
static void test_short_buffer(struct lsm_xattr_cgroup *skel)
{
	ASSERT_EQ(open_under_policy(skel, MODE_SHORT), -ERANGE, "open");
	ASSERT_EQ(skel->bss->own_ret, -ERANGE, "own_ret");
}

/* Another LSM's label cannot be read at all. */
static void test_foreign_name_refused(struct lsm_xattr_cgroup *skel)
{
	ASSERT_EQ(open_under_policy(skel, MODE_FOREIGN), -EPERM, "open");
	ASSERT_EQ(skel->bss->own_ret, -EPERM, "own_ret");
}

/* The kfunc is in the common set, so a tracing program reads the same. */
static void test_from_non_lsm_program(struct lsm_xattr_cgroup *skel)
{
	skel->bss->tp_ret = 0;
	skel->bss->tp_armed = 1;
	syscall(__NR_getpid);
	ASSERT_EQ(skel->bss->tp_armed, 0, "program ran");
	ASSERT_EQ(skel->bss->tp_ret, (int)sizeof("alpha"), "tp_ret");
	ASSERT_STREQ(skel->bss->tp_buf, "alpha", "label read");
}

/* The cgroup of the task the hook is handed, not of the one running it:
 * the child is moved out of a cgroup labelled differently from our own.
 */
static void test_other_task_cgroup(struct lsm_xattr_cgroup *skel)
{
	char pid[16];
	pid_t child;

	child = fork();
	if (child == 0) {
		for (;;)
			pause();
	}
	if (!ASSERT_GE(child, 0, "fork child"))
		return;
	snprintf(pid, sizeof(pid), "%d", child);
	if (!ASSERT_OK(write_cgroup_file(SRC_CG, "cgroup.procs", pid),
		       "park child in the source cgroup"))
		goto out;
	skel->bss->task_pid = 0;
	skel->bss->task_ret = 0;
	if (!ASSERT_OK(write_cgroup_file(DST_CG, "cgroup.procs", pid),
		       "move the child on"))
		goto out;
	ASSERT_EQ(skel->bss->task_pid, child, "the moved task");
	ASSERT_EQ(skel->bss->task_ret, (int)sizeof("beta"), "task_ret");
	ASSERT_STREQ(skel->bss->task_buf, "beta", "the moved task's label");
out:
	if (child > 0) {
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
	}
}

void test_lsm_xattr_cgroup(void)
{
	int self_fd = -1, src_fd = -1, dst_fd = -1, fd;
	struct lsm_xattr_cgroup *skel = NULL;

	remove(TMPFILE);
	if (!ASSERT_OK(setup_cgroup_environment(), "setup cgroup environment"))
		return;

	self_fd = create_and_get_cgroup(SELF_CG);
	if (!ASSERT_OK_FD(self_fd, "create own cgroup"))
		goto out;
	if (set_cgroup_xattr(SELF_CG, ZONE, "alpha")) {
		printf("%s:SKIP:cannot set %s on a cgroup (errno %d)\n",
		       __func__, ZONE, errno);
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(set_cgroup_xattr(SELF_CG, USER_NOTE, "hello"),
		       "set user note") ||
	    !ASSERT_OK(join_cgroup(SELF_CG), "join own cgroup"))
		goto out;
	src_fd = create_and_get_cgroup(SRC_CG);
	if (!ASSERT_OK_FD(src_fd, "create source cgroup") ||
	    !ASSERT_OK(set_cgroup_xattr(SRC_CG, ZONE, "beta"), "label it"))
		goto out;
	dst_fd = create_and_get_cgroup(DST_CG);
	if (!ASSERT_OK_FD(dst_fd, "create destination cgroup"))
		goto out;

	fd = open(TMPFILE, O_CREAT | O_RDONLY, 0644);
	if (!ASSERT_OK_FD(fd, "create the file to open"))
		goto out;
	close(fd);

	skel = lsm_xattr_cgroup__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open and load"))
		goto out;
	skel->bss->monitored_pid = getpid();
	if (!ASSERT_OK(lsm_xattr_cgroup__attach(skel), "attach"))
		goto out;

	if (test__start_subtest("read_security_bpf"))
		test_read_security_bpf(skel);
	if (test__start_subtest("read_user"))
		test_read_user(skel);
	if (test__start_subtest("missing"))
		test_missing(skel);
	if (test__start_subtest("short_buffer"))
		test_short_buffer(skel);
	if (test__start_subtest("foreign_name_refused"))
		test_foreign_name_refused(skel);
	if (test__start_subtest("from_non_lsm_program"))
		test_from_non_lsm_program(skel);
	if (test__start_subtest("other_task_cgroup"))
		test_other_task_cgroup(skel);
out:
	if (skel)
		skel->bss->mode = MODE_NONE;
	lsm_xattr_cgroup__destroy(skel);
	if (dst_fd >= 0)
		close(dst_fd);
	if (src_fd >= 0)
		close(src_fd);
	if (self_fd >= 0)
		close(self_fd);
	cleanup_cgroup_environment();
	remove(TMPFILE);
}
