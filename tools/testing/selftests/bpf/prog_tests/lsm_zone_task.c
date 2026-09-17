// SPDX-License-Identifier: GPL-2.0
/* Tasks under the zone policy: what the mapping hooks never see. A write
 * through the own mem file and a tracer are refused in the default zone, and
 * outside the policy only attaching to a trusted task is; exec, as an
 * interpreter checks it before running a script, follows the file's zone.
 *
 * The zoned root stands in for the default zone, the trusted pod below it
 * for the trusted one, the unzoned root for a task in no zone. The manager
 * parked in the trusted pod places the test process and is the trusted task
 * to attach to.
 */
#define ZONE_TMP "/tmp/test_progs_zone_task_"
#include "lsm_zone_helpers.h"
#include "lsm_zone_task.skel.h"

#define FILE_TRUSTED	ZONE_TMP "trusted"
#define FILE_DEFAULT	ZONE_TMP "default"

static struct zone_env zenv;

/* Writing through /proc/PID/mem forces a copy of a private page past its
 * protection, and to one's own mem file no ptrace check applies.
 */
static void test_default_cannot_open_own_mem_for_write(struct lsm_zone_task *skel)
{
	__u32 denied = skel->bss->mem_denied;

	if (!ASSERT_OK(enter(ROOT_CG), "enter default zone"))
		return;
	ASSERT_EQ(try_open(AT_FDCWD, "/proc/self/mem", O_RDWR), -EPERM,
		  "default: open own mem read-write");
	ASSERT_EQ(try_open(AT_FDCWD, "/proc/self/mem", O_WRONLY), -EPERM,
		  "default: open own mem for write");
	ASSERT_EQ(skel->bss->mem_denied - denied, 2, "mem_denied");
}

/* Reading it forces nothing: the open goes through and the bytes come back. */
static void test_default_reads_own_mem(struct lsm_zone_task *skel)
{
	static const char probe = 'z';
	char c = 0;
	int fd;

	if (!ASSERT_OK(enter(ROOT_CG), "enter default zone"))
		return;
	fd = open("/proc/self/mem", O_RDONLY);
	if (!ASSERT_OK_FD(fd, "default: open own mem for read"))
		return;
	ASSERT_EQ(pread(fd, &c, 1, (off_t)(uintptr_t)&probe), 1, "default: read own mem");
	ASSERT_EQ(c, probe, "default: byte read back");
	close(fd);
}

/* A tracer writes into private mappings past every protection: no attaching
 * from the default zone, not even to its own child.
 */
static void test_default_cannot_ptrace(struct lsm_zone_task *skel)
{
	__u32 denied = skel->bss->ptrace_denied;

	if (!ASSERT_OK(enter(ROOT_CG), "enter default zone"))
		return;
	ASSERT_EQ(attach_child(), -EPERM, "default: ptrace attach own child");
	ASSERT_EQ(skel->bss->ptrace_denied - denied, 1, "ptrace_denied");
}

/* The trusted zone attaches. */
static void test_trusted_ptraces(struct lsm_zone_task *skel)
{
	if (!ASSERT_OK(enter(TRUSTED_CG), "enter trusted zone"))
		return;
	ASSERT_OK(attach_child(), "trusted: ptrace attach own child");
}

/* Outside the policy only attaching to a trusted task is refused: the manager
 * parked in the trusted pod, but not one's own child.
 */
static void test_unzoned_cannot_ptrace_trusted(struct lsm_zone_task *skel)
{
	__u32 denied = skel->bss->ptrace_denied;

	if (!ASSERT_OK(enter(PLAIN_CG), "enter unzoned root"))
		return;
	ASSERT_OK(attach_child(), "unzoned: ptrace attach own child");
	ASSERT_EQ(attach_pid(mover), -EPERM, "unzoned: ptrace attach trusted task");
	ASSERT_EQ(skel->bss->ptrace_denied - denied, 1, "ptrace_denied");
}

/* A file written in the default zone carries "default" from its first
 * instant and cannot be run there, as an interpreter's check finds out.
 */
static void test_exec_check_of_default_file_denied(struct lsm_zone_task *skel)
{
	__u32 denied = skel->bss->exec_denied;

	if (!ASSERT_OK(enter(ROOT_CG), "enter default zone"))
		return;
	ASSERT_EQ(exec_check(FILE_DEFAULT), -EPERM,
		  "default: exec check of file written here");
	ASSERT_EQ(skel->bss->exec_denied - denied, 1, "exec_denied");
}

/* One carrying the trusted label may run. */
static void test_exec_check_of_trusted_file_allowed(struct lsm_zone_task *skel)
{
	__u32 allowed = skel->bss->allowed;

	if (!ASSERT_OK(enter(ROOT_CG), "enter default zone"))
		return;
	ASSERT_OK(exec_check(FILE_TRUSTED), "default: exec check of trusted file");
	ASSERT_EQ(skel->bss->allowed - allowed, 1, "allowed");
}

/* In the trusted zone nothing is enforced: either file passes the check. */
static void test_trusted_exec_check_unenforced(struct lsm_zone_task *skel)
{
	if (!ASSERT_OK(enter(TRUSTED_CG), "enter trusted zone"))
		return;
	ASSERT_OK(exec_check(FILE_DEFAULT), "trusted: exec check of default-zone file");
	ASSERT_OK(exec_check(FILE_TRUSTED), "trusted: exec check of trusted file");
}

void test_lsm_zone_task(void)
{
	struct lsm_zone_task *skel = NULL;
	int err;

	remove(FILE_TRUSTED);
	remove(FILE_DEFAULT);
	err = zone_bootstrap(&zenv);
	if (err == -EOPNOTSUPP) {
		printf("%s:SKIP:cannot set %s on a cgroup\n", __func__, ZONE_XATTR);
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(err, "zone_bootstrap"))
		goto out;

	/* What the trusted zone installs: a page file labelled by hand. */
	if (!ASSERT_OK(make_page_file(FILE_TRUSTED), "make trusted file"))
		goto out;
	err = set_zone(FILE_TRUSTED, ZONE_TRUSTED);
	if (err == -EOPNOTSUPP) {
		printf("%s:SKIP:local fs doesn't support xattr (%d)\n"
		       "To run this test, make sure /tmp filesystem supports xattr.\n",
		       __func__, -err);
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(err, "label trusted file"))
		goto out;

	skel = lsm_zone_task__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel open_and_load"))
		goto out;
	skel->bss->monitored_pid = getpid();
	if (!ASSERT_OK(lsm_zone_task__attach(skel), "skel attach"))
		goto out;

	/* What the default zone writes: a page file made there, stamped
	 * "default" by the policy as it is created.
	 */
	if (!ASSERT_OK(enter(ROOT_CG), "enter default zone"))
		goto out;
	if (!ASSERT_OK(make_page_file(FILE_DEFAULT), "make default file"))
		goto out;
	ASSERT_OK(skel->data->stamp_err, "stamp_err");
	assert_file_zone(FILE_DEFAULT, ZONE_DEFAULT, "default: file stamped default");

	if (test__start_subtest("default_cannot_open_own_mem_for_write"))
		test_default_cannot_open_own_mem_for_write(skel);
	if (test__start_subtest("default_reads_own_mem"))
		test_default_reads_own_mem(skel);
	if (test__start_subtest("default_cannot_ptrace"))
		test_default_cannot_ptrace(skel);
	if (test__start_subtest("trusted_ptraces"))
		test_trusted_ptraces(skel);
	if (test__start_subtest("unzoned_cannot_ptrace_trusted"))
		test_unzoned_cannot_ptrace_trusted(skel);
	if (test__start_subtest("exec_check_of_default_file_denied"))
		test_exec_check_of_default_file_denied(skel);
	if (test__start_subtest("exec_check_of_trusted_file_allowed"))
		test_exec_check_of_trusted_file_allowed(skel);
	if (test__start_subtest("trusted_exec_check_unenforced"))
		test_trusted_exec_check_unenforced(skel);
out:
	lsm_zone_task__destroy(skel);
	zone_teardown(&zenv);
	remove(FILE_TRUSTED);
	remove(FILE_DEFAULT);
}
