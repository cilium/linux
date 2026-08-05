// SPDX-License-Identifier: GPL-2.0
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test_progs.h"
#include "cap_helpers.h"
#include "task_vm_access.skel.h"

/*
 * Reading the memory of a task the caller may not ptrace() has to fail, the
 * same way /proc/<pid>/mem would. The victim runs under a different uid, so
 * only CAP_SYS_PTRACE lets the reader in.
 */
#define VICTIM_UID	65534	/* nobody */

static char victim_secret[16] = "STARLABS";

/*
 * Fork a child that drops to VICTIM_UID and then blocks. 'hold_fd' keeps it
 * alive: closing it lets the child exit. victim_secret lives at the same
 * address in the child, so the parent can hand that address to the program.
 */
static pid_t spawn_victim(int *hold_fd)
{
	int notify[2], hold[2];
	pid_t pid;
	char c;

	if (!ASSERT_OK(pipe(notify), "pipe notify"))
		return -1;
	if (!ASSERT_OK(pipe(hold), "pipe hold")) {
		close(notify[0]);
		close(notify[1]);
		return -1;
	}

	pid = fork();
	if (!ASSERT_GE(pid, 0, "fork")) {
		close(notify[0]);
		close(notify[1]);
		close(hold[0]);
		close(hold[1]);
		return -1;
	}

	if (pid == 0) {
		close(notify[0]);
		close(hold[1]);
		if (setresgid(VICTIM_UID, VICTIM_UID, VICTIM_UID) ||
		    setresuid(VICTIM_UID, VICTIM_UID, VICTIM_UID))
			_exit(1);
		if (write(notify[1], victim_secret, 1) != 1)
			_exit(1);
		/* Block until the parent closes its end of 'hold'. */
		read(hold[0], &c, 1);
		_exit(0);
	}

	close(notify[1]);
	close(hold[0]);

	/* Wait for the child to finish dropping privileges. */
	if (!ASSERT_EQ(read(notify[0], &c, 1), 1, "victim ready")) {
		close(notify[0]);
		close(hold[1]);
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		return -1;
	}
	close(notify[0]);

	*hold_fd = hold[1];
	return pid;
}

void test_task_vm_access(void)
{
	struct task_vm_access *skel;
	int hold_fd = -1, err;
	__u64 old_caps = 0;
	pid_t victim;

	skel = task_vm_access__open_and_load();
	if (!ASSERT_OK_PTR(skel, "task_vm_access open_load"))
		return;

	victim = spawn_victim(&hold_fd);
	if (victim < 0)
		goto destroy;

	skel->bss->target_pid = getpid();
	skel->bss->victim_pid = victim;
	skel->bss->user_ptr = victim_secret;

	err = task_vm_access__attach(skel);
	if (!ASSERT_OK(err, "task_vm_access attach"))
		goto release_victim;

	/* CAP_SYS_PTRACE lets the reader through, as it does for ptrace(2). */
	usleep(1);
	ASSERT_EQ(skel->bss->copy_task_ret, 0, "privileged copy_from_user_task");
	ASSERT_EQ(skel->bss->copy_task_str_ret, (int)sizeof("STARLABS"),
		  "privileged copy_from_user_task_str");
	ASSERT_STREQ(skel->bss->copy_task_str_buf, "STARLABS",
		     "privileged copy_from_user_task_str buf");

	/* Without it the uids differ, so the read has to be refused. */
	if (!ASSERT_OK(cap_disable_effective(1ULL << CAP_SYS_PTRACE, &old_caps),
		       "disable CAP_SYS_PTRACE"))
		goto release_victim;

	skel->bss->copy_task_ret = 1;
	skel->bss->copy_task_str_ret = 1;
	usleep(1);
	ASSERT_EQ(skel->bss->copy_task_ret, -EACCES, "unprivileged copy_from_user_task");
	ASSERT_EQ(skel->bss->copy_task_str_ret, -EACCES,
		  "unprivileged copy_from_user_task_str");

	ASSERT_OK(cap_enable_effective(old_caps, NULL), "restore CAP_SYS_PTRACE");

release_victim:
	close(hold_fd);
	waitpid(victim, NULL, 0);
destroy:
	task_vm_access__destroy(skel);
}
