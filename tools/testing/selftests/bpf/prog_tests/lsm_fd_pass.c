// SPDX-License-Identifier: GPL-2.0
/* Passing a labelled socket to another task, and being refused.
 *
 * This is the hole the socket label opens by living on the inode: the label
 * follows the descriptor across SCM_RIGHTS. The policy closes it at
 * file_receive rather than by relabelling, so a socket's label stays
 * written once and never changes.
 *
 * Nothing here needs a kernel change. bpf_get_file_xattr() already reaches
 * a sockfs inode through file_dentry(), which is what the security.* get
 * handler on sockfs is for.
 */
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <test_progs.h>

#include "lsm_fd_pass.skel.h"

#define ZONE		"prod"

/* Send @fd over @sock via SCM_RIGHTS: 0 or -errno. */
static int send_fd(int sock, int fd)
{
	char c = 'x';
	char cbuf[CMSG_SPACE(sizeof(int))] = {};
	struct iovec iov = { .iov_base = &c, .iov_len = 1 };
	struct msghdr m = { .msg_iov = &iov, .msg_iovlen = 1,
			    .msg_control = cbuf, .msg_controllen = sizeof(cbuf) };
	struct cmsghdr *cm = CMSG_FIRSTHDR(&m);

	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_type = SCM_RIGHTS;
	cm->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cm), &fd, sizeof(int));
	return sendmsg(sock, &m, 0) < 0 ? -errno : 0;
}

/* Receive one descriptor: the fd, or a negative errno.
 *
 * A refusal surfaces in one of two ways. By default scm_detach_fds() stops
 * at the first refused descriptor and writes no SCM_RIGHTS header at all,
 * so the message arrives without the fd and with MSG_CTRUNC set, which
 * reads here as -ENOMSG. A unix socket that has turned on
 * scm_rights_notrunc instead keeps the header and puts the errno in the
 * slot, which reads back as that errno. Either way the fd is not
 * delivered, and @flags_out carries msg_flags so the caller can tell a
 * refusal from a malformed message.
 */
static int recv_fd(int sock, int *flags_out)
{
	char c;
	char cbuf[CMSG_SPACE(sizeof(int))] = {};
	struct iovec iov = { .iov_base = &c, .iov_len = 1 };
	struct msghdr m = { .msg_iov = &iov, .msg_iovlen = 1,
			    .msg_control = cbuf, .msg_controllen = sizeof(cbuf) };
	struct cmsghdr *cm;
	int fd;

	if (recvmsg(sock, &m, 0) < 0)
		return -errno;
	if (flags_out)
		*flags_out = m.msg_flags;
	cm = CMSG_FIRSTHDR(&m);
	if (!cm || cm->cmsg_type != SCM_RIGHTS)
		return -ENOMSG;
	memcpy(&fd, CMSG_DATA(cm), sizeof(int));
	return fd;
}

static void test_labelled_fd_pass(void)
{
	struct lsm_fd_pass *skel = NULL;
	int sp[2] = { -1, -1 };
	int zoned = -1, got = -1;
	int status;
	pid_t pid;

	skel = lsm_fd_pass__open_and_load();
	if (!ASSERT_OK_PTR(skel, "lsm_fd_pass__open_and_load"))
		return;
	skel->bss->owner_pid = getpid();
	skel->bss->zone_len = sizeof(ZONE);
	if (!ASSERT_OK(lsm_fd_pass__attach(skel), "attach"))
		goto out;

	if (!ASSERT_OK(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) ? -errno : 0,
		       "socketpair"))
		goto out;
	zoned = socket(AF_INET, SOCK_STREAM, 0);
	if (!ASSERT_OK_FD(zoned, "zoned socket"))
		goto out;
	ASSERT_GE(skel->bss->sockets_labelled, 1, "socket labelled");

	/* The owner may hand its own socket back to itself. */
	if (!ASSERT_OK(send_fd(sp[0], zoned), "send to self"))
		goto out;
	got = recv_fd(sp[1], NULL);
	if (ASSERT_GE(got, 0, "owner receives its own socket"))
		close(got);
	ASSERT_EQ(skel->data->label_ret, sizeof(ZONE), "label seen at receive");
	ASSERT_STREQ(skel->bss->seen_zone, ZONE, "zone seen at receive");

	/* Another task may not, even though the descriptor is identical. */
	pid = fork();
	if (!ASSERT_GE(pid, 0, "fork"))
		goto out;
	if (pid == 0) {
		int flags = 0;
		int r = recv_fd(sp[1], &flags);

		/* 0 = refused, 1 = got the socket, 2 = refused unrecognisably */
		if (r >= 0) {
			close(r);
			_exit(1);
		}
		if (r == -ENOMSG && (flags & MSG_CTRUNC))
			_exit(0);	/* no header written: the default */
		if (r == -EPERM)
			_exit(0);	/* errno in the slot: scm_rights_notrunc */
		_exit(2);
	}
	if (!ASSERT_OK(send_fd(sp[0], zoned), "send to the child"))
		goto out;
	if (!ASSERT_OK(waitpid(pid, &status, 0) < 0 ? -errno : 0, "waitpid"))
		goto out;
	if (ASSERT_TRUE(WIFEXITED(status), "child exited")) {
		if (WEXITSTATUS(status) == 1)
			PRINT_FAIL("child received a socket of a zone it was not granted\n");
		else
			ASSERT_EQ(WEXITSTATUS(status), 0, "child was refused the socket");
	}
	ASSERT_GE(skel->bss->receives_denied, 1, "a receive was denied");
out:
	if (zoned >= 0)
		close(zoned);
	if (sp[0] >= 0)
		close(sp[0]);
	if (sp[1] >= 0)
		close(sp[1]);
	lsm_fd_pass__destroy(skel);
}

void test_lsm_fd_pass(void)
{
	if (test__start_subtest("labelled_fd_pass"))
		test_labelled_fd_pass();
}
