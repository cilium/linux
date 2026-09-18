// SPDX-License-Identifier: GPL-2.0
/* A labelled program's sockets carrying its label.
 *
 * The whole path, as a policy would use it: an executable labelled on disk
 * with security.bpf.zone, a task that execs it, and the sockets that task
 * opens carrying the zone -- readable from socket_connect and
 * socket_sendmsg, neither of which may sleep or touch a filesystem.
 *
 * The application runs as its own program, sock_zone_helper, because the
 * label is read at exec: there is no exec, no label. It checks from
 * userspace what its sockets ended up carrying, and that it cannot write a
 * label itself, and reports which step disagreed in its exit status.
 */
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <test_progs.h>

#include "lsm_sock_zone.skel.h"
#include "lsm_sock_zone_fail.skel.h"

#define ZONE_XATTR	"security.bpf.zone"
#define ZONE		"prod"
#define HELPER_SRC	"./sock_zone_helper"
#define BASE		"/tmp/test_progs_sock_zone"
#define APP		BASE "/app"

/* The helper's exit status, as sock_zone_helper.c defines it. */
static const char * const helper_err[] = {
	[1] = "socket() failed",
	[2] = "socket carried no label",
	[3] = "socket carried the wrong label",
	[4] = "fsetxattr() forged a label",
	[5] = "the label changed",
	[6] = "loopback setup failed",
	[7] = "accept() failed",
	[8] = "accepted socket carried the wrong label",
};

static int copy_file(const char *src, const char *dst)
{
	char buf[4096];
	int in, out, n, ret = 0;

	in = open(src, O_RDONLY);
	if (in < 0)
		return -errno;
	out = open(dst, O_CREAT | O_WRONLY | O_TRUNC, 0755);
	if (out < 0) {
		close(in);
		return -errno;
	}
	while ((n = read(in, buf, sizeof(buf))) > 0) {
		if (write(out, buf, n) != n) {
			ret = -EIO;
			break;
		}
	}
	if (n < 0)
		ret = -errno;
	close(in);
	close(out);
	return ret;
}

/* Run the labelled program and return its exit status, or a negative errno. */
static int run_app(void)
{
	char *const argv[] = { (char *)APP, (char *)ZONE, NULL };
	char *const envp[] = { NULL };
	int status;
	pid_t pid;

	pid = fork();
	if (pid < 0)
		return -errno;
	if (pid == 0) {
		execve(APP, argv, envp);
		_exit(127);
	}
	if (waitpid(pid, &status, 0) < 0)
		return -errno;
	if (!WIFEXITED(status))
		return -EINTR;
	return WEXITSTATUS(status);
}

static void test_labelled_app(struct lsm_sock_zone *skel)
{
	int ret = run_app();

	if (!ASSERT_GE(ret, 0, "run the labelled app"))
		return;
	if (ret) {
		const char *why = ret < (int)ARRAY_SIZE(helper_err) ?
				  helper_err[ret] : "unknown";

		PRINT_FAIL("sock_zone_helper: %s (exit %d)\n", why, ret);
		return;
	}

	/* The label was read once, off the executable, at exec. */
	ASSERT_EQ(skel->data->exec_ret, sizeof(ZONE), "zone read at exec");
	ASSERT_STREQ(skel->bss->exec_zone, ZONE, "zone on the executable");

	/* And put on the sockets, where the traffic hooks could read it. */
	ASSERT_OK(skel->data->create_ret, "socket labelled at creation");
	ASSERT_EQ(skel->data->connect_ret, sizeof(ZONE), "zone read at connect");
	ASSERT_STREQ(skel->bss->connect_zone, ZONE, "zone at connect");
	ASSERT_EQ(skel->data->sendmsg_ret, sizeof(ZONE), "zone read at sendmsg");
	ASSERT_STREQ(skel->bss->sendmsg_zone, ZONE, "zone at sendmsg");
	ASSERT_OK(skel->data->accept_ret, "accepted socket labelled");
}

/* This process never exec'd anything labelled, so its sockets carry nothing,
 * and say so rather than reading back as some default.
 */
static void test_unlabelled_task(struct lsm_sock_zone *skel)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(1),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	char buf[64] = {};
	int fd;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (!ASSERT_OK_FD(fd, "socket"))
		return;
	connect(fd, (struct sockaddr *)&addr, sizeof(addr));

	ASSERT_EQ(skel->data->unlabelled_ret, -ENODATA, "no zone to read");
	ASSERT_EQ(fgetxattr(fd, ZONE_XATTR, buf, sizeof(buf)) < 0 ? -errno : 0,
		  -ENODATA, "and none from userspace either");
	close(fd);
}

void test_lsm_sock_zone(void)
{
	struct lsm_sock_zone *skel = NULL;
	int err;

	RUN_TESTS(lsm_sock_zone_fail);

	if (mkdir(BASE, 0755) && errno != EEXIST) {
		ASSERT_OK(-errno, "mkdir");
		return;
	}
	if (!ASSERT_OK(copy_file(HELPER_SRC, APP), "copy the app"))
		goto out;

	err = setxattr(APP, ZONE_XATTR, ZONE, sizeof(ZONE), 0) ? -errno : 0;
	if (err == -EOPNOTSUPP) {
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(err, "label the app"))
		goto out;

	skel = lsm_sock_zone__open_and_load();
	if (!ASSERT_OK_PTR(skel, "lsm_sock_zone__open_and_load"))
		goto out;
	skel->bss->monitored_pid = getpid();
	if (!ASSERT_OK(lsm_sock_zone__attach(skel), "attach"))
		goto out;

	if (test__start_subtest("labelled_app"))
		test_labelled_app(skel);
	if (test__start_subtest("unlabelled_task"))
		test_unlabelled_task(skel);
out:
	lsm_sock_zone__destroy(skel);
	unlink(APP);
	rmdir(BASE);
}
