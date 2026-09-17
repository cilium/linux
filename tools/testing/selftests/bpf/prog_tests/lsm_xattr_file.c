// SPDX-License-Identifier: GPL-2.0
/*
 * The file xattr kfuncs from the hooks that hand out a struct file and no
 * trusted dentry: what the setter, the getter and the remover do at
 * file_open, the names they refuse and the errors they report, a file
 * claimed when it is written through at file_permission, and the label of a
 * descriptor read at file_receive as it is passed over SCM_RIGHTS.
 */
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <test_progs.h>
#include "lsm_xattr_file.skel.h"

#define BASE		"/tmp/test_progs_xattr_file"
#define FILE		BASE "/file"
#define PLAIN		BASE "/plain"
#define SEALED		BASE "/sealed"
#define RAMFS		BASE "_ramfs"
#define RAMFS_FILE	RAMFS "/file"

#define DATA		"security.bpf.data"
#define CLAIM		"security.bpf.claim"
#define USER		"user.data"
#define HELLO		"hello"

enum {
	OP_NONE,
	OP_SET,
	OP_REMOVE,
	OP_GET,
	OP_SET_CREATE,
	OP_SET_REPLACE,
	OP_SET_EMPTY,
	OP_GET_MISSING,
	OP_GET_SHORT,
	OP_SET_USER,
	OP_FOREIGN,
	OP_NO_XATTR_FS,
	OP_CLAIM,
	OP_RECEIVE,
};

static int make_file(const char *path)
{
	int fd = open(path, O_CREAT | O_WRONLY, 0644);

	if (fd < 0)
		return -errno;
	close(fd);
	return 0;
}

/* Read a xattr: its length, or -errno. */
static int get_xattr(const char *path, const char *name, char *buf, size_t sz)
{
	int len = getxattr(path, name, buf, sz);

	return len < 0 ? -errno : len;
}

/* Point the policy at @path and let it act on the next open of it. */
static int aim(struct lsm_xattr_file *skel, const char *path, int op)
{
	struct stat st;

	if (stat(path, &st))
		return -errno;
	skel->bss->target_ino = st.st_ino;
	skel->bss->op = op;
	return 0;
}

/* Fire file_open on @path: 0 or -errno. */
static int trigger_open(const char *path)
{
	int fd = open(path, O_RDONLY);

	if (fd < 0)
		return -errno;
	close(fd);
	return 0;
}

static void reset(struct lsm_xattr_file *skel)
{
	removexattr(FILE, DATA);
	removexattr(FILE, CLAIM);
	removexattr(FILE, USER);
	skel->bss->get_ret = 0;
	skel->bss->set_ret = 0;
	skel->bss->remove_ret = 0;
	skel->bss->claims = 0;
	memset(skel->bss->read_value, 0, sizeof(skel->bss->read_value));
	skel->bss->op = OP_NONE;
	skel->bss->target_ino = 0;
}

/* Send @fd over @sock via SCM_RIGHTS: 0 or -errno. */
static int send_fd(int sock, int fd)
{
	char cbuf[CMSG_SPACE(sizeof(int))] = {};
	char c = 'x';
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

/* Receive one fd from @sock: the fd, or -errno. A refusal by file_receive
 * delivers the message without the descriptor, which reads as -ENOMSG.
 */
static int recv_fd(int sock)
{
	char cbuf[CMSG_SPACE(sizeof(int))] = {};
	char c;
	struct iovec iov = { .iov_base = &c, .iov_len = 1 };
	struct msghdr m = { .msg_iov = &iov, .msg_iovlen = 1,
			    .msg_control = cbuf, .msg_controllen = sizeof(cbuf) };
	struct cmsghdr *cm;
	int fd;

	if (recvmsg(sock, &m, 0) < 0)
		return -errno;
	cm = CMSG_FIRSTHDR(&m);
	if (!cm || cm->cmsg_type != SCM_RIGHTS)
		return -ENOMSG;
	memcpy(&fd, CMSG_DATA(cm), sizeof(int));
	return fd;
}

static void test_set_on_open(struct lsm_xattr_file *skel)
{
	char buf[64] = {};

	reset(skel);
	if (!ASSERT_OK(aim(skel, FILE, OP_SET), "aim"))
		return;
	ASSERT_OK(trigger_open(FILE), "open");
	ASSERT_OK(skel->bss->set_ret, "set_ret");
	if (ASSERT_EQ(get_xattr(FILE, DATA, buf, sizeof(buf)), sizeof(HELLO),
		      "value length"))
		ASSERT_STREQ(buf, HELLO, "value");
}

static void test_remove_on_open(struct lsm_xattr_file *skel)
{
	char buf[64] = {};

	reset(skel);
	if (!ASSERT_OK(setxattr(FILE, DATA, HELLO, sizeof(HELLO), 0), "set data"))
		return;
	if (!ASSERT_OK(aim(skel, FILE, OP_REMOVE), "aim"))
		return;
	ASSERT_OK(trigger_open(FILE), "open");
	ASSERT_OK(skel->bss->remove_ret, "remove_ret");
	ASSERT_EQ(get_xattr(FILE, DATA, buf, sizeof(buf)), -ENODATA, "gone");
}

static void test_get(struct lsm_xattr_file *skel)
{
	reset(skel);
	if (!ASSERT_OK(setxattr(FILE, DATA, HELLO, sizeof(HELLO), 0), "set data"))
		return;
	if (!ASSERT_OK(aim(skel, FILE, OP_GET), "aim"))
		return;
	ASSERT_OK(trigger_open(FILE), "open");
	ASSERT_EQ(skel->bss->get_ret, sizeof(HELLO), "get_ret");
	ASSERT_STREQ(skel->bss->read_value, HELLO, "value read");
}

static void test_create_flag_exists(struct lsm_xattr_file *skel)
{
	char buf[64] = {};

	reset(skel);
	if (!ASSERT_OK(setxattr(FILE, DATA, "there", sizeof("there"), 0),
		       "set data"))
		return;
	if (!ASSERT_OK(aim(skel, FILE, OP_SET_CREATE), "aim"))
		return;
	ASSERT_OK(trigger_open(FILE), "open");
	ASSERT_EQ(skel->bss->set_ret, -EEXIST, "set_ret");
	if (ASSERT_EQ(get_xattr(FILE, DATA, buf, sizeof(buf)), sizeof("there"),
		      "value length"))
		ASSERT_STREQ(buf, "there", "value kept");
}

static void test_replace_flag_missing(struct lsm_xattr_file *skel)
{
	char buf[64] = {};

	reset(skel);
	if (!ASSERT_OK(aim(skel, FILE, OP_SET_REPLACE), "aim"))
		return;
	ASSERT_OK(trigger_open(FILE), "open");
	ASSERT_EQ(skel->bss->set_ret, -ENODATA, "set_ret");
	ASSERT_EQ(get_xattr(FILE, DATA, buf, sizeof(buf)), -ENODATA,
		  "nothing created");
}

static void test_empty_value(struct lsm_xattr_file *skel)
{
	char buf[64] = {};

	reset(skel);
	if (!ASSERT_OK(aim(skel, FILE, OP_SET_EMPTY), "aim"))
		return;
	ASSERT_OK(trigger_open(FILE), "open");
	ASSERT_OK(skel->bss->set_ret, "set_ret");
	ASSERT_EQ(get_xattr(FILE, DATA, buf, sizeof(buf)), 0, "empty value");

	skel->bss->op = OP_GET;
	ASSERT_OK(trigger_open(FILE), "open again");
	ASSERT_EQ(skel->bss->get_ret, 0, "get_ret");
}

static void test_missing(struct lsm_xattr_file *skel)
{
	reset(skel);
	if (!ASSERT_OK(aim(skel, FILE, OP_GET_MISSING), "aim"))
		return;
	ASSERT_OK(trigger_open(FILE), "open");
	ASSERT_EQ(skel->bss->get_ret, -ENODATA, "get_ret");
}

static void test_short_buffer(struct lsm_xattr_file *skel)
{
	char buf[64] = {};

	reset(skel);
	if (!ASSERT_OK(setxattr(FILE, DATA, HELLO, sizeof(HELLO), 0), "set data"))
		return;
	if (!ASSERT_OK(aim(skel, FILE, OP_GET_SHORT), "aim"))
		return;
	ASSERT_OK(trigger_open(FILE), "open");
	ASSERT_EQ(skel->bss->get_ret, -ERANGE, "get_ret");
	ASSERT_EQ(get_xattr(FILE, DATA, buf, 1), -ERANGE, "userspace short buffer");
}

static void test_user_prefix_set_refused(struct lsm_xattr_file *skel)
{
	char buf[64] = {};

	reset(skel);
	if (!ASSERT_OK(aim(skel, FILE, OP_SET_USER), "aim"))
		return;
	ASSERT_OK(trigger_open(FILE), "open");
	ASSERT_EQ(skel->bss->set_ret, -EPERM, "set_ret");
	ASSERT_EQ(get_xattr(FILE, USER, buf, sizeof(buf)), -ENODATA,
		  "nothing written");
}

static void test_foreign_name_refused(struct lsm_xattr_file *skel)
{
	char buf[64] = {};

	reset(skel);
	if (!ASSERT_OK(aim(skel, FILE, OP_FOREIGN), "aim"))
		return;
	ASSERT_OK(trigger_open(FILE), "open");
	ASSERT_EQ(skel->bss->get_ret, -EPERM, "get_ret");
	ASSERT_EQ(skel->bss->set_ret, -EPERM, "set_ret");
	ASSERT_EQ(get_xattr(FILE, "security.selinux", buf, sizeof(buf)),
		  -ENODATA, "nothing written");
}

static void test_no_xattr_fs(struct lsm_xattr_file *skel)
{
	reset(skel);
	if (!ASSERT_OK(mkdir(RAMFS, 0755), "mkdir ramfs"))
		return;
	if (!ASSERT_OK(mount("ramfs", RAMFS, "ramfs", 0, NULL) ? -errno : 0,
		       "mount ramfs"))
		goto out;
	if (!ASSERT_OK(make_file(RAMFS_FILE), "create on ramfs"))
		goto out_umount;
	if (!ASSERT_OK(aim(skel, RAMFS_FILE, OP_NO_XATTR_FS), "aim"))
		goto out_file;

	ASSERT_OK(trigger_open(RAMFS_FILE), "open");
	ASSERT_EQ(skel->bss->get_ret, -EOPNOTSUPP, "get_ret");
	ASSERT_EQ(skel->bss->set_ret, -EOPNOTSUPP, "set_ret");
	/* Userspace is turned away by the same filesystem. */
	ASSERT_EQ(setxattr(RAMFS_FILE, DATA, HELLO, sizeof(HELLO), 0) ? -errno : 0,
		  -EOPNOTSUPP, "userspace set");
out_file:
	skel->bss->op = OP_NONE;
	remove(RAMFS_FILE);
out_umount:
	umount(RAMFS);
out:
	remove(RAMFS);
}

static void test_claim_on_write(struct lsm_xattr_file *skel)
{
	char buf[64] = {};
	int fd;

	reset(skel);
	/* Opened before the policy is aimed: nothing is claimed at open. */
	fd = open(FILE, O_RDWR);
	if (!ASSERT_OK_FD(fd, "open"))
		return;
	if (!ASSERT_OK(aim(skel, FILE, OP_CLAIM), "aim"))
		goto out;

	ASSERT_EQ(write(fd, "x", 1), 1, "write");
	ASSERT_EQ(skel->bss->claims, 1, "claims");
	ASSERT_OK(skel->bss->set_ret, "set_ret");
	if (ASSERT_EQ(get_xattr(FILE, CLAIM, buf, sizeof(buf)), sizeof("1"),
		      "claim length"))
		ASSERT_STREQ(buf, "1", "claim");

	/* A read leaves the file alone. */
	ASSERT_OK(removexattr(FILE, CLAIM), "drop claim");
	ASSERT_EQ(lseek(fd, 0, SEEK_SET), 0, "rewind");
	ASSERT_EQ(read(fd, buf, 1), 1, "read");
	ASSERT_EQ(skel->bss->claims, 1, "claims after read");
	ASSERT_EQ(get_xattr(FILE, CLAIM, buf, sizeof(buf)), -ENODATA,
		  "not claimed by a read");
out:
	skel->bss->op = OP_NONE;
	close(fd);
}

static void test_read_on_receive(struct lsm_xattr_file *skel)
{
	int sv[2] = { -1, -1 }, fd;
	pid_t pid;

	reset(skel);
	if (!ASSERT_OK(make_file(PLAIN), "create plain") ||
	    !ASSERT_OK(make_file(SEALED), "create sealed") ||
	    !ASSERT_OK(setxattr(SEALED, DATA, "sealed", sizeof("sealed"), 0),
		       "seal it"))
		goto out;
	if (!ASSERT_OK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) ? -errno : 0,
		       "socketpair"))
		goto out;

	pid = fork();
	if (!ASSERT_GE(pid, 0, "fork"))
		goto out;
	if (pid == 0) {
		int a = open(PLAIN, O_RDONLY);
		int b = open(SEALED, O_RDONLY);

		close(sv[0]);
		if (a < 0 || b < 0 || send_fd(sv[1], a) || send_fd(sv[1], b))
			_exit(1);
		_exit(0);
	}

	skel->bss->op = OP_RECEIVE;
	fd = recv_fd(sv[0]);
	if (ASSERT_OK_FD(fd, "unlabelled descriptor received"))
		close(fd);
	ASSERT_EQ(recv_fd(sv[0]), -ENOMSG, "sealed descriptor refused");
	ASSERT_EQ(skel->bss->recv_seen, 1, "recv_seen");
	ASSERT_EQ(skel->bss->recv_denied, 1, "recv_denied");
	skel->bss->op = OP_NONE;
	waitpid(pid, NULL, 0);
out:
	if (sv[0] >= 0)
		close(sv[0]);
	if (sv[1] >= 0)
		close(sv[1]);
	remove(PLAIN);
	remove(SEALED);
}

static void cleanup(void)
{
	umount(RAMFS);
	remove(RAMFS_FILE);
	remove(RAMFS);
	remove(PLAIN);
	remove(SEALED);
	remove(FILE);
	remove(BASE);
}

void test_lsm_xattr_file(void)
{
	struct lsm_xattr_file *skel = NULL;
	int err;

	cleanup();
	if (!ASSERT_OK(mkdir(BASE, 0755), "mkdir base") ||
	    !ASSERT_OK(make_file(FILE), "create file"))
		goto out;

	err = setxattr(FILE, DATA, HELLO, sizeof(HELLO), 0);
	if (err && errno == EOPNOTSUPP) {
		printf("%s:SKIP:local fs doesn't support xattr (%d)\n"
		       "To run this test, make sure /tmp filesystem supports xattr.\n",
		       __func__, errno);
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(err, "setxattr"))
		goto out;

	skel = lsm_xattr_file__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open and load"))
		goto out;
	skel->bss->monitored_pid = getpid();
	if (!ASSERT_OK(lsm_xattr_file__attach(skel), "attach"))
		goto out;

	if (test__start_subtest("set_on_open"))
		test_set_on_open(skel);
	if (test__start_subtest("remove_on_open"))
		test_remove_on_open(skel);
	if (test__start_subtest("get"))
		test_get(skel);
	if (test__start_subtest("create_flag_exists"))
		test_create_flag_exists(skel);
	if (test__start_subtest("replace_flag_missing"))
		test_replace_flag_missing(skel);
	if (test__start_subtest("empty_value"))
		test_empty_value(skel);
	if (test__start_subtest("missing"))
		test_missing(skel);
	if (test__start_subtest("short_buffer"))
		test_short_buffer(skel);
	if (test__start_subtest("user_prefix_set_refused"))
		test_user_prefix_set_refused(skel);
	if (test__start_subtest("foreign_name_refused"))
		test_foreign_name_refused(skel);
	if (test__start_subtest("no_xattr_fs"))
		test_no_xattr_fs(skel);
	if (test__start_subtest("claim_on_write"))
		test_claim_on_write(skel);
	if (test__start_subtest("read_on_receive"))
		test_read_on_receive(skel);
out:
	lsm_xattr_file__destroy(skel);
	cleanup();
}
