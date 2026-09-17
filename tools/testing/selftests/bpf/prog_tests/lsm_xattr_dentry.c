// SPDX-License-Identifier: GPL-2.0
/*
 * The dentry xattr kfuncs, driven from a policy on inode_getxattr keyed by
 * the name being read, so that only the runner's trigger reaches it: what
 * the setter, the getter and the remover do to a file, the names they
 * refuse, the errors they report, and that the writers do not deadlock when
 * the hook already holds i_rwsem.
 */
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <test_progs.h>
#include "lsm_xattr_dentry.skel.h"

#define BASE		"/tmp/test_progs_xattr_dentry"
#define FILE		BASE "/file"
#define NEW		BASE "/new"
#define RAMFS		BASE "_ramfs"
#define RAMFS_FILE	RAMFS "/file"

#define TRIGGER		"security.bpf.trigger"
#define DATA		"security.bpf.data"
#define USER		"user.data"
#define HELLO		"hello"

enum {
	OP_NONE,
	OP_SET,
	OP_GET,
	OP_REMOVE,
	OP_SET_CREATE,
	OP_SET_REPLACE,
	OP_SET_EMPTY,
	OP_GET_MISSING,
	OP_GET_SHORT,
	OP_SET_USER,
	OP_FOREIGN,
	OP_NEGATIVE,
	OP_NO_XATTR_FS,
	OP_LOCKED_SET,
	OP_LOCKED_REMOVE,
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

/* Fire inode_getxattr on @path. The read itself finds nothing; the policy
 * runs before that.
 */
static void trigger_get(const char *path)
{
	char buf[64];

	getxattr(path, TRIGGER, buf, sizeof(buf));
}

/* Fire inode_setxattr on @path: 0 or -errno. */
static int trigger_set(const char *path)
{
	return setxattr(path, TRIGGER, "1", 2, 0) ? -errno : 0;
}

static void reset(struct lsm_xattr_dentry *skel)
{
	removexattr(FILE, DATA);
	removexattr(FILE, USER);
	skel->bss->get_ret = 0;
	skel->bss->set_ret = 0;
	skel->bss->remove_ret = 0;
	memset(skel->bss->read_value, 0, sizeof(skel->bss->read_value));
	skel->bss->op = OP_NONE;
}

static void test_set_and_get(struct lsm_xattr_dentry *skel)
{
	char buf[64] = {};

	reset(skel);
	skel->bss->op = OP_SET;
	trigger_get(FILE);
	ASSERT_OK(skel->bss->set_ret, "set_ret");
	if (ASSERT_EQ(get_xattr(FILE, DATA, buf, sizeof(buf)), sizeof(HELLO),
		      "value length"))
		ASSERT_STREQ(buf, HELLO, "value");

	skel->bss->op = OP_GET;
	trigger_get(FILE);
	ASSERT_EQ(skel->bss->get_ret, sizeof(HELLO), "get_ret");
	ASSERT_STREQ(skel->bss->read_value, HELLO, "read back");
}

static void test_remove(struct lsm_xattr_dentry *skel)
{
	char buf[64] = {};

	reset(skel);
	if (!ASSERT_OK(setxattr(FILE, DATA, HELLO, sizeof(HELLO), 0), "set data"))
		return;
	skel->bss->op = OP_REMOVE;
	trigger_get(FILE);
	ASSERT_OK(skel->bss->remove_ret, "remove_ret");
	ASSERT_EQ(get_xattr(FILE, DATA, buf, sizeof(buf)), -ENODATA, "gone");
}

static void test_create_flag_exists(struct lsm_xattr_dentry *skel)
{
	char buf[64] = {};

	reset(skel);
	if (!ASSERT_OK(setxattr(FILE, DATA, "there", sizeof("there"), 0),
		       "set data"))
		return;
	skel->bss->op = OP_SET_CREATE;
	trigger_get(FILE);
	ASSERT_EQ(skel->bss->set_ret, -EEXIST, "set_ret");
	/* The value the flag protected is untouched. */
	if (ASSERT_EQ(get_xattr(FILE, DATA, buf, sizeof(buf)), sizeof("there"),
		      "value length"))
		ASSERT_STREQ(buf, "there", "value kept");
}

static void test_replace_flag_missing(struct lsm_xattr_dentry *skel)
{
	char buf[64] = {};

	reset(skel);
	skel->bss->op = OP_SET_REPLACE;
	trigger_get(FILE);
	ASSERT_EQ(skel->bss->set_ret, -ENODATA, "set_ret");
	ASSERT_EQ(get_xattr(FILE, DATA, buf, sizeof(buf)), -ENODATA,
		  "nothing created");
}

static void test_empty_value(struct lsm_xattr_dentry *skel)
{
	char buf[64] = {};

	reset(skel);
	skel->bss->op = OP_SET_EMPTY;
	trigger_get(FILE);
	ASSERT_OK(skel->bss->set_ret, "set_ret");
	ASSERT_EQ(get_xattr(FILE, DATA, buf, sizeof(buf)), 0, "empty value");

	skel->bss->op = OP_GET;
	trigger_get(FILE);
	ASSERT_EQ(skel->bss->get_ret, 0, "get_ret");
}

static void test_missing(struct lsm_xattr_dentry *skel)
{
	reset(skel);
	skel->bss->op = OP_GET_MISSING;
	trigger_get(FILE);
	ASSERT_EQ(skel->bss->get_ret, -ENODATA, "get_ret");
}

static void test_short_buffer(struct lsm_xattr_dentry *skel)
{
	char buf[64] = {};

	reset(skel);
	if (!ASSERT_OK(setxattr(FILE, DATA, HELLO, sizeof(HELLO), 0), "set data"))
		return;
	skel->bss->op = OP_GET_SHORT;
	trigger_get(FILE);
	ASSERT_EQ(skel->bss->get_ret, -ERANGE, "get_ret");
	/* Userspace sees the same refusal for the same buffer. */
	ASSERT_EQ(get_xattr(FILE, DATA, buf, 1), -ERANGE, "userspace short buffer");
}

static void test_user_prefix_set_refused(struct lsm_xattr_dentry *skel)
{
	char buf[64] = {};

	reset(skel);
	skel->bss->op = OP_SET_USER;
	trigger_get(FILE);
	ASSERT_EQ(skel->bss->set_ret, -EPERM, "set_ret");
	ASSERT_EQ(get_xattr(FILE, USER, buf, sizeof(buf)), -ENODATA,
		  "nothing written");
}

static void test_foreign_name_refused(struct lsm_xattr_dentry *skel)
{
	char buf[64] = {};

	reset(skel);
	skel->bss->op = OP_FOREIGN;
	trigger_get(FILE);
	ASSERT_EQ(skel->bss->get_ret, -EPERM, "get_ret");
	ASSERT_EQ(skel->bss->set_ret, -EPERM, "set_ret");
	ASSERT_EQ(get_xattr(FILE, "security.selinux", buf, sizeof(buf)),
		  -ENODATA, "nothing written");
}

static void test_negative_dentry(struct lsm_xattr_dentry *skel)
{
	int fd;

	reset(skel);
	remove(NEW);
	skel->bss->op = OP_NEGATIVE;
	fd = open(NEW, O_CREAT | O_WRONLY, 0644);
	if (ASSERT_OK_FD(fd, "create"))
		close(fd);
	ASSERT_EQ(skel->bss->get_ret, -EINVAL, "get_ret");
	ASSERT_EQ(skel->bss->set_ret, -EINVAL, "set_ret");
	ASSERT_EQ(skel->bss->remove_ret, -EINVAL, "remove_ret");
	skel->bss->op = OP_NONE;
	remove(NEW);
}

static void test_no_xattr_fs(struct lsm_xattr_dentry *skel)
{
	reset(skel);
	if (!ASSERT_OK(mkdir(RAMFS, 0755), "mkdir ramfs"))
		return;
	if (!ASSERT_OK(mount("ramfs", RAMFS, "ramfs", 0, NULL) ? -errno : 0,
		       "mount ramfs"))
		goto out;
	if (!ASSERT_OK(make_file(RAMFS_FILE), "create on ramfs"))
		goto out_umount;

	skel->bss->op = OP_NO_XATTR_FS;
	trigger_get(RAMFS_FILE);
	ASSERT_EQ(skel->bss->get_ret, -EOPNOTSUPP, "get_ret");
	ASSERT_EQ(skel->bss->set_ret, -EOPNOTSUPP, "set_ret");
	/* Userspace is turned away by the same filesystem. */
	ASSERT_EQ(setxattr(RAMFS_FILE, DATA, HELLO, sizeof(HELLO), 0) ? -errno : 0,
		  -EOPNOTSUPP, "userspace set");
	skel->bss->op = OP_NONE;
	remove(RAMFS_FILE);
out_umount:
	umount(RAMFS);
out:
	remove(RAMFS);
}

static void test_locked_hook(struct lsm_xattr_dentry *skel)
{
	char buf[64] = {};

	reset(skel);
	skel->bss->op = OP_LOCKED_SET;
	ASSERT_OK(trigger_set(FILE), "setxattr returns");
	ASSERT_OK(skel->bss->set_ret, "set_ret");
	if (ASSERT_EQ(get_xattr(FILE, DATA, buf, sizeof(buf)), sizeof(HELLO),
		      "value length"))
		ASSERT_STREQ(buf, HELLO, "value");

	skel->bss->op = OP_LOCKED_REMOVE;
	ASSERT_OK(trigger_set(FILE), "setxattr returns");
	ASSERT_OK(skel->bss->remove_ret, "remove_ret");
	ASSERT_EQ(get_xattr(FILE, DATA, buf, sizeof(buf)), -ENODATA, "gone");
	skel->bss->op = OP_NONE;
}

static void cleanup(void)
{
	umount(RAMFS);
	remove(RAMFS_FILE);
	remove(RAMFS);
	remove(NEW);
	remove(FILE);
	remove(BASE);
}

void test_lsm_xattr_dentry(void)
{
	struct lsm_xattr_dentry *skel = NULL;
	int err;

	cleanup();
	if (!ASSERT_OK(mkdir(BASE, 0755), "mkdir base") ||
	    !ASSERT_OK(make_file(FILE), "create file"))
		goto out;

	err = setxattr(FILE, TRIGGER, "1", 2, 0);
	if (err && errno == EOPNOTSUPP) {
		printf("%s:SKIP:local fs doesn't support xattr (%d)\n"
		       "To run this test, make sure /tmp filesystem supports xattr.\n",
		       __func__, errno);
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(err, "setxattr"))
		goto out;

	skel = lsm_xattr_dentry__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open and load"))
		goto out;
	skel->bss->monitored_pid = getpid();
	if (!ASSERT_OK(lsm_xattr_dentry__attach(skel), "attach"))
		goto out;

	if (test__start_subtest("set_and_get"))
		test_set_and_get(skel);
	if (test__start_subtest("remove"))
		test_remove(skel);
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
	if (test__start_subtest("negative_dentry"))
		test_negative_dentry(skel);
	if (test__start_subtest("no_xattr_fs"))
		test_no_xattr_fs(skel);
	if (test__start_subtest("locked_hook"))
		test_locked_hook(skel);
out:
	lsm_xattr_dentry__destroy(skel);
	cleanup();
}
