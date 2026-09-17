// SPDX-License-Identifier: GPL-2.0
/*
 * A policy that hands a directory's label down to what is created in it: the
 * path hooks read security.bpf.label off the parent's dentry, reachable
 * through the trusted struct path, and inode_init_security attaches it to the
 * new inode as it is created. The same hooks write to the dentry they were
 * handed, which is locked there, so the writers are fixed up to their locked
 * variants.
 */
#include <fcntl.h>
#include <ftw.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <test_progs.h>
#include "lsm_xattr_path.skel.h"

#define BASE		"/tmp/test_progs_xattr_path"
#define D_MKDIR		BASE "/mkdir"
#define D_CREATE	BASE "/create"
#define D_MKNOD		BASE "/mknod"
#define D_SYMLINK	BASE "/symlink"
#define D_GRAND		BASE "/grand"
#define D_RELABEL	BASE "/relabel"
#define D_PLAIN		BASE "/plain"
#define D_STAMP		BASE "/stamp"
#define D_CHMOD		BASE "/chmod"
#define D_CHOWN		BASE "/chown"

#define LABEL		"security.bpf.label"
#define STAMP		"security.bpf.stamp"
#define ALPHA		"alpha"
#define BETA		"beta"

static int rm(const char *path, const struct stat *st, int type,
	      struct FTW *ftw)
{
	return remove(path);
}

static void rmtree(const char *path)
{
	nftw(path, rm, 8, FTW_DEPTH | FTW_PHYS | FTW_MOUNT);
}

/* A fresh directory, labelled or not, to create things in. */
static int make_parent(const char *path, const char *label)
{
	rmtree(path);
	if (mkdir(path, 0755))
		return -errno;
	if (!label)
		return 0;
	return setxattr(path, LABEL, label, strlen(label) + 1, 0) ? -errno : 0;
}

static int make_file(const char *path)
{
	int fd = open(path, O_CREAT | O_WRONLY, 0644);

	if (fd < 0)
		return -errno;
	close(fd);
	return 0;
}

/* The label of @path itself, a symlink included. */
static void assert_label(const char *path, const char *want, const char *what)
{
	char buf[64] = {};
	int len = lgetxattr(path, LABEL, buf, sizeof(buf) - 1);

	if (want) {
		if (ASSERT_EQ(len < 0 ? -errno : len, (int)strlen(want) + 1, what))
			ASSERT_STREQ(buf, want, what);
	} else {
		ASSERT_EQ(len < 0 ? -errno : len, -ENODATA, what);
	}
}

static void assert_stamped(const char *path, const char *what)
{
	char buf[64] = {};

	if (ASSERT_EQ(lgetxattr(path, STAMP, buf, sizeof(buf) - 1), 2, what))
		ASSERT_STREQ(buf, "1", what);
}

static void reset(struct lsm_xattr_path *skel)
{
	skel->bss->remembered = 0;
	skel->bss->inherited = 0;
	skel->bss->init_err = 0;
	skel->bss->stamp_err = 0;
}

static void test_inherit_mkdir(struct lsm_xattr_path *skel)
{
	if (!ASSERT_OK(make_parent(D_MKDIR, ALPHA), "make parent"))
		return;
	reset(skel);
	ASSERT_OK(mkdir(D_MKDIR "/child", 0755), "mkdir child");
	assert_label(D_MKDIR "/child", ALPHA, "child inherits");
	ASSERT_EQ(skel->bss->remembered, 1, "remembered");
	ASSERT_EQ(skel->bss->inherited, 1, "inherited");
	ASSERT_OK(skel->bss->init_err, "init_err");
	rmtree(D_MKDIR);
}

/* O_CREAT goes through path_mknod, not path_mkdir. */
static void test_inherit_create(struct lsm_xattr_path *skel)
{
	if (!ASSERT_OK(make_parent(D_CREATE, ALPHA), "make parent"))
		return;
	reset(skel);
	ASSERT_OK(make_file(D_CREATE "/file"), "create file");
	assert_label(D_CREATE "/file", ALPHA, "file inherits");
	ASSERT_EQ(skel->bss->inherited, 1, "inherited");
	ASSERT_OK(skel->bss->init_err, "init_err");
	rmtree(D_CREATE);
}

static void test_inherit_mknod(struct lsm_xattr_path *skel)
{
	if (!ASSERT_OK(make_parent(D_MKNOD, ALPHA), "make parent"))
		return;
	reset(skel);
	ASSERT_OK(mknod(D_MKNOD "/fifo", S_IFIFO | 0644, 0) ? -errno : 0,
		  "mknod fifo");
	assert_label(D_MKNOD "/fifo", ALPHA, "fifo inherits");
	ASSERT_EQ(skel->bss->inherited, 1, "inherited");
	rmtree(D_MKNOD);
}

static void test_inherit_symlink(struct lsm_xattr_path *skel)
{
	if (!ASSERT_OK(make_parent(D_SYMLINK, ALPHA), "make parent"))
		return;
	reset(skel);
	ASSERT_OK(symlink("target", D_SYMLINK "/link") ? -errno : 0, "symlink");
	assert_label(D_SYMLINK "/link", ALPHA, "symlink inherits");
	ASSERT_EQ(skel->bss->inherited, 1, "inherited");
	rmtree(D_SYMLINK);
}

/* Two levels down the label comes off the child's own persisted label. */
static void test_inherit_grandchild(struct lsm_xattr_path *skel)
{
	if (!ASSERT_OK(make_parent(D_GRAND, ALPHA), "make parent"))
		return;
	reset(skel);
	ASSERT_OK(mkdir(D_GRAND "/child", 0755), "mkdir child");
	ASSERT_OK(mkdir(D_GRAND "/child/grandchild", 0755), "mkdir grandchild");
	assert_label(D_GRAND "/child", ALPHA, "child inherits");
	assert_label(D_GRAND "/child/grandchild", ALPHA, "grandchild inherits");
	ASSERT_EQ(skel->bss->remembered, 2, "remembered");
	ASSERT_EQ(skel->bss->inherited, 2, "inherited");
	rmtree(D_GRAND);
}

/* The label is read from the parent at creation and nothing is cached. */
static void test_relabel_midway(struct lsm_xattr_path *skel)
{
	if (!ASSERT_OK(make_parent(D_RELABEL, ALPHA), "make parent"))
		return;
	reset(skel);
	ASSERT_OK(mkdir(D_RELABEL "/first", 0755), "mkdir first");
	assert_label(D_RELABEL "/first", ALPHA, "first inherits");
	ASSERT_OK(setxattr(D_RELABEL, LABEL, BETA, sizeof(BETA), 0), "relabel");
	ASSERT_OK(mkdir(D_RELABEL "/later", 0755), "mkdir later");
	assert_label(D_RELABEL "/later", BETA, "later inherits the new label");
	rmtree(D_RELABEL);
}

static void test_unlabelled_parent(struct lsm_xattr_path *skel)
{
	if (!ASSERT_OK(make_parent(D_PLAIN, NULL), "make parent"))
		return;
	reset(skel);
	ASSERT_OK(mkdir(D_PLAIN "/child", 0755), "mkdir child");
	assert_label(D_PLAIN "/child", NULL, "child unlabelled");
	ASSERT_EQ(skel->bss->remembered, 0, "remembered");
	ASSERT_EQ(skel->bss->inherited, 0, "inherited");
	rmtree(D_PLAIN);
}

/* Written onto the locked parent from path_mkdir without deadlocking. */
static void test_write_parent(struct lsm_xattr_path *skel)
{
	if (!ASSERT_OK(make_parent(D_STAMP, ALPHA), "make parent"))
		return;
	reset(skel);
	ASSERT_OK(mkdir(D_STAMP "/child", 0755), "mkdir child");
	ASSERT_OK(skel->bss->stamp_err, "stamp_err");
	assert_stamped(D_STAMP, "parent stamped");
	rmtree(D_STAMP);
}

/* path_chmod is called with the path's own inode locked. */
static void test_write_on_chmod(struct lsm_xattr_path *skel)
{
	struct stat st;

	if (!ASSERT_OK(make_parent(D_CHMOD, NULL), "make parent") ||
	    !ASSERT_OK(make_file(D_CHMOD "/file"), "create file"))
		return;
	reset(skel);
	ASSERT_OK(chmod(D_CHMOD "/file", 0600) ? -errno : 0, "chmod");
	ASSERT_OK(skel->bss->stamp_err, "stamp_err");
	assert_stamped(D_CHMOD "/file", "file stamped");
	if (ASSERT_OK(stat(D_CHMOD "/file", &st) ? -errno : 0, "stat"))
		ASSERT_EQ(st.st_mode & 07777, 0600, "mode changed");
	rmtree(D_CHMOD);
}

/* And so is path_chown. */
static void test_write_on_chown(struct lsm_xattr_path *skel)
{
	struct stat st;

	if (!ASSERT_OK(make_parent(D_CHOWN, NULL), "make parent") ||
	    !ASSERT_OK(make_file(D_CHOWN "/file"), "create file"))
		return;
	reset(skel);
	ASSERT_OK(chown(D_CHOWN "/file", 1, 1) ? -errno : 0, "chown");
	ASSERT_OK(skel->bss->stamp_err, "stamp_err");
	assert_stamped(D_CHOWN "/file", "file stamped");
	if (ASSERT_OK(stat(D_CHOWN "/file", &st) ? -errno : 0, "stat")) {
		ASSERT_EQ(st.st_uid, 1, "owner changed");
		ASSERT_EQ(st.st_gid, 1, "group changed");
	}
	rmtree(D_CHOWN);
}

void test_lsm_xattr_path(void)
{
	struct lsm_xattr_path *skel = NULL;
	int err;

	rmtree(BASE);
	if (!ASSERT_OK(mkdir(BASE, 0755), "mkdir base"))
		goto out;

	err = setxattr(BASE, LABEL, ALPHA, sizeof(ALPHA), 0);
	if (err && errno == EOPNOTSUPP) {
		printf("%s:SKIP:local fs doesn't support xattr (%d)\n"
		       "To run this test, make sure /tmp filesystem supports xattr.\n",
		       __func__, errno);
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(err, "setxattr") ||
	    !ASSERT_OK(removexattr(BASE, LABEL), "unlabel base"))
		goto out;

	skel = lsm_xattr_path__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open and load"))
		goto out;
	skel->bss->monitored_pid = getpid();
	if (!ASSERT_OK(lsm_xattr_path__attach(skel), "attach"))
		goto out;

	if (test__start_subtest("inherit_mkdir"))
		test_inherit_mkdir(skel);
	if (test__start_subtest("inherit_create"))
		test_inherit_create(skel);
	if (test__start_subtest("inherit_mknod"))
		test_inherit_mknod(skel);
	if (test__start_subtest("inherit_symlink"))
		test_inherit_symlink(skel);
	if (test__start_subtest("inherit_grandchild"))
		test_inherit_grandchild(skel);
	if (test__start_subtest("relabel_midway"))
		test_relabel_midway(skel);
	if (test__start_subtest("unlabelled_parent"))
		test_unlabelled_parent(skel);
	if (test__start_subtest("write_parent"))
		test_write_parent(skel);
	if (test__start_subtest("write_on_chmod"))
		test_write_on_chmod(skel);
	if (test__start_subtest("write_on_chown"))
		test_write_on_chown(skel);
out:
	lsm_xattr_path__destroy(skel);
	rmtree(BASE);
}
