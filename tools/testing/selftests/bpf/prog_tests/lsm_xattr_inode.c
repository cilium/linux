// SPDX-License-Identifier: GPL-2.0
/*
 * The inode xattr getter, from the hooks that hand out an inode: through the
 * dentry d_instantiate supplies before it is attached, through an alias
 * looked up for the parent of a create, and refused when a dentry of another
 * inode is passed. The last case is the policy this is for: a label loaded
 * as the dentry is instantiated and enforced from inode_permission, which
 * cannot read the xattr itself.
 */
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <test_progs.h>
#include "lsm_xattr_inode.skel.h"

#define BASE		"/tmp/test_progs_xattr_inode"
#define FILE		BASE "/file"
#define LINK		BASE "/link"
#define RENAMED		BASE "/renamed"
#define DIR		BASE "/dir"
#define CREATED		BASE "/created"
#define DENY		BASE "/deny"
#define DENY_LINK	BASE "/deny_link"
#define ALLOW		BASE "/allow"
#define ALLOW_LINK	BASE "/allow_link"

#define LABEL		"security.bpf.label"
#define ALPHA		"alpha"
#define PARENT		"parent"

enum {
	OP_NONE,
	OP_READ,
	OP_MISSING,
	OP_SHORT,
	OP_PARENT,
	OP_RENAME,
	OP_ENFORCE,
};

static int make_file(const char *path)
{
	int fd = open(path, O_CREAT | O_WRONLY, 0644);

	if (fd < 0)
		return -errno;
	close(fd);
	return 0;
}

static int make_labelled(const char *path, const char *label)
{
	int err = make_file(path);

	if (err)
		return err;
	return setxattr(path, LABEL, label, strlen(label) + 1, 0) ? -errno : 0;
}

static int try_open(const char *path)
{
	int fd = open(path, O_RDONLY);

	if (fd < 0)
		return -errno;
	close(fd);
	return 0;
}

static int exists(const char *path)
{
	struct stat st;

	return stat(path, &st) ? -errno : 0;
}

static void reset(struct lsm_xattr_inode *skel)
{
	skel->bss->read_ret = 0;
	skel->bss->mkdir_ret = 0;
	skel->bss->create_ret = 0;
	skel->bss->rename_ret = 0;
	skel->bss->instantiated = 0;
	skel->bss->denied = 0;
	memset(skel->bss->read_value, 0, sizeof(skel->bss->read_value));
	memset(skel->bss->parent_value, 0, sizeof(skel->bss->parent_value));
	skel->bss->op = OP_NONE;
}

static void test_read_at_instantiate(struct lsm_xattr_inode *skel)
{
	reset(skel);
	remove(LINK);
	skel->bss->op = OP_READ;
	/* A link instantiates a fresh dentry for the labelled inode. */
	ASSERT_OK(link(FILE, LINK) ? -errno : 0, "link");
	skel->bss->op = OP_NONE;
	ASSERT_EQ(skel->bss->read_ret, sizeof(ALPHA), "read_ret");
	ASSERT_STREQ(skel->bss->read_value, ALPHA, "label read");
	ASSERT_OK(exists(LINK), "link created");
	remove(LINK);
}

static void test_read_parent_null_dentry(struct lsm_xattr_inode *skel)
{
	reset(skel);
	remove(DIR);
	remove(CREATED);
	if (!ASSERT_OK(setxattr(BASE, LABEL, PARENT, sizeof(PARENT), 0),
		       "label parent"))
		return;

	skel->bss->op = OP_PARENT;
	ASSERT_OK(mkdir(DIR, 0755), "mkdir");
	ASSERT_EQ(skel->bss->mkdir_ret, sizeof(PARENT), "mkdir_ret");
	ASSERT_STREQ(skel->bss->parent_value, PARENT, "parent label at mkdir");

	memset(skel->bss->parent_value, 0, sizeof(skel->bss->parent_value));
	ASSERT_OK(make_file(CREATED), "create");
	ASSERT_EQ(skel->bss->create_ret, sizeof(PARENT), "create_ret");
	ASSERT_STREQ(skel->bss->parent_value, PARENT, "parent label at create");
	skel->bss->op = OP_NONE;

	ASSERT_OK(exists(DIR), "dir created");
	ASSERT_OK(exists(CREATED), "file created");
	remove(DIR);
	remove(CREATED);
	removexattr(BASE, LABEL);
}

static void test_mismatched_dentry(struct lsm_xattr_inode *skel)
{
	reset(skel);
	remove(RENAMED);
	skel->bss->op = OP_RENAME;
	ASSERT_OK(rename(FILE, RENAMED) ? -errno : 0, "rename");
	skel->bss->op = OP_NONE;
	/* old_dentry is not a dentry of old_dir, so nothing is read. */
	ASSERT_EQ(skel->bss->rename_ret, -EINVAL, "rename_ret");
	ASSERT_OK(exists(RENAMED), "new name");
	ASSERT_EQ(exists(FILE), -ENOENT, "old name gone");
	ASSERT_OK(rename(RENAMED, FILE) ? -errno : 0, "rename back");
}

static void test_missing(struct lsm_xattr_inode *skel)
{
	reset(skel);
	remove(LINK);
	skel->bss->op = OP_MISSING;
	ASSERT_OK(link(FILE, LINK) ? -errno : 0, "link");
	skel->bss->op = OP_NONE;
	ASSERT_EQ(skel->bss->read_ret, -ENODATA, "read_ret");
	remove(LINK);
}

static void test_short_buffer(struct lsm_xattr_inode *skel)
{
	char buf[64] = {};

	reset(skel);
	remove(LINK);
	skel->bss->op = OP_SHORT;
	ASSERT_OK(link(FILE, LINK) ? -errno : 0, "link");
	skel->bss->op = OP_NONE;
	ASSERT_EQ(skel->bss->read_ret, -ERANGE, "read_ret");
	/* Userspace is turned away by the same buffer. */
	ASSERT_EQ(getxattr(FILE, LABEL, buf, 1) < 0 ? -errno : 0, -ERANGE,
		  "userspace short buffer");
	remove(LINK);
}

/* Two files are labelled before the policy looks at them; linking them
 * instantiates a fresh dentry for each inode under the policy, and from then
 * on the inode is refused through either name.
 */
static void test_load_then_enforce(struct lsm_xattr_inode *skel)
{
	reset(skel);
	remove(DENY_LINK);
	remove(ALLOW_LINK);
	remove(DENY);
	remove(ALLOW);
	if (!ASSERT_OK(make_labelled(DENY, "deny"), "make deny") ||
	    !ASSERT_OK(make_labelled(ALLOW, "allow"), "make allow"))
		goto out;

	skel->bss->op = OP_ENFORCE;
	/* Instantiated before the policy: the inode is unknown to it. */
	ASSERT_OK(try_open(DENY), "deny before instantiate: allowed");
	ASSERT_OK(link(DENY, DENY_LINK) ? -errno : 0, "link deny");
	ASSERT_OK(link(ALLOW, ALLOW_LINK) ? -errno : 0, "link allow");
	ASSERT_EQ(skel->bss->instantiated, 2, "instantiated");
	ASSERT_EQ(try_open(DENY_LINK), -EPERM, "deny link: denied");
	ASSERT_EQ(try_open(DENY), -EPERM, "deny through the old name: denied");
	ASSERT_OK(try_open(ALLOW_LINK), "allow link: allowed");
	ASSERT_OK(try_open(ALLOW), "allow: allowed");
	ASSERT_EQ(skel->bss->denied, 2, "denied");
out:
	skel->bss->op = OP_NONE;
	remove(DENY_LINK);
	remove(ALLOW_LINK);
	remove(DENY);
	remove(ALLOW);
}

static void cleanup(void)
{
	remove(DENY_LINK);
	remove(ALLOW_LINK);
	remove(DENY);
	remove(ALLOW);
	remove(CREATED);
	remove(DIR);
	remove(RENAMED);
	remove(LINK);
	remove(FILE);
	remove(BASE);
}

void test_lsm_xattr_inode(void)
{
	struct lsm_xattr_inode *skel = NULL;
	int err;

	cleanup();
	if (!ASSERT_OK(mkdir(BASE, 0755), "mkdir base") ||
	    !ASSERT_OK(make_file(FILE), "create file"))
		goto out;

	err = setxattr(FILE, LABEL, ALPHA, sizeof(ALPHA), 0);
	if (err && errno == EOPNOTSUPP) {
		printf("%s:SKIP:local fs doesn't support xattr (%d)\n"
		       "To run this test, make sure /tmp filesystem supports xattr.\n",
		       __func__, errno);
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(err, "setxattr"))
		goto out;

	skel = lsm_xattr_inode__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open and load"))
		goto out;
	skel->bss->monitored_pid = getpid();
	if (!ASSERT_OK(lsm_xattr_inode__attach(skel), "attach"))
		goto out;

	if (test__start_subtest("read_at_instantiate"))
		test_read_at_instantiate(skel);
	if (test__start_subtest("read_parent_null_dentry"))
		test_read_parent_null_dentry(skel);
	if (test__start_subtest("mismatched_dentry"))
		test_mismatched_dentry(skel);
	if (test__start_subtest("missing"))
		test_missing(skel);
	if (test__start_subtest("short_buffer"))
		test_short_buffer(skel);
	if (test__start_subtest("load_then_enforce"))
		test_load_then_enforce(skel);
out:
	lsm_xattr_inode__destroy(skel);
	cleanup();
}
