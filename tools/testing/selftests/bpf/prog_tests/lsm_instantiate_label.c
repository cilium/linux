// SPDX-License-Identifier: GPL-2.0
/*
 * A policy that loads a file's label as its dentry is instantiated and
 * enforces it from inode_permission, which cannot read the xattr itself:
 * measure at instantiate, enforce in the atomic hook. Two files are labelled
 * before the policy attaches; linking them afterwards instantiates a fresh
 * dentry for each inode under the policy, and from then on the inode is
 * refused through either name.
 */
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <test_progs.h>
#include "lsm_instantiate_label.skel.h"

#define XATTR		"security.bpf.label"
#define BASE		"/tmp/test_progs_instantiate"
#define DENY		BASE "/deny"
#define DENY_LINK	BASE "/deny_link"
#define ALLOW		BASE "/allow"
#define ALLOW_LINK	BASE "/allow_link"

static int make_labelled(const char *path, const char *label)
{
	int fd = open(path, O_CREAT | O_WRONLY, 0644);

	if (fd < 0)
		return -errno;
	close(fd);
	return setxattr(path, XATTR, label, strlen(label) + 1, 0) ? -errno : 0;
}

static int try_open(const char *path)
{
	int fd = open(path, O_RDONLY);

	if (fd < 0)
		return -errno;
	close(fd);
	return 0;
}

static void cleanup(void)
{
	remove(DENY_LINK);
	remove(ALLOW_LINK);
	remove(DENY);
	remove(ALLOW);
	remove(BASE);
}

void test_lsm_instantiate_label(void)
{
	struct lsm_instantiate_label *skel = NULL;

	cleanup();
	if (!ASSERT_OK(mkdir(BASE, 0755), "mkdir base") ||
	    !ASSERT_OK(make_labelled(DENY, "deny"), "make deny") ||
	    !ASSERT_OK(make_labelled(ALLOW, "allow"), "make allow"))
		goto out;

	skel = lsm_instantiate_label__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open and load"))
		goto out;
	skel->bss->monitored_pid = getpid();
	if (!ASSERT_OK(lsm_instantiate_label__attach(skel), "attach"))
		goto out;

	/* Instantiated before the policy: the inode is unknown to it. */
	ASSERT_OK(try_open(DENY), "deny before instantiate: allowed");
	/* A link instantiates a fresh dentry, and the label is loaded then. */
	ASSERT_OK(link(DENY, DENY_LINK) ? -errno : 0, "link deny");
	ASSERT_OK(link(ALLOW, ALLOW_LINK) ? -errno : 0, "link allow");
	ASSERT_EQ(skel->bss->instantiated, 2, "instantiated");
	ASSERT_EQ(try_open(DENY_LINK), -EPERM, "deny link: denied");
	ASSERT_EQ(try_open(DENY), -EPERM, "deny through the old name: denied");
	ASSERT_OK(try_open(ALLOW_LINK), "allow link: allowed");
	ASSERT_OK(try_open(ALLOW), "allow: allowed");
	ASSERT_EQ(skel->bss->denied, 2, "denied");
out:
	lsm_instantiate_label__destroy(skel);
	cleanup();
}
