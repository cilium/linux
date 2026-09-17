// SPDX-License-Identifier: GPL-2.0
/*
 * A policy that hands a directory's label down to what is created in it:
 * path_mkdir and path_mknod read security.bpf.label off the parent's dentry,
 * reachable through the trusted struct path, and inode_init_security attaches
 * it to the new inode. The directory is labelled before the policy attaches
 * and relabelled while it runs, so every label is read from the parent at
 * creation and nothing is cached.
 */
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <test_progs.h>
#include "lsm_inherit_label.skel.h"

#define XATTR		"security.bpf.label"
#define STAMP		"security.bpf.stamp"
#define BASE		"/tmp/test_progs_inherit"
#define PLAIN		"/tmp/test_progs_inherit_plain"

static void assert_label(const char *path, const char *want, const char *what)
{
	char buf[64] = {};
	int len;

	len = getxattr(path, XATTR, buf, sizeof(buf) - 1);
	if (want) {
		ASSERT_EQ(len, strlen(want) + 1, what);
		ASSERT_STREQ(buf, want, what);
	} else {
		ASSERT_EQ(len < 0 ? -errno : len, -ENODATA, what);
	}
}

static void cleanup(void)
{
	remove(BASE "/child/grandchild");
	remove(BASE "/child");
	remove(BASE "/file");
	remove(BASE "/later");
	remove(BASE);
	remove(PLAIN "/child");
	remove(PLAIN);
}

void test_lsm_inherit_label(void)
{
	struct lsm_inherit_label *skel = NULL;
	int fd;

	cleanup();
	if (!ASSERT_OK(mkdir(BASE, 0755), "mkdir base") ||
	    !ASSERT_OK(mkdir(PLAIN, 0755), "mkdir plain"))
		goto out;
	/* Labelled before the policy exists, so nothing has seen the label. */
	if (!ASSERT_OK(setxattr(BASE, XATTR, "alpha", sizeof("alpha"), 0),
		       "label base"))
		goto out;

	skel = lsm_inherit_label__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open and load"))
		goto out;
	skel->bss->monitored_pid = getpid();
	if (!ASSERT_OK(lsm_inherit_label__attach(skel), "attach"))
		goto out;

	ASSERT_OK(mkdir(BASE "/child", 0755), "mkdir child");
	assert_label(BASE "/child", "alpha", "child inherits");
	fd = open(BASE "/file", O_CREAT | O_WRONLY, 0644);
	if (ASSERT_GE(fd, 0, "create file"))
		close(fd);
	assert_label(BASE "/file", "alpha", "file inherits");
	/* Two levels down it comes off the child's own persisted label. */
	ASSERT_OK(mkdir(BASE "/child/grandchild", 0755), "mkdir grandchild");
	assert_label(BASE "/child/grandchild", "alpha", "grandchild inherits");
	/* Relabelled while the policy runs: read at creation, not cached. */
	ASSERT_OK(setxattr(BASE, XATTR, "beta", sizeof("beta"), 0), "relabel base");
	ASSERT_OK(mkdir(BASE "/later", 0755), "mkdir later");
	assert_label(BASE "/later", "beta", "later inherits the new label");
	/* An unlabelled parent hands down nothing. */
	ASSERT_OK(mkdir(PLAIN "/child", 0755), "mkdir plain child");
	assert_label(PLAIN "/child", NULL, "plain child unlabelled");

	/* Written onto the locked parent from path_mkdir without deadlocking. */
	ASSERT_EQ(getxattr(BASE, STAMP, NULL, 0), 2, "base stamped");
	ASSERT_EQ(getxattr(PLAIN, STAMP, NULL, 0), 2, "plain stamped");
	ASSERT_EQ(skel->bss->remembered, 4, "remembered");
	ASSERT_EQ(skel->bss->inherited, 4, "inherited");
	ASSERT_OK(skel->bss->init_err, "init_err");
out:
	lsm_inherit_label__destroy(skel);
	cleanup();
}
