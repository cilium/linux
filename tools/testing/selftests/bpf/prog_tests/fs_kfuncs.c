// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <linux/fsverity.h>
#include <unistd.h>
#include <test_progs.h>
#include "test_get_xattr.skel.h"
#include "test_set_remove_xattr.skel.h"
#include "test_dget_parent.skel.h"
#include "test_fsverity.skel.h"

static const char testfile[] = "/tmp/test_progs_fs_kfuncs";
static const char testfile_renamed[] = "/tmp/test_progs_fs_kfuncs_renamed";
static const char testdir[] = "/tmp/test_progs_fs_kfuncs_dir";

static void test_get_xattr(const char *name, const char *value, bool allow_access)
{
	struct test_get_xattr *skel = NULL;
	int fd = -1, err;
	int v[32];

	fd = open(testfile, O_CREAT | O_RDONLY, 0644);
	if (!ASSERT_GE(fd, 0, "create_file"))
		return;

	close(fd);
	fd = -1;

	err = setxattr(testfile, name, value, strlen(value) + 1, 0);
	if (err && errno == EOPNOTSUPP) {
		printf("%s:SKIP:local fs doesn't support xattr (%d)\n"
		       "To run this test, make sure /tmp filesystem supports xattr.\n",
		       __func__, errno);
		test__skip();
		goto out;
	}

	if (!ASSERT_OK(err, "setxattr"))
		goto out;

	skel = test_get_xattr__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_get_xattr__open_and_load"))
		goto out;

	skel->bss->monitored_pid = getpid();
	err = test_get_xattr__attach(skel);

	if (!ASSERT_OK(err, "test_get_xattr__attach"))
		goto out;

	fd = open(testfile, O_RDONLY, 0644);

	if (!ASSERT_GE(fd, 0, "open_file"))
		goto out;

	/* Trigger security_inode_getxattr */
	err = getxattr(testfile, name, v, sizeof(v));

	if (allow_access) {
		ASSERT_EQ(err, -1, "getxattr_return");
		ASSERT_EQ(errno, EINVAL, "getxattr_errno");
		ASSERT_EQ(skel->bss->found_xattr_from_file, 1, "found_xattr_from_file");
		ASSERT_EQ(skel->bss->found_xattr_from_dentry, 1, "found_xattr_from_dentry");
	} else {
		ASSERT_EQ(err, strlen(value) + 1, "getxattr_return");
		ASSERT_EQ(skel->bss->found_xattr_from_file, 0, "found_xattr_from_file");
		ASSERT_EQ(skel->bss->found_xattr_from_dentry, 0, "found_xattr_from_dentry");
	}

out:
	close(fd);
	test_get_xattr__destroy(skel);
	remove(testfile);
}

/* xattr value we will set to security.bpf.foo */
static const char value_foo[] = "hello";

static void read_and_validate_foo(struct test_set_remove_xattr *skel)
{
	char value_out[32];
	int err;

	err = getxattr(testfile, skel->rodata->xattr_foo, value_out, sizeof(value_out));
	ASSERT_EQ(err, sizeof(value_foo), "getxattr size foo");
	ASSERT_EQ(strncmp(value_out, value_foo, sizeof(value_foo)), 0, "strncmp value_foo");
}

static void set_foo(struct test_set_remove_xattr *skel)
{
	ASSERT_OK(setxattr(testfile, skel->rodata->xattr_foo, value_foo, strlen(value_foo) + 1, 0),
		  "setxattr foo");
}

static void validate_bar_match(struct test_set_remove_xattr *skel, const char *path)
{
	char value_out[32];
	int err;

	err = getxattr(path, skel->rodata->xattr_bar, value_out, sizeof(value_out));
	ASSERT_EQ(err, sizeof(skel->data->value_bar), "getxattr size bar");
	ASSERT_EQ(strncmp(value_out, skel->data->value_bar, sizeof(skel->data->value_bar)), 0,
		  "strncmp value_bar");
}

static void validate_bar_removed(struct test_set_remove_xattr *skel, const char *path)
{
	char value_out[32];
	int err;

	err = getxattr(path, skel->rodata->xattr_bar, value_out, sizeof(value_out));
	ASSERT_LT(err, 0, "getxattr size bar should fail");
}

static void test_set_remove_xattr(void)
{
	struct test_set_remove_xattr *skel = NULL;
	int fd = -1, err;

	fd = open(testfile, O_CREAT | O_RDONLY, 0644);
	if (!ASSERT_GE(fd, 0, "create_file"))
		return;

	close(fd);
	fd = -1;

	skel = test_set_remove_xattr__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_set_remove_xattr__open_and_load"))
		return;

	/* Set security.bpf.foo to "hello" */
	err = setxattr(testfile, skel->rodata->xattr_foo, value_foo, strlen(value_foo) + 1, 0);
	if (err && errno == EOPNOTSUPP) {
		printf("%s:SKIP:local fs doesn't support xattr (%d)\n"
		       "To run this test, make sure /tmp filesystem supports xattr.\n",
		       __func__, errno);
		test__skip();
		goto out;
	}

	if (!ASSERT_OK(err, "setxattr"))
		goto out;

	skel->bss->monitored_pid = getpid();
	err = test_set_remove_xattr__attach(skel);
	if (!ASSERT_OK(err, "test_set_remove_xattr__attach"))
		goto out;

	/* First, test not _locked version of the kfuncs with rename. */

	/* Rename the file and trigger test_inode_rename. This bpf program
	 * will set security.bpf.bar to "world".
	 */
	if (!ASSERT_OK(rename(testfile, testfile_renamed), "rename"))
		goto out;
	validate_bar_match(skel, testfile_renamed);

	/* Rename it back and trigger test_inode_rename again. This will
	 * remove xattr security.bpf.bar.
	 */
	if (!ASSERT_OK(rename(testfile_renamed, testfile), "rename back"))
		goto out;
	validate_bar_removed(skel, testfile);
	read_and_validate_foo(skel);

	ASSERT_TRUE(skel->bss->set_security_bpf_bar_success, "set_security_bpf_bar_success");
	ASSERT_TRUE(skel->bss->remove_security_bpf_bar_success, "remove_security_bpf_bar_success");
	ASSERT_TRUE(skel->bss->set_security_selinux_fail, "set_security_selinux_fail");
	ASSERT_TRUE(skel->bss->remove_security_selinux_fail, "remove_security_selinux_fail");

	/* Second, test _locked version of the kfuncs, with setxattr */

	/* Set security.bpf.foo and trigger test_inode_setxattr. This
	 * bpf program will set security.bpf.bar to "world".
	 */
	set_foo(skel);
	validate_bar_match(skel, testfile);

	/* Set security.bpf.foo and trigger test_inode_setxattr again.
	 * This will remove xattr security.bpf.bar.
	 */
	set_foo(skel);
	validate_bar_removed(skel, testfile);

	ASSERT_TRUE(skel->bss->locked_set_security_bpf_bar_success,
		    "locked_set_security_bpf_bar_success");
	ASSERT_TRUE(skel->bss->locked_remove_security_bpf_bar_success,
		    "locked_remove_security_bpf_bar_success");
	ASSERT_TRUE(skel->bss->locked_set_security_selinux_fail,
		    "locked_set_security_selinux_fail");
	ASSERT_TRUE(skel->bss->locked_remove_security_selinux_fail,
		    "locked_remove_security_selinux_fail");

out:
	close(fd);
	test_set_remove_xattr__destroy(skel);
	remove(testfile_renamed);
	remove(testfile);
}

static void test_dget_parent(void)
{
	static const char value[] = "hello";
	struct test_dget_parent *skel = NULL;
	char file[64];
	int fd = -1, err;

	snprintf(file, sizeof(file), "%s/file", testdir);
	if (!ASSERT_OK(mkdir(testdir, 0755), "mkdir"))
		return;

	err = setxattr(testdir, "security.bpf.dir", value, sizeof(value), 0);
	if (err && errno == EOPNOTSUPP) {
		printf("%s:SKIP:local fs doesn't support xattr (%d)\n"
		       "To run this test, make sure /tmp filesystem supports xattr.\n",
		       __func__, errno);
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(err, "setxattr"))
		goto out;

	skel = test_dget_parent__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_dget_parent__open_and_load"))
		goto out;

	skel->bss->monitored_pid = getpid();
	err = test_dget_parent__attach(skel);
	if (!ASSERT_OK(err, "test_dget_parent__attach"))
		goto out;

	/* Trigger security_inode_create, which reads the label of testdir */
	fd = open(file, O_CREAT | O_RDWR, 0644);
	if (!ASSERT_GE(fd, 0, "create_file"))
		goto out;

	ASSERT_EQ(skel->bss->parent_xattr_len, sizeof(value), "parent_xattr_len");
	ASSERT_STREQ(skel->bss->parent_xattr, value, "parent_xattr");
out:
	if (fd >= 0)
		close(fd);
	test_dget_parent__destroy(skel);
	remove(file);
	rmdir(testdir);
}

#ifndef SHA256_DIGEST_SIZE
#define SHA256_DIGEST_SIZE      32
#endif

static void test_fsverity(void)
{
	struct fsverity_enable_arg arg = {0};
	struct test_fsverity *skel = NULL;
	struct fsverity_digest *d;
	int fd, err;
	char buffer[4096];

	fd = open(testfile, O_CREAT | O_RDWR, 0644);
	if (!ASSERT_GE(fd, 0, "create_file"))
		return;

	/* Write random buffer, so the file is not empty */
	err = write(fd, buffer, 4096);
	if (!ASSERT_EQ(err, 4096, "write_file"))
		goto out;
	close(fd);

	/* Reopen read-only, otherwise FS_IOC_ENABLE_VERITY will fail */
	fd = open(testfile, O_RDONLY, 0644);
	if (!ASSERT_GE(fd, 0, "open_file1"))
		return;

	/* Enable fsverity for the file.
	 * If the file system doesn't support verity, this will fail. Skip
	 * the test in such case.
	 */
	arg.version = 1;
	arg.hash_algorithm = FS_VERITY_HASH_ALG_SHA256;
	arg.block_size = 4096;
	err = ioctl(fd, FS_IOC_ENABLE_VERITY, &arg);
	if (err) {
		printf("%s:SKIP:local fs doesn't support fsverity (%d)\n"
		       "To run this test, try enable CONFIG_FS_VERITY and enable FSVerity for the filesystem.\n",
		       __func__, errno);
		test__skip();
		goto out;
	}

	skel = test_fsverity__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_fsverity__open_and_load"))
		goto out;

	/* Get fsverity_digest from ioctl */
	d = (struct fsverity_digest *)skel->bss->expected_digest;
	d->digest_algorithm = FS_VERITY_HASH_ALG_SHA256;
	d->digest_size = SHA256_DIGEST_SIZE;
	err = ioctl(fd, FS_IOC_MEASURE_VERITY, skel->bss->expected_digest);
	if (!ASSERT_OK(err, "ioctl_FS_IOC_MEASURE_VERITY"))
		goto out;

	skel->bss->monitored_pid = getpid();
	err = test_fsverity__attach(skel);
	if (!ASSERT_OK(err, "test_fsverity__attach"))
		goto out;

	/* Reopen the file to trigger the program */
	close(fd);
	fd = open(testfile, O_RDONLY);
	if (!ASSERT_GE(fd, 0, "open_file2"))
		goto out;

	ASSERT_EQ(skel->bss->got_fsverity, 1, "got_fsverity");
	ASSERT_EQ(skel->bss->digest_matches, 1, "digest_matches");
out:
	close(fd);
	test_fsverity__destroy(skel);
	remove(testfile);
}

void test_fs_kfuncs(void)
{
	/* Matches xattr_names in progs/test_get_xattr.c */
	if (test__start_subtest("user_xattr"))
		test_get_xattr("user.kfuncs", "hello", true);

	if (test__start_subtest("security_bpf_xattr"))
		test_get_xattr("security.bpf.xxx", "hello", true);

	if (test__start_subtest("security_bpf_xattr_error"))
		test_get_xattr("security.bpf", "hello", false);

	if (test__start_subtest("security_selinux_xattr_error"))
		test_get_xattr("security.selinux", "hello", false);

	if (test__start_subtest("set_remove_xattr"))
		test_set_remove_xattr();

	if (test__start_subtest("dget_parent"))
		test_dget_parent();

	if (test__start_subtest("fsverity"))
		test_fsverity();
}
