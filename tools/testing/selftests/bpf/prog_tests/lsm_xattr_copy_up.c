// SPDX-License-Identifier: GPL-2.0
/*
 * A policy that steers what overlayfs copies up: the label it owns stays on
 * the lower layer instead of following the file into the writable upper
 * copy, a file it has sealed is not copied up at all, and anything else is
 * copied as before. Every case has a lower file of its own, so that each
 * one triggers the copy up it looks at.
 */
#include <fcntl.h>
#include <ftw.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <test_progs.h>
#include "lsm_xattr_copy_up.skel.h"

#define BASE		"/tmp/test_progs_xattr_copy_up"
#define LOWER		BASE "/lower"
#define UPPER		BASE "/upper"
#define WORK		BASE "/work"
#define MERGED		BASE "/merged"
#define OPTS		"lowerdir=" LOWER ",upperdir=" UPPER ",workdir=" WORK
#define LABEL		"security.bpf.label"
#define SEALED		"security.bpf.sealed"
#define KEEP		"user.keep"
#define ORIGIN		"security.bpf.origin"

static int make_file(const char *path)
{
	int fd = open(path, O_CREAT | O_WRONLY, 0644);

	if (fd < 0)
		return -errno;
	if (write(fd, "x", 1) != 1) {
		close(fd);
		return -EIO;
	}
	close(fd);
	return 0;
}

static int set(const char *path, const char *name, const char *value)
{
	return setxattr(path, name, value, strlen(value) + 1, 0) ? -errno : 0;
}

/* Length of the xattr, or -errno. */
static int has(const char *path, const char *name)
{
	char buf[16];
	int len = getxattr(path, name, buf, sizeof(buf));

	return len < 0 ? -errno : len;
}

/* Open for write, which copies the file up: 0 or -errno. */
static int copy_up(const char *path)
{
	int fd = open(path, O_WRONLY);

	if (fd < 0)
		return -errno;
	close(fd);
	return 0;
}

/* The label the policy owns does not follow the file up. */
static void test_discard_label(struct lsm_xattr_copy_up *skel)
{
	__u32 discarded = skel->bss->discarded;

	ASSERT_OK(copy_up(MERGED "/discard"), "copy up");
	ASSERT_EQ(has(UPPER "/discard", LABEL), -ENODATA, "label not copied up");
	ASSERT_EQ(skel->bss->discarded, discarded + 1, "discarded");
}

/* A name the policy does not own is copied along as before. */
static void test_keep_other_xattr(struct lsm_xattr_copy_up *skel)
{
	ASSERT_OK(copy_up(MERGED "/keep"), "copy up");
	ASSERT_EQ(has(UPPER "/keep", KEEP), (int)sizeof("1"),
		  "other xattr copied up");
	ASSERT_EQ(has(UPPER "/keep", LABEL), -ENODATA, "label not copied up");
}

/* What the lower layer holds is left alone by the copy up. */
static void test_lower_untouched(struct lsm_xattr_copy_up *skel)
{
	ASSERT_OK(copy_up(MERGED "/lower"), "copy up");
	ASSERT_EQ(has(LOWER "/lower", LABEL), (int)sizeof("lower"),
		  "label still on the lower layer");
}

/* Through the overlay the label is visible until the copy up, and gone
 * afterwards: the upper copy is what the mount shows from then on.
 */
static void test_overlay_view(struct lsm_xattr_copy_up *skel)
{
	ASSERT_EQ(has(MERGED "/view", LABEL), (int)sizeof("lower"),
		  "label visible before the copy up");
	ASSERT_OK(copy_up(MERGED "/view"), "copy up");
	ASSERT_EQ(has(MERGED "/view", LABEL), -ENODATA,
		  "label gone from the overlay");
}

/* An error other than -ECANCELED aborts the copy up, so the file cannot be
 * opened for writing at all and nothing lands in the upper layer.
 */
static void test_abort_sealed(struct lsm_xattr_copy_up *skel)
{
	__u32 aborted = skel->bss->aborted;

	ASSERT_EQ(copy_up(MERGED "/sealed"), -EPERM, "copy up refused");
	ASSERT_EQ(has(UPPER "/sealed", SEALED), -ENOENT, "nothing copied up");
	ASSERT_EQ(skel->bss->aborted, aborted + 1, "aborted");
}

/* A name the program returns 0 for is copied, and the hook saw it. */
static void test_default_copies(struct lsm_xattr_copy_up *skel)
{
	__u32 seen = skel->bss->seen;

	ASSERT_OK(copy_up(MERGED "/plain"), "copy up");
	ASSERT_EQ(has(UPPER "/plain", KEEP), (int)sizeof("1"), "xattr copied up");
	ASSERT_EQ(skel->bss->seen, seen + 1, "seen");
}

static int rm(const char *path, const struct stat *st, int type,
	      struct FTW *ftw)
{
	return remove(path);
}

static void cleanup(void)
{
	umount(MERGED);
	nftw(BASE, rm, 8, FTW_DEPTH | FTW_PHYS | FTW_MOUNT);
}

/* A lower file with the policy's label on it, plus @extra. */
static int make_lower(const char *name, const char *label, const char *extra)
{
	char path[PATH_MAX];
	int err;

	snprintf(path, sizeof(path), LOWER "/%s", name);
	err = make_file(path);
	if (err)
		return err;
	if (label) {
		err = set(path, label, "lower");
		if (err)
			return err;
	}
	return extra ? set(path, extra, "1") : 0;
}

/* A file created through the overlay is a brand new upper inode: it carries
 * what inode_init_security stamped and nothing from any lower layer.
 */
static void test_created_in_overlay(struct lsm_xattr_copy_up *skel)
{
	__u32 stamped = skel->bss->stamped;

	ASSERT_OK(make_file(MERGED "/fresh"), "create through the overlay");
	ASSERT_GE(skel->bss->stamped - stamped, 1, "stamped");
	ASSERT_OK(skel->bss->stamp_err, "stamp_err");
	ASSERT_EQ(has(UPPER "/fresh", ORIGIN), (int)sizeof("upper"),
		  "the new upper file carries the stamp");
	ASSERT_EQ(has(UPPER "/fresh", LABEL), -ENODATA, "and no lower label");
}

/* A copy up makes an upper inode too, so both hooks run on the one
 * operation: the new inode is stamped, and the lower layer's own label is
 * still discarded rather than laid on top of it.
 */
static void test_copy_up_stamps_upper(struct lsm_xattr_copy_up *skel)
{
	__u32 discarded = skel->bss->discarded;
	__u32 stamped = skel->bss->stamped;

	ASSERT_OK(copy_up(MERGED "/stamped"), "copy up");
	ASSERT_GE(skel->bss->stamped - stamped, 1, "stamped");
	ASSERT_EQ(skel->bss->discarded, discarded + 1, "discarded");
	ASSERT_EQ(has(UPPER "/stamped", ORIGIN), (int)sizeof("upper"),
		  "the upper inode carries the stamp");
	ASSERT_EQ(has(UPPER "/stamped", LABEL), -ENODATA,
		  "the lower label did not follow");
}

void test_lsm_xattr_copy_up(void)
{
	struct lsm_xattr_copy_up *skel = NULL;
	int err;

	cleanup();
	if (!ASSERT_OK(mkdir(BASE, 0755), "mkdir base") ||
	    !ASSERT_OK(mkdir(LOWER, 0755), "mkdir lower") ||
	    !ASSERT_OK(mkdir(UPPER, 0755), "mkdir upper") ||
	    !ASSERT_OK(mkdir(WORK, 0755), "mkdir work") ||
	    !ASSERT_OK(mkdir(MERGED, 0755), "mkdir merged"))
		goto out;

	err = make_lower("discard", LABEL, NULL);
	if (err == -EOPNOTSUPP) {
		printf("%s:SKIP:local fs doesn't support xattr (%d)\n"
		       "To run this test, make sure /tmp filesystem supports xattr.\n",
		       __func__, -err);
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(err, "make the discard file") ||
	    !ASSERT_OK(make_lower("keep", LABEL, KEEP), "make the keep file") ||
	    !ASSERT_OK(make_lower("lower", LABEL, NULL), "make the lower file") ||
	    !ASSERT_OK(make_lower("view", LABEL, NULL), "make the view file") ||
	    !ASSERT_OK(make_lower("sealed", SEALED, NULL), "make the sealed file") ||
	    !ASSERT_OK(make_lower("plain", NULL, KEEP), "make the plain file") ||
	    !ASSERT_OK(make_lower("stamped", LABEL, NULL), "make the stamped file"))
		goto out;
	if (!ASSERT_OK(mount("overlay", MERGED, "overlay", 0, OPTS) ? -errno : 0,
		       "mount overlay"))
		goto out;

	skel = lsm_xattr_copy_up__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open and load"))
		goto out;
	skel->bss->monitored_pid = getpid();
	if (!ASSERT_OK(lsm_xattr_copy_up__attach(skel), "attach"))
		goto out;

	if (test__start_subtest("discard_label"))
		test_discard_label(skel);
	if (test__start_subtest("keep_other_xattr"))
		test_keep_other_xattr(skel);
	if (test__start_subtest("lower_untouched"))
		test_lower_untouched(skel);
	if (test__start_subtest("overlay_view"))
		test_overlay_view(skel);
	if (test__start_subtest("abort_sealed"))
		test_abort_sealed(skel);
	if (test__start_subtest("default_copies"))
		test_default_copies(skel);
	if (test__start_subtest("created_in_overlay"))
		test_created_in_overlay(skel);
	if (test__start_subtest("copy_up_stamps_upper"))
		test_copy_up_stamps_upper(skel);
out:
	lsm_xattr_copy_up__destroy(skel);
	cleanup();
}
