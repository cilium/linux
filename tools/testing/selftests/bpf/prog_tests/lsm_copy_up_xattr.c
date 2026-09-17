// SPDX-License-Identifier: GPL-2.0
/*
 * A policy that steers what overlayfs copies up: the label it owns stays on
 * the lower layer instead of following the file into the writable upper
 * copy, a file it has sealed is not copied up at all, and anything else is
 * copied as before.
 */
#include <fcntl.h>
#include <ftw.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <test_progs.h>
#include "lsm_copy_up_xattr.skel.h"

#define BASE		"/tmp/test_progs_copy_up"
#define LOWER		BASE "/lower"
#define UPPER		BASE "/upper"
#define WORK		BASE "/work"
#define MERGED		BASE "/merged"
#define OPTS		"lowerdir=" LOWER ",upperdir=" UPPER ",workdir=" WORK
#define LABEL		"security.bpf.label"
#define SEALED		"security.bpf.sealed"
#define KEEP		"user.keep"

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

static int open_for_write(const char *path)
{
	int fd = open(path, O_WRONLY);

	if (fd < 0)
		return -errno;
	close(fd);
	return 0;
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

void test_lsm_copy_up_xattr(void)
{
	struct lsm_copy_up_xattr *skel = NULL;

	cleanup();
	if (!ASSERT_OK(mkdir(BASE, 0755), "mkdir base") ||
	    !ASSERT_OK(mkdir(LOWER, 0755), "mkdir lower") ||
	    !ASSERT_OK(mkdir(UPPER, 0755), "mkdir upper") ||
	    !ASSERT_OK(mkdir(WORK, 0755), "mkdir work") ||
	    !ASSERT_OK(mkdir(MERGED, 0755), "mkdir merged"))
		goto out;
	if (!ASSERT_OK(make_file(LOWER "/labelled"), "make labelled") ||
	    !ASSERT_OK(set(LOWER "/labelled", LABEL, "lower"), "label it") ||
	    !ASSERT_OK(set(LOWER "/labelled", KEEP, "1"), "mark it") ||
	    !ASSERT_OK(make_file(LOWER "/sealed"), "make sealed") ||
	    !ASSERT_OK(set(LOWER "/sealed", SEALED, "1"), "seal it"))
		goto out;
	if (!ASSERT_OK(mount("overlay", MERGED, "overlay", 0, OPTS) ? -errno : 0,
		       "mount overlay"))
		goto out;

	skel = lsm_copy_up_xattr__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open and load"))
		goto out;
	skel->bss->monitored_pid = getpid();
	if (!ASSERT_OK(lsm_copy_up_xattr__attach(skel), "attach"))
		goto out;

	/* Before the copy up the overlay shows the lower layer's label. */
	ASSERT_EQ(has(MERGED "/labelled", LABEL), sizeof("lower"),
		  "label visible before copy up");
	/* Opening for write copies the file up, and the label stays behind. */
	ASSERT_OK(open_for_write(MERGED "/labelled"), "copy up labelled");
	ASSERT_EQ(has(UPPER "/labelled", LABEL), -ENODATA, "label not copied up");
	ASSERT_EQ(has(UPPER "/labelled", KEEP), sizeof("1"), "other xattr copied up");
	ASSERT_EQ(has(MERGED "/labelled", LABEL), -ENODATA,
		  "label gone from the overlay");
	ASSERT_EQ(has(LOWER "/labelled", LABEL), sizeof("lower"),
		  "label still on the lower layer");
	/* A sealed file is not copied up at all. */
	ASSERT_EQ(open_for_write(MERGED "/sealed"), -EPERM, "copy up sealed: refused");
	ASSERT_EQ(has(UPPER "/sealed", SEALED), -ENOENT, "sealed not copied up");
	ASSERT_EQ(skel->bss->seen, 3, "seen");
	ASSERT_EQ(skel->bss->discarded, 1, "discarded");
	ASSERT_EQ(skel->bss->aborted, 1, "aborted");
out:
	lsm_copy_up_xattr__destroy(skel);
	cleanup();
}
