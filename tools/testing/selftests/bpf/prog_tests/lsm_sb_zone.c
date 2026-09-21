// SPDX-License-Identifier: GPL-2.0
/* A labelled mount, and a file on it judged by the mount's label.
 *
 * Nothing new is stored: the label goes on the one inode that stands for the
 * whole mount, the one behind the superblock's root dentry, which is now
 * reachable from any inode on that mount. Both kinds of label are exercised
 * -- the mounter's, in inode storage, and the image's, as an xattr on the
 * same inode -- because a policy wants to tell them apart.
 */
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <test_progs.h>

#include "lsm_sb_zone.skel.h"
#include "lsm_sb_zone_fail.skel.h"

#define BASE		"/tmp/test_progs_sb_zone"
#define ZONE_XATTR	"security.bpf.zone"
#define IMAGE_ZONE	"prod"
#define MOUNT_ZONE	0x5a5a

static void test_labelled_mount(void)
{
	struct lsm_sb_zone *skel = NULL;
	bool mounted = false;
	int fd = -1, err;

	if (mkdir(BASE, 0755) && errno != EEXIST) {
		ASSERT_OK(-errno, "mkdir");
		return;
	}

	skel = lsm_sb_zone__open_and_load();
	if (!ASSERT_OK_PTR(skel, "lsm_sb_zone__open_and_load"))
		goto out;
	skel->bss->monitored_pid = getpid();
	skel->bss->mount_label = MOUNT_ZONE;
	if (!ASSERT_OK(lsm_sb_zone__attach(skel), "attach"))
		goto out;

	/* The policy is watching before the mount exists, which is the only
	 * way it can label one: sb_set_mnt_opts runs inside mount(2).
	 */
	if (mount("tmpfs", BASE, "tmpfs", 0, NULL)) {
		if (errno == EPERM || errno == ENODEV) {
			test__skip();
			goto out;
		}
		ASSERT_OK(-errno, "mount tmpfs");
		goto out;
	}
	mounted = true;
	ASSERT_GE(skel->bss->mounts_labelled, 1, "mount labelled");

	/* The image's own label, on the same inode, put there by whoever
	 * owns the filesystem rather than by the mounter.
	 */
	err = setxattr(BASE, ZONE_XATTR, IMAGE_ZONE, sizeof(IMAGE_ZONE), 0) ?
	      -errno : 0;
	if (err == -EOPNOTSUPP) {
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(err, "label the image"))
		goto out;

	/* A file on the mount, reached from nothing but its own struct file. */
	fd = open(BASE "/file", O_CREAT | O_RDWR, 0644);
	if (!ASSERT_OK_FD(fd, "open a file on the mount"))
		goto out;

	ASSERT_EQ(skel->data->open_ret, MOUNT_ZONE, "mount label at file_open");
	ASSERT_EQ(skel->data->image_ret, sizeof(IMAGE_ZONE), "image label read");
	ASSERT_STREQ(skel->bss->image_zone, IMAGE_ZONE, "image label value");
out:
	if (fd >= 0)
		close(fd);
	lsm_sb_zone__destroy(skel);
	if (mounted) {
		unlink(BASE "/file");
		umount(BASE);
	}
	rmdir(BASE);
}

void test_lsm_sb_zone(void)
{
	RUN_TESTS(lsm_sb_zone_fail);

	if (test__start_subtest("labelled_mount"))
		test_labelled_mount();
}
