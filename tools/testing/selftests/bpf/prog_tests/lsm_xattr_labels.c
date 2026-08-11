// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2026 Isovalent */

#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <test_progs.h>
#include "lsm_xattr_labels.skel.h"

#define LABEL_MAX	32

#define XATTR_ZONE	"security.bpf.zone"
#define XATTR_ORIGIN	"security.bpf.origin"
#define XATTR_STATE	"security.bpf.state"

#define DEFAULT_ZONE	"default"
#define NESTED_ZONE	"restricted"
#define LOWER_ZONE	"lowerzone"
#define LOWER_ORIGIN	"lowerorigin"

struct label {
	char	v[LABEL_MAX];
	__u32	len;
};

struct scratch {
	char	root[64];	/* mkdtemp'd, holds every mount below */
	char	data[128];	/* tmpfs, real xattr support */
	char	bare[128];	/* ramfs, no xattr support at all */
	char	lower[192];
	char	upper[192];
	char	work[192];
	char	merged[192];
	bool	data_mounted;
	bool	bare_mounted;
	bool	merged_mounted;
};

static void scratch_cleanup(struct scratch *s)
{
	if (s->merged_mounted)
		umount(s->merged);
	if (s->bare_mounted)
		umount(s->bare);
	if (s->data_mounted)
		umount(s->data);
	if (s->bare[0])
		rmdir(s->bare);
	if (s->data[0])
		rmdir(s->data);
	if (s->root[0])
		rmdir(s->root);
}

static int copy_file(const char *from, const char *to)
{
	char buf[4096];
	int in, out, ret = -1;
	ssize_t n;

	in = open(from, O_RDONLY);
	if (in < 0)
		return -1;
	out = open(to, O_CREAT | O_TRUNC | O_WRONLY, 0755);
	if (out < 0)
		goto close_in;

	while ((n = read(in, buf, sizeof(buf))) > 0) {
		if (write(out, buf, n) != n)
			goto close_out;
	}
	if (!n)
		ret = 0;
close_out:
	close(out);
close_in:
	close(in);
	return ret;
}

static int scratch_setup(struct scratch *s)
{
	memset(s, 0, sizeof(*s));
	snprintf(s->root, sizeof(s->root), "/tmp/lsm_xattr_labels.XXXXXX");
	if (!ASSERT_OK_PTR(mkdtemp(s->root), "mkdtemp"))
		return -1;
	/* mkdtemp() gives 0700, which an unprivileged child cannot traverse. */
	if (!ASSERT_OK(chmod(s->root, 0755), "chmod_root"))
		return -1;

	snprintf(s->data, sizeof(s->data), "%s/data", s->root);
	snprintf(s->bare, sizeof(s->bare), "%s/bare", s->root);
	if (!ASSERT_OK(mkdir(s->data, 0755), "mkdir_data"))
		return -1;
	if (!ASSERT_OK(mkdir(s->bare, 0755), "mkdir_bare"))
		return -1;

	if (!ASSERT_OK(mount("tmpfs", s->data, "tmpfs", 0, NULL), "mount_tmpfs"))
		return -1;
	s->data_mounted = true;

	snprintf(s->lower, sizeof(s->lower), "%s/lower", s->data);
	snprintf(s->upper, sizeof(s->upper), "%s/upper", s->data);
	snprintf(s->work, sizeof(s->work), "%s/work", s->data);
	snprintf(s->merged, sizeof(s->merged), "%s/merged", s->data);

	return 0;
}

/*
 * Seed the per-mount default zone from userspace, which is also what exercises
 * the syscall side of BPF_MAP_TYPE_SB_STORAGE: a super_block has no descriptor
 * of its own, so the key is a file descriptor of anything on the mount.
 */
static int seed_sb_default(struct lsm_xattr_labels *skel, const char *dir,
			   const char *zone)
{
	struct label val = {};
	int fd, err;

	fd = open(dir, O_RDONLY | O_DIRECTORY);
	if (!ASSERT_GE(fd, 0, "open_mount"))
		return -1;

	val.len = strlen(zone);
	memcpy(val.v, zone, val.len);

	err = bpf_map_update_elem(bpf_map__fd(skel->maps.sb_default_zone),
				  &fd, &val, BPF_ANY);
	ASSERT_OK(err, "sb_storage_update");
	close(fd);
	return err;
}

static int read_xattr(const char *path, const char *name, char *buf, size_t sz)
{
	memset(buf, 0, sz);
	return getxattr(path, name, buf, sz);
}

/* Creation-time labelling: two labels at once, and inheritance from the dir. */
static void test_init_labels(struct lsm_xattr_labels *skel, struct scratch *s)
{
	char path[512], sub[256], buf[LABEL_MAX];
	int fd, err;

	snprintf(path, sizeof(path), "%s/plain", s->data);
	fd = open(path, O_CREAT | O_RDWR, 0644);
	if (!ASSERT_GE(fd, 0, "create_plain"))
		return;
	close(fd);

	/* Both labels are on disk without anybody having called setxattr(). */
	err = read_xattr(path, XATTR_ZONE, buf, sizeof(buf));
	if (!ASSERT_EQ(err, strlen(DEFAULT_ZONE), "zone_len"))
		return;
	ASSERT_STRNEQ(buf, DEFAULT_ZONE, strlen(DEFAULT_ZONE), "zone_value");

	err = read_xattr(path, XATTR_ORIGIN, buf, sizeof(buf));
	if (!ASSERT_GT(err, 0, "origin_len"))
		return;
	ASSERT_STREQ(buf, "created", "origin_value");

	/* A directory relabelled by hand hands its zone down to new children. */
	snprintf(sub, sizeof(sub), "%s/nested", s->data);
	if (!ASSERT_OK(mkdir(sub, 0755), "mkdir_nested"))
		return;
	if (!ASSERT_OK(setxattr(sub, XATTR_ZONE, NESTED_ZONE,
				strlen(NESTED_ZONE), 0), "relabel_nested"))
		return;

	snprintf(path, sizeof(path), "%s/child", sub);
	fd = open(path, O_CREAT | O_RDWR, 0644);
	if (!ASSERT_GE(fd, 0, "create_child"))
		return;
	close(fd);

	err = read_xattr(path, XATTR_ZONE, buf, sizeof(buf));
	if (!ASSERT_EQ(err, strlen(NESTED_ZONE), "child_zone_len"))
		return;
	ASSERT_STRNEQ(buf, NESTED_ZONE, strlen(NESTED_ZONE), "child_zone_value");

	/* Two labels for the plain file, two more for nested/ and its child. */
	ASSERT_GE(skel->bss->init_labels_set, 6, "init_labels_set");
	ASSERT_GT(skel->bss->init_selinux_err, 0, "init_selinux_refused");

	/* d_instantiate() resolved the on-disk label into inode storage. */
	ASSERT_GT(skel->bss->instantiated, 0, "instantiated");
}

/*
 * A filesystem with no xattr support at all. Everything here goes through the
 * label hooks: setxattr() lands in inode_setsecurity(), getxattr() in
 * inode_getsecurity() and listxattr() in inode_listsecurity().
 */
static void test_virtual_labels(struct lsm_xattr_labels *skel, struct scratch *s)
{
	char path[512], buf[LABEL_MAX], list[256];
	bool found = false;
	int fd, err, off;

	if (mount("ramfs", s->bare, "ramfs", 0, NULL)) {
		printf("%s:SKIP:ramfs not available\n", __func__);
		test__skip();
		return;
	}
	s->bare_mounted = true;

	snprintf(path, sizeof(path), "%s/virt", s->bare);
	fd = open(path, O_CREAT | O_RDWR, 0644);
	if (!ASSERT_GE(fd, 0, "create_virt"))
		return;
	close(fd);

	/* ramfs cannot store this, so the policy has to take it. */
	err = setxattr(path, XATTR_STATE, NESTED_ZONE, strlen(NESTED_ZONE), 0);
	if (!ASSERT_OK(err, "setxattr_virtual"))
		return;
	ASSERT_EQ(skel->bss->set_label_len, strlen(NESTED_ZONE), "set_label_len");

	/* ... and hand it back on read, out of inode local storage. */
	err = read_xattr(path, XATTR_STATE, buf, sizeof(buf));
	if (!ASSERT_EQ(err, strlen(NESTED_ZONE), "getxattr_virtual_len"))
		return;
	ASSERT_STRNEQ(buf, NESTED_ZONE, strlen(NESTED_ZONE), "getxattr_virtual");
	ASSERT_GT(skel->bss->get_label_served, 0, "get_label_served");

	/* ... and advertise it, so that listxattr() reports something. */
	memset(list, 0, sizeof(list));
	err = listxattr(path, list, sizeof(list));
	if (!ASSERT_GT(err, 0, "listxattr_len"))
		return;
	for (off = 0; off < err; off += strlen(list + off) + 1) {
		if (!strcmp(list + off, XATTR_STATE))
			found = true;
	}
	ASSERT_TRUE(found, "listxattr_reports_virtual_label");
	ASSERT_GT(skel->bss->list_labels_served, 0, "list_labels_served");
	ASSERT_GT(skel->bss->add_selinux_err, 0, "add_selinux_refused");
}

/* Provenance must not be inherited by a copy-up, the zone must be. */
static void test_copy_up(struct lsm_xattr_labels *skel, struct scratch *s)
{
	char opts[1024], path[512], buf[LABEL_MAX];
	int fd, err;

	if (!ASSERT_OK(mkdir(s->lower, 0755), "mkdir_lower") ||
	    !ASSERT_OK(mkdir(s->upper, 0755), "mkdir_upper") ||
	    !ASSERT_OK(mkdir(s->work, 0755), "mkdir_work") ||
	    !ASSERT_OK(mkdir(s->merged, 0755), "mkdir_merged"))
		return;

	snprintf(path, sizeof(path), "%s/victim", s->lower);
	fd = open(path, O_CREAT | O_RDWR, 0644);
	if (!ASSERT_GE(fd, 0, "create_lower"))
		return;
	close(fd);

	/*
	 * Give the lower file distinctive values. overlayfs creates the upper
	 * copy through the normal create path, so it picks up labels of its
	 * own from inode_init_label() before any xattr is copied over; what is
	 * being tested is which of the lower file's values then replace them.
	 */
	if (!ASSERT_OK(setxattr(path, XATTR_ZONE, LOWER_ZONE,
				strlen(LOWER_ZONE), 0), "lower_set_zone"))
		return;
	if (!ASSERT_OK(setxattr(path, XATTR_ORIGIN, LOWER_ORIGIN,
				strlen(LOWER_ORIGIN), 0), "lower_set_origin"))
		return;

	snprintf(opts, sizeof(opts), "lowerdir=%s,upperdir=%s,workdir=%s",
		 s->lower, s->upper, s->work);
	if (mount("overlay", s->merged, "overlay", 0, opts)) {
		printf("%s:SKIP:overlayfs unavailable (%s)\n", __func__,
		       strerror(errno));
		test__skip();
		return;
	}
	s->merged_mounted = true;

	/* Writing through the merged dir triggers the copy-up. */
	snprintf(path, sizeof(path), "%s/victim", s->merged);
	fd = open(path, O_WRONLY);
	if (!ASSERT_GE(fd, 0, "open_merged"))
		return;
	err = write(fd, "x", 1);
	close(fd);
	if (!ASSERT_EQ(err, 1, "write_merged"))
		return;

	ASSERT_GT(skel->bss->copy_up_dropped, 0, "copy_up_saw_origin");
	ASSERT_GT(skel->bss->copy_up_kept, 0, "copy_up_saw_zone");

	/* Inspect the upper file directly, bypassing the overlay. */
	snprintf(path, sizeof(path), "%s/victim", s->upper);

	/* The zone was copied up, so the lower file's value won. */
	if (!ASSERT_EQ(read_xattr(path, XATTR_ZONE, buf, sizeof(buf)),
		       strlen(LOWER_ZONE), "upper_zone_len"))
		return;
	ASSERT_STRNEQ(buf, LOWER_ZONE, strlen(LOWER_ZONE), "upper_kept_zone");

	/* Provenance was dropped, so the lower file's value did not. */
	err = read_xattr(path, XATTR_ORIGIN, buf, sizeof(buf));
	if (err > 0)
		ASSERT_FALSE(!strncmp(buf, LOWER_ORIGIN, strlen(LOWER_ORIGIN)),
			     "upper_dropped_origin");
	else
		ASSERT_EQ(errno, ENODATA, "upper_dropped_origin_errno");
}

/*
 * Read a label off a binary the running task has no read access to. Before
 * security.bpf.* reads stopped being gated on the subject's permissions this
 * came back -EACCES.
 */
static void test_label_read_without_access(struct lsm_xattr_labels *skel,
					   struct scratch *s)
{
	char path[512];
	struct passwd *nobody;
	int fd, status;
	pid_t pid;

	nobody = getpwnam("nobody");
	if (!nobody) {
		printf("%s:SKIP:no nobody user\n", __func__);
		test__skip();
		return;
	}

	snprintf(path, sizeof(path), "%s/exec_only", s->data);
	if (!ASSERT_OK(copy_file("/bin/true", path), "copy_true"))
		return;
	/* Executable by everyone, readable by nobody at all. */
	if (!ASSERT_OK(chmod(path, 0111), "chmod_exec_only"))
		return;
	if (!ASSERT_OK(setxattr(path, XATTR_ZONE, NESTED_ZONE,
				strlen(NESTED_ZONE), 0), "label_exec_only"))
		return;

	fd = open(path, O_RDONLY);
	ASSERT_GE(fd, 0, "root_can_still_read");
	if (fd >= 0)
		close(fd);

	pid = fork();
	if (!ASSERT_GE(pid, 0, "fork"))
		return;
	if (pid == 0) {
		/* skel->bss is a shared mapping, so the kernel sees this. */
		skel->bss->monitored_exec_pid = getpid();
		if (setgid(nobody->pw_gid) || setuid(nobody->pw_uid))
			_exit(2);
		/* Confirm the label really is out of reach for this task. */
		if (open(path, O_RDONLY) >= 0)
			_exit(3);
		/* argv[0] stays "true" so a busybox /bin/true still succeeds. */
		execl(path, "true", NULL);
		fprintf(stderr, "execl(%s): %s\n", path, strerror(errno));
		_exit(4);
	}
	if (!ASSERT_EQ(waitpid(pid, &status, 0), pid, "waitpid"))
		return;
	if (!ASSERT_TRUE(WIFEXITED(status), "child_exited"))
		return;
	if (!ASSERT_EQ(WEXITSTATUS(status), 0, "child_status"))
		return;

	ASSERT_EQ(skel->bss->exec_zone_err, 0, "exec_zone_err");
	if (!ASSERT_EQ(skel->bss->exec_zone_len, strlen(NESTED_ZONE),
		       "exec_zone_len"))
		return;
	ASSERT_STRNEQ(skel->bss->exec_zone, NESTED_ZONE, strlen(NESTED_ZONE),
		      "exec_zone_value");
}

void test_lsm_xattr_labels(void)
{
	struct lsm_xattr_labels *skel;
	struct scratch s;
	int err;

	if (scratch_setup(&s))
		goto cleanup;

	skel = lsm_xattr_labels__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		goto cleanup;

	if (seed_sb_default(skel, s.data, DEFAULT_ZONE))
		goto destroy;

	skel->bss->monitored_pid = getpid();
	err = lsm_xattr_labels__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto destroy;

	if (test__start_subtest("init_labels"))
		test_init_labels(skel, &s);
	if (test__start_subtest("virtual_labels"))
		test_virtual_labels(skel, &s);
	if (test__start_subtest("copy_up"))
		test_copy_up(skel, &s);
	if (test__start_subtest("label_read_without_access"))
		test_label_read_without_access(skel, &s);

destroy:
	lsm_xattr_labels__destroy(skel);
cleanup:
	scratch_cleanup(&s);
}
