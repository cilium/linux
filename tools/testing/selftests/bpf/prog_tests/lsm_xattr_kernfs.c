// SPDX-License-Identifier: GPL-2.0
/*
 * A policy on kernfs_init_security, which runs for every node created in
 * cgroupfs before it is linked into its parent: it reads the parent's label
 * and writes it onto the new node, cgroup directories and their control
 * files alike, and may refuse the creation outright.
 */
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <test_progs.h>
#include "cgroup_helpers.h"
#include "lsm_xattr_kernfs.skel.h"

#define ZONE		"security.bpf.zone"
#define NOTE		"security.bpf.note"
#define USER_NOTE	"user.note"
#define ROOT_CG		"/kernfs/"
#define PLAIN_CG	"/kernfs_plain/"
#define SEALED_CG	"/kernfs_sealed/"

enum {
	MODE_INHERIT,
	MODE_RELABEL_PARENT,
	MODE_SHORT_NAME,
	MODE_USER_SET,
	MODE_READ_USER,
	MODE_SHORT_BUFFER,
	MODE_FOREIGN_NAME,
};

static int sealed_fd = -1;

/* Length of @name on the node behind @fd, or -errno. */
static int get_xattr(int fd, const char *name, char *buf, size_t sz)
{
	int len = fgetxattr(fd, name, buf, sz);

	return len < 0 ? -errno : len;
}

static void assert_xattr(int fd, const char *name, const char *want,
			 const char *what)
{
	char buf[64] = {};

	if (ASSERT_EQ(get_xattr(fd, name, buf, sizeof(buf)),
		      (int)strlen(want) + 1, what))
		ASSERT_STREQ(buf, want, what);
}

/* Open a control file of the cgroup behind @cgroup_fd: fd or -errno. */
static int open_control_file(int cgroup_fd, const char *name)
{
	int fd = openat(cgroup_fd, name, O_RDONLY);

	return fd < 0 ? -errno : fd;
}

static void assert_control_file(int cgroup_fd, const char *name,
				const char *want, const char *what)
{
	int fd = open_control_file(cgroup_fd, name);

	if (!ASSERT_OK_FD(fd, what))
		return;
	assert_xattr(fd, ZONE, want, what);
	close(fd);
}

/* A child cgroup comes up carrying the label of the one it was made in. */
static void test_inherit_dir(struct lsm_xattr_kernfs *skel)
{
	int fd;

	skel->bss->mode = MODE_INHERIT;
	fd = create_and_get_cgroup(ROOT_CG "child");
	if (!ASSERT_OK_FD(fd, "create child"))
		return;
	assert_xattr(fd, ZONE, "alpha", "child inherits the label");
	ASSERT_OK(skel->bss->set_ret, "set_ret");
	ASSERT_EQ(skel->bss->labelled_dirs, 1, "labelled_dirs");
	close(fd);
	remove_cgroup(ROOT_CG "child");
}

/* The control files are nodes of the same parent and are labelled too. */
static void test_inherit_control_files(struct lsm_xattr_kernfs *skel)
{
	int fd;

	skel->bss->mode = MODE_INHERIT;
	fd = create_and_get_cgroup(ROOT_CG "files");
	if (!ASSERT_OK_FD(fd, "create child"))
		return;
	assert_control_file(fd, "cgroup.procs", "alpha", "procs inherits");
	assert_control_file(fd, "cgroup.threads", "alpha", "threads inherits");
	ASSERT_GE(skel->bss->labelled_files, 2, "labelled_files");
	close(fd);
	remove_cgroup(ROOT_CG "files");
}

/* Nothing is read off an unlabelled parent, so nothing is handed down. */
static void test_unlabelled_parent(struct lsm_xattr_kernfs *skel)
{
	char buf[64] = {};
	int fd;

	skel->bss->mode = MODE_INHERIT;
	fd = create_and_get_cgroup(PLAIN_CG "child");
	if (!ASSERT_OK_FD(fd, "create child"))
		return;
	ASSERT_EQ(get_xattr(fd, ZONE, buf, sizeof(buf)), -ENODATA,
		  "child stays unlabelled");
	ASSERT_EQ(skel->bss->get_ret, -ENODATA, "get_ret");
	close(fd);
	remove_cgroup(PLAIN_CG "child");
}

/* An error from the hook reaches mkdir(2) as itself, not as -ENOMEM. */
static void test_refuse_mkdir(struct lsm_xattr_kernfs *skel)
{
	skel->bss->mode = MODE_INHERIT;
	skel->bss->refuse_sealed = 1;
	ASSERT_EQ(mkdirat(sealed_fd, "child", 0755) ? -errno : 0, -EPERM,
		  "mkdir below a sealed cgroup");
	ASSERT_EQ(skel->bss->refused, 1, "refused");
	skel->bss->refuse_sealed = 0;
	unlinkat(sealed_fd, "child", AT_REMOVEDIR);
}

/* Both nodes the hook is handed may be written, the parent included. */
static void test_relabel_parent(struct lsm_xattr_kernfs *skel)
{
	int fd, root_fd;

	skel->bss->mode = MODE_RELABEL_PARENT;
	fd = create_and_get_cgroup(PLAIN_CG "relabel");
	if (!ASSERT_OK_FD(fd, "create child"))
		return;
	ASSERT_OK(skel->bss->set_ret, "set_ret");
	root_fd = create_and_get_cgroup(PLAIN_CG);
	if (ASSERT_OK_FD(root_fd, "open parent")) {
		assert_xattr(root_fd, ZONE, "beta", "parent relabelled");
		ASSERT_OK(fremovexattr(root_fd, ZONE) ? -errno : 0, "strip parent");
		close(root_fd);
	}
	close(fd);
	remove_cgroup(PLAIN_CG "relabel");
}

/* The name has to name something below "security.bpf.". */
static void test_short_name_refused(struct lsm_xattr_kernfs *skel)
{
	int fd;

	skel->bss->mode = MODE_SHORT_NAME;
	fd = create_and_get_cgroup(PLAIN_CG "shortname");
	if (!ASSERT_OK_FD(fd, "create child"))
		return;
	ASSERT_EQ(skel->bss->set_ret, -EINVAL, "set_ret");
	close(fd);
	remove_cgroup(PLAIN_CG "shortname");
}

/* The setter takes security.bpf. names only, not user. ones. */
static void test_user_prefix_set_refused(struct lsm_xattr_kernfs *skel)
{
	int fd;

	skel->bss->mode = MODE_USER_SET;
	fd = create_and_get_cgroup(PLAIN_CG "userset");
	if (!ASSERT_OK_FD(fd, "create child"))
		return;
	ASSERT_EQ(skel->bss->set_ret, -EPERM, "set_ret");
	close(fd);
	remove_cgroup(PLAIN_CG "userset");
}

/* The getter takes user. names as well, so one set by userspace is read. */
static void test_read_user_prefix(struct lsm_xattr_kernfs *skel)
{
	int fd;

	skel->bss->mode = MODE_READ_USER;
	fd = create_and_get_cgroup(ROOT_CG "userget");
	if (!ASSERT_OK_FD(fd, "create child"))
		return;
	ASSERT_EQ(skel->bss->get_ret, (int)sizeof("hello"), "get_ret");
	ASSERT_OK(skel->bss->set_ret, "set_ret");
	assert_xattr(fd, NOTE, "hello", "what was read is handed on");
	close(fd);
	remove_cgroup(ROOT_CG "userget");
}

/* A buffer too short for the value reads -ERANGE. */
static void test_short_buffer(struct lsm_xattr_kernfs *skel)
{
	int fd;

	skel->bss->mode = MODE_SHORT_BUFFER;
	fd = create_and_get_cgroup(ROOT_CG "shortbuf");
	if (!ASSERT_OK_FD(fd, "create child"))
		return;
	ASSERT_EQ(skel->bss->get_ret, -ERANGE, "get_ret");
	close(fd);
	remove_cgroup(ROOT_CG "shortbuf");
}

/* Another module's name is refused both ways, so that a policy cannot read
 * or forge the label SELinux put on the node.
 */
static void test_foreign_name_refused(struct lsm_xattr_kernfs *skel)
{
	char buf[64] = {};
	int fd;

	skel->bss->mode = MODE_FOREIGN_NAME;
	fd = create_and_get_cgroup(ROOT_CG "foreign");
	if (!ASSERT_OK_FD(fd, "create child"))
		return;
	ASSERT_EQ(skel->bss->get_ret, -EPERM, "get_ret");
	ASSERT_EQ(skel->bss->set_ret, -EPERM, "set_ret");
	ASSERT_EQ(fgetxattr(fd, "security.selinux", buf, sizeof(buf)) < 0 ?
		  -errno : 0, -ENODATA, "nothing written");
	close(fd);
	remove_cgroup(ROOT_CG "foreign");
}

void test_lsm_xattr_kernfs(void)
{
	int root_fd = -1, plain_fd = -1;
	struct lsm_xattr_kernfs *skel = NULL;

	if (!ASSERT_OK(setup_cgroup_environment(), "setup cgroup environment"))
		return;

	/* Labelled before the policy attaches, as an administrator would. */
	root_fd = create_and_get_cgroup(ROOT_CG);
	if (!ASSERT_OK_FD(root_fd, "create root"))
		goto out;
	if (set_cgroup_xattr(ROOT_CG, ZONE, "alpha")) {
		printf("%s:SKIP:cannot set %s on a cgroup (errno %d)\n",
		       __func__, ZONE, errno);
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(set_cgroup_xattr(ROOT_CG, USER_NOTE, "hello"),
		       "set user note"))
		goto out;
	plain_fd = create_and_get_cgroup(PLAIN_CG);
	if (!ASSERT_OK_FD(plain_fd, "create unlabelled root"))
		goto out;
	sealed_fd = create_and_get_cgroup(SEALED_CG);
	if (!ASSERT_OK_FD(sealed_fd, "create sealed root") ||
	    !ASSERT_OK(set_cgroup_xattr(SEALED_CG, ZONE, "sealed"), "seal it"))
		goto out;

	skel = lsm_xattr_kernfs__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open and load"))
		goto out;
	skel->bss->monitored_pid = getpid();
	if (!ASSERT_OK(lsm_xattr_kernfs__attach(skel), "attach"))
		goto out;

	if (test__start_subtest("inherit_dir"))
		test_inherit_dir(skel);
	if (test__start_subtest("inherit_control_files"))
		test_inherit_control_files(skel);
	if (test__start_subtest("unlabelled_parent"))
		test_unlabelled_parent(skel);
	if (test__start_subtest("refuse_mkdir"))
		test_refuse_mkdir(skel);
	if (test__start_subtest("relabel_parent"))
		test_relabel_parent(skel);
	if (test__start_subtest("short_name_refused"))
		test_short_name_refused(skel);
	if (test__start_subtest("user_prefix_set_refused"))
		test_user_prefix_set_refused(skel);
	if (test__start_subtest("read_user_prefix"))
		test_read_user_prefix(skel);
	if (test__start_subtest("short_buffer"))
		test_short_buffer(skel);
	if (test__start_subtest("foreign_name_refused"))
		test_foreign_name_refused(skel);
out:
	lsm_xattr_kernfs__destroy(skel);
	if (sealed_fd >= 0)
		close(sealed_fd);
	sealed_fd = -1;
	if (plain_fd >= 0)
		close(plain_fd);
	if (root_fd >= 0)
		close(root_fd);
	cleanup_cgroup_environment();
}
