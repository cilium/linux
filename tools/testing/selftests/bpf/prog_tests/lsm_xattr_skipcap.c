// SPDX-License-Identifier: GPL-2.0
/*
 * inode_xattr_skipcap: a policy claims the one name it owns, so writing and
 * removing that name is decided by the policy alone rather than by
 * CAP_SYS_ADMIN, while every other security. name keeps needing the
 * capability. What the policy decides for its own name is enforced from
 * inode_setxattr and inode_removexattr, capability or not.
 */
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <test_progs.h>
#include "cap_helpers.h"
#include "cgroup_helpers.h"
#include "lsm_xattr_skipcap.skel.h"

#define ZONE		"security.bpf.zone"
#define OTHER		"security.bpf.other"
#define BASE		"/tmp/test_progs_xattr_skipcap"
#define FILE		BASE "/file"
#define LOCKED		BASE "/locked"
#define SKIPCAP_CG	"/skipcap_zone/"

static int cgroup_fd = -1;

static int set(const char *path, const char *name, const char *value)
{
	return setxattr(path, name, value, strlen(value) + 1, 0) ? -errno : 0;
}

static int unset(const char *path, const char *name)
{
	return removexattr(path, name) ? -errno : 0;
}

/* Length of the xattr, or -errno. */
static int has(const char *path, const char *name)
{
	char buf[32];
	int len = getxattr(path, name, buf, sizeof(buf));

	return len < 0 ? -errno : len;
}

static void assert_label(const char *path, const char *want, const char *what)
{
	char buf[32] = {};
	int len;

	len = getxattr(path, ZONE, buf, sizeof(buf));
	if (ASSERT_EQ(len < 0 ? -errno : len, (int)strlen(want) + 1, what))
		ASSERT_STREQ(buf, want, what);
}

static int make_file(const char *path, const char *label)
{
	int fd = open(path, O_CREAT | O_WRONLY, 0644);

	if (fd < 0)
		return -errno;
	close(fd);
	return label ? set(path, ZONE, label) : 0;
}

/* The policy owns the name, so no capability is needed to write it. */
static void test_relabel_file_without_cap(struct lsm_xattr_skipcap *skel)
{
	__u32 claimed = skel->bss->claimed;
	__u64 caps = 0;

	if (!ASSERT_OK(cap_disable_effective(1ULL << CAP_SYS_ADMIN, &caps),
		       "drop CAP_SYS_ADMIN"))
		return;
	ASSERT_OK(set(FILE, ZONE, "alpha"), "relabel without CAP_SYS_ADMIN");
	ASSERT_OK(cap_enable_effective(caps, NULL), "restore CAP_SYS_ADMIN");
	assert_label(FILE, "alpha", "the file carries the new label");
	ASSERT_GT(skel->bss->claimed, claimed, "claimed");
}

/* And none to take it off again. */
static void test_strip_file_without_cap(struct lsm_xattr_skipcap *skel)
{
	__u64 caps = 0;

	if (!ASSERT_OK(set(FILE, ZONE, "alpha"), "label the file"))
		return;
	if (!ASSERT_OK(cap_disable_effective(1ULL << CAP_SYS_ADMIN, &caps),
		       "drop CAP_SYS_ADMIN"))
		return;
	ASSERT_OK(unset(FILE, ZONE), "strip without CAP_SYS_ADMIN");
	ASSERT_OK(cap_enable_effective(caps, NULL), "restore CAP_SYS_ADMIN");
	ASSERT_EQ(has(FILE, ZONE), -ENODATA, "the label is gone");
}

/* The same name on a cgroup, which carries it in its kernfs node. */
static void test_relabel_cgroup_without_cap(struct lsm_xattr_skipcap *skel)
{
	char buf[32] = {};
	__u64 caps = 0;
	int len;

	if (!ASSERT_OK(cap_disable_effective(1ULL << CAP_SYS_ADMIN, &caps),
		       "drop CAP_SYS_ADMIN"))
		return;
	ASSERT_OK(set_cgroup_xattr(SKIPCAP_CG, ZONE, "alpha") ? -errno : 0,
		  "relabel a cgroup without CAP_SYS_ADMIN");
	ASSERT_OK(cap_enable_effective(caps, NULL), "restore CAP_SYS_ADMIN");
	len = fgetxattr(cgroup_fd, ZONE, buf, sizeof(buf));
	if (ASSERT_EQ(len < 0 ? -errno : len, (int)sizeof("alpha"),
		      "the cgroup carries the new label"))
		ASSERT_STREQ(buf, "alpha", "the cgroup's label");
}

/* Any other security. name is left to the capability check. */
static void test_unowned_name_needs_cap(struct lsm_xattr_skipcap *skel)
{
	__u64 caps = 0;

	if (!ASSERT_OK(cap_disable_effective(1ULL << CAP_SYS_ADMIN, &caps),
		       "drop CAP_SYS_ADMIN"))
		return;
	ASSERT_EQ(set(FILE, OTHER, "1"), -EPERM,
		  "set an unowned name without CAP_SYS_ADMIN");
	ASSERT_OK(cap_enable_effective(caps, NULL), "restore CAP_SYS_ADMIN");
	ASSERT_EQ(has(FILE, OTHER), -ENODATA, "nothing was written");
}

/* Removing one is gated the same way. */
static void test_remove_unowned_needs_cap(struct lsm_xattr_skipcap *skel)
{
	__u64 caps = 0;

	if (!ASSERT_OK(set(FILE, OTHER, "1"), "set an unowned name with the cap"))
		return;
	if (!ASSERT_OK(cap_disable_effective(1ULL << CAP_SYS_ADMIN, &caps),
		       "drop CAP_SYS_ADMIN"))
		return;
	ASSERT_EQ(unset(FILE, OTHER), -EPERM,
		  "remove an unowned name without CAP_SYS_ADMIN");
	ASSERT_OK(cap_enable_effective(caps, NULL), "restore CAP_SYS_ADMIN");
	ASSERT_EQ(has(FILE, OTHER), (int)sizeof("1"), "it is still there");
	ASSERT_OK(unset(FILE, OTHER), "remove it with the cap");
}

/* Skipping the capability check is not permission: what the policy refuses
 * stays refused for a caller holding CAP_SYS_ADMIN.
 */
static void test_policy_gate_still_applies(struct lsm_xattr_skipcap *skel)
{
	__u32 denied = skel->bss->denied;

	ASSERT_EQ(set(LOCKED, ZONE, "alpha"), -EPERM,
		  "relabel a locked file with CAP_SYS_ADMIN");
	ASSERT_EQ(unset(LOCKED, ZONE), -EPERM,
		  "strip a locked file with CAP_SYS_ADMIN");
	assert_label(LOCKED, "locked", "the label is untouched");
	ASSERT_EQ(skel->bss->denied, denied + 2, "denied");
}

static void cleanup(void)
{
	remove(FILE);
	remove(LOCKED);
	remove(BASE);
}

void test_lsm_xattr_skipcap(void)
{
	struct lsm_xattr_skipcap *skel = NULL;
	bool cgroups = false;
	int err;

	cleanup();
	if (!ASSERT_OK(mkdir(BASE, 0755), "mkdir base"))
		return;

	err = make_file(FILE, NULL);
	if (!ASSERT_OK(err, "make the file"))
		goto out;
	err = set(FILE, ZONE, "plain");
	if (err == -EOPNOTSUPP) {
		printf("%s:SKIP:local fs doesn't support xattr (%d)\n"
		       "To run this test, make sure /tmp filesystem supports xattr.\n",
		       __func__, -err);
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(err, "label the file") ||
	    !ASSERT_OK(unset(FILE, ZONE), "start unlabelled") ||
	    !ASSERT_OK(make_file(LOCKED, "locked"), "make the locked file"))
		goto out;

	if (!ASSERT_OK(setup_cgroup_environment(), "setup cgroup environment"))
		goto out;
	cgroups = true;
	cgroup_fd = create_and_get_cgroup(SKIPCAP_CG);
	if (!ASSERT_OK_FD(cgroup_fd, "create a cgroup"))
		goto out;
	if (set_cgroup_xattr(SKIPCAP_CG, ZONE, "plain")) {
		printf("%s:SKIP:cannot set %s on a cgroup (errno %d)\n",
		       __func__, ZONE, errno);
		test__skip();
		goto out;
	}

	skel = lsm_xattr_skipcap__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open and load"))
		goto out;
	skel->bss->monitored_pid = getpid();
	if (!ASSERT_OK(lsm_xattr_skipcap__attach(skel), "attach"))
		goto out;

	if (test__start_subtest("relabel_file_without_cap"))
		test_relabel_file_without_cap(skel);
	if (test__start_subtest("strip_file_without_cap"))
		test_strip_file_without_cap(skel);
	if (test__start_subtest("relabel_cgroup_without_cap"))
		test_relabel_cgroup_without_cap(skel);
	if (test__start_subtest("unowned_name_needs_cap"))
		test_unowned_name_needs_cap(skel);
	if (test__start_subtest("remove_unowned_needs_cap"))
		test_remove_unowned_needs_cap(skel);
	if (test__start_subtest("policy_gate_still_applies"))
		test_policy_gate_still_applies(skel);
out:
	lsm_xattr_skipcap__destroy(skel);
	if (cgroup_fd >= 0)
		close(cgroup_fd);
	cgroup_fd = -1;
	if (cgroups)
		cleanup_cgroup_environment();
	cleanup();
}
