// SPDX-License-Identifier: GPL-2.0
/*
 * Anonymous inodes under a BPF LSM policy. A userfaultfd is the interesting
 * one: it hands a task a way to supply the contents of a page on demand,
 * which no mapping hook sees, so a policy that enforces W^X wants it refused
 * rather than labelled. inode_init_security_anon is where that is decided,
 * and this test pins both what can be done there and what cannot: the class
 * name identifies the object and an error refuses it, while the label a
 * filesystem would carry does not exist on either side of the interface.
 */
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <test_progs.h>
#include "lsm_anon_inode.skel.h"

#define ORIGIN		"security.bpf.origin"

#ifndef __NR_userfaultfd
#define __NR_userfaultfd 323
#endif
#ifndef UFFD_USER_MODE_ONLY
#define UFFD_USER_MODE_ONLY 1
#endif

static int uffd(void)
{
	int fd = syscall(__NR_userfaultfd, O_CLOEXEC | UFFD_USER_MODE_ONLY);

	return fd < 0 ? -errno : fd;
}

/* The policy refuses a userfaultfd to the task it watches, and the refusal
 * reaches the caller as the error the hook returned.
 */
static void test_refuse_userfaultfd(struct lsm_anon_inode *skel)
{
	__u32 refused = skel->bss->uffd_refused;
	__u32 seen = skel->bss->uffd_seen;
	int fd;

	skel->bss->refuse_uffd = 1;
	ASSERT_EQ(uffd(), -EPERM, "userfaultfd refused");
	ASSERT_EQ(skel->bss->uffd_refused - refused, 1, "uffd_refused");
	ASSERT_EQ(skel->bss->uffd_seen - seen, 1, "uffd_seen");

	/* With the toggle clear the same call goes through, so the refusal
	 * came from the policy and not from the configuration.
	 */
	skel->bss->refuse_uffd = 0;
	fd = uffd();
	if (ASSERT_OK_FD(fd, "userfaultfd allowed"))
		close(fd);
	ASSERT_EQ(skel->bss->uffd_seen - seen, 2, "uffd_seen again");
	ASSERT_EQ(skel->bss->uffd_refused - refused, 1, "nothing else refused");
}

/* The hook sees every anonymous inode, told apart by the name of its class:
 * a memfd is not a userfaultfd and is not caught by a rule about one.
 */
static void test_name_identifies_class(struct lsm_anon_inode *skel)
{
	__u32 memfd = skel->bss->memfd_seen;
	__u32 refused = skel->bss->uffd_refused;
	int fd;

	skel->bss->refuse_uffd = 1;
	fd = syscall(__NR_memfd_create, "probe", MFD_CLOEXEC);
	if (ASSERT_OK_FD(fd < 0 ? -errno : fd, "memfd allowed")) {
		ASSERT_STREQ(skel->bss->seen_name, "[memfd]", "the class name");
		close(fd);
	}
	ASSERT_EQ(skel->bss->memfd_seen - memfd, 1, "memfd_seen");
	ASSERT_EQ(skel->bss->uffd_refused - refused, 0, "not refused as a uffd");
	skel->bss->refuse_uffd = 0;
}

/* The label itself is the part that does not exist. An anonymous inode has
 * no xattr storage, and a BPF LSM cannot serve one in its place the way
 * SELinux does from its in-core label, so userspace can neither read a
 * label off a userfaultfd nor put one there.
 */
static void test_no_xattr_on_anon(struct lsm_anon_inode *skel)
{
	char buf[64] = {};
	int fd;

	fd = uffd();
	if (!ASSERT_OK_FD(fd, "userfaultfd"))
		return;
	ASSERT_EQ(fgetxattr(fd, ORIGIN, buf, sizeof(buf)) < 0 ? -errno : 0,
		  -EOPNOTSUPP, "no label to read");
	ASSERT_EQ(fsetxattr(fd, ORIGIN, "x", 2, 0) ? -errno : 0, -EOPNOTSUPP,
		  "nowhere to write one");
	ASSERT_EQ(flistxattr(fd, buf, sizeof(buf)) < 0 ? -errno : 0, 0,
		  "nothing listed");
	close(fd);
}

void test_lsm_anon_inode(void)
{
	struct lsm_anon_inode *skel;
	int fd;

	/* Nothing to do where the kernel hands out no userfaultfd. */
	fd = uffd();
	if (fd < 0) {
		printf("%s:SKIP:userfaultfd unavailable (%d)\n", __func__, -fd);
		test__skip();
		return;
	}
	close(fd);

	skel = lsm_anon_inode__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open and load"))
		return;
	skel->bss->monitored_pid = getpid();
	if (!ASSERT_OK(lsm_anon_inode__attach(skel), "attach"))
		goto out;

	if (test__start_subtest("refuse_userfaultfd"))
		test_refuse_userfaultfd(skel);
	if (test__start_subtest("name_identifies_class"))
		test_name_identifies_class(skel);
	if (test__start_subtest("no_xattr_on_anon"))
		test_no_xattr_on_anon(skel);
out:
	skel->bss->refuse_uffd = 0;
	lsm_anon_inode__destroy(skel);
}
