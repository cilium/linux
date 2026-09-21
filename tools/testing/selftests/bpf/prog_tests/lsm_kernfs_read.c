// SPDX-License-Identifier: GPL-2.0
/* A kernfs label, read back from hooks other than the one that writes it.
 *
 * The label goes on the cgroup from userspace, the way a container manager
 * would place it, and the policy reads it off the node behind the cgroup the
 * task runs in -- once from a hook that may sleep and once from one that may
 * not. Before the getter came out of the kernfs hook restriction, neither
 * program would load at all.
 */
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <test_progs.h>
#include "cgroup_helpers.h"

#include "lsm_kernfs_read.skel.h"
#include "lsm_kernfs_read_fail.skel.h"

#define CGROUP		"/lsm_kernfs_read"
#define ZONE_XATTR	"security.bpf.zone"
#define ZONE		"prod"

static void test_read_off_hooks(struct lsm_kernfs_read *skel)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	int fd;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (!ASSERT_OK_FD(fd, "socket"))
		return;

	/* Sleepable hook: the program takes RCU for itself. */
	bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	ASSERT_EQ(skel->data->bind_ret, sizeof(ZONE), "read at bind");
	ASSERT_STREQ(skel->bss->bind_zone, ZONE, "zone at bind");

	/* Non-sleepable hook: RCU is already held for it. */
	addr.sin_port = htons(1);
	connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	ASSERT_EQ(skel->data->connect_ret, sizeof(ZONE), "read at connect");
	ASSERT_STREQ(skel->bss->connect_zone, ZONE, "zone at connect");

	close(fd);
}

/* An unlabelled cgroup reads back as having no label, not as some default. */
static void test_unlabelled_cgroup(struct lsm_kernfs_read *skel)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(1),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	int fd;

	skel->data->connect_ret = -999;
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (!ASSERT_OK_FD(fd, "socket"))
		return;
	connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	ASSERT_EQ(skel->data->connect_ret, -ENODATA, "no label to read");
	close(fd);
}

void test_lsm_kernfs_read(void)
{
	struct lsm_kernfs_read *skel = NULL;
	int cgroup_fd, err;

	RUN_TESTS(lsm_kernfs_read_fail);

	cgroup_fd = cgroup_setup_and_join(CGROUP);
	if (!ASSERT_OK_FD(cgroup_fd, "cgroup_setup_and_join"))
		return;

	skel = lsm_kernfs_read__open_and_load();
	if (!ASSERT_OK_PTR(skel, "lsm_kernfs_read__open_and_load"))
		goto out;
	skel->bss->monitored_pid = getpid();
	if (!ASSERT_OK(lsm_kernfs_read__attach(skel), "attach"))
		goto out;

	/* Before the label goes on, so no removexattr() is needed. */
	if (test__start_subtest("unlabelled_cgroup"))
		test_unlabelled_cgroup(skel);

	err = set_cgroup_xattr(CGROUP, ZONE_XATTR, ZONE);
	if (err && (errno == EOPNOTSUPP || errno == EPERM)) {
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(err, "label the cgroup"))
		goto out;

	if (test__start_subtest("read_off_hooks"))
		test_read_off_hooks(skel);
out:
	lsm_kernfs_read__destroy(skel);
	close(cgroup_fd);
	cleanup_cgroup_environment();
}
