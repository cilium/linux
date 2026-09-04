// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/xattr.h>
#include <test_progs.h>
#include "cgroup_helpers.h"

#include "lsm_cgroup_init_xattr.skel.h"

/*
 * A cgroup only ever comes into existence through a mkdir(2) in cgroupfs -
 * cgroup_kf_syscall_ops has no other directory-creating entry point - so a
 * manager creating one for a container, whether directly or by way of a
 * transient unit, ends up here. Stand in for the manager with plain mkdirs.
 */
#define ZONE		"prod"
#define ZONE_XATTR	"security.bpf.zone"

#define ROOT_CG		"zoned/"
#define POD_CG		ROOT_CG "pod0/"
#define PAYLOAD_CG	POD_CG "payload/"
#define PLAIN_CG	"unzoned/"
#define PLAIN_POD_CG	PLAIN_CG "pod0/"

#define TMP_FILE	"/tmp/selftests_lsm_cgroup_init_xattr"

static int read_zone(int cgroup_fd, char *buf, size_t sz)
{
	int ret = fgetxattr(cgroup_fd, ZONE_XATTR, buf, sz);

	return ret < 0 ? -errno : ret;
}

static void assert_zone(int cgroup_fd, const char *what)
{
	char buf[64] = {};

	if (!ASSERT_EQ(read_zone(cgroup_fd, buf, sizeof(buf)),
		       (int)sizeof(ZONE), what))
		return;
	ASSERT_STREQ(buf, ZONE, what);
}

void test_lsm_cgroup_init_xattr(void)
{
	int root_fd = -1, pod_fd = -1, payload_fd = -1;
	int plain_fd = -1, plain_pod_fd = -1, fd;
	struct lsm_cgroup_init_xattr *skel = NULL;
	char buf[64] = {};

	if (!ASSERT_OK(setup_cgroup_environment(), "setup_cgroup_environment"))
		return;

	/* The zoned root stands in for the slice a manager parks pods under. */
	root_fd = create_and_get_cgroup(ROOT_CG);
	if (!ASSERT_OK_FD(root_fd, "create_zoned_root"))
		goto out;
	plain_fd = create_and_get_cgroup(PLAIN_CG);
	if (!ASSERT_OK_FD(plain_fd, "create_unzoned_root"))
		goto out;

	if (!ASSERT_OK(set_cgroup_xattr(ROOT_CG, ZONE_XATTR, ZONE),
		       "label_zoned_root")) {
		test__skip();
		goto out;
	}

	skel = lsm_cgroup_init_xattr__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		goto out;

	skel->bss->monitored_pid = getpid();
	if (!ASSERT_OK(lsm_cgroup_init_xattr__attach(skel), "skel_attach"))
		goto out;

	/* A pod created below the zoned root comes up carrying the zone. */
	pod_fd = create_and_get_cgroup(POD_CG);
	if (!ASSERT_OK_FD(pod_fd, "create_pod"))
		goto out;

	if (!skel->bss->nr_labelled) {
		test__skip();
		goto out;
	}
	ASSERT_OK(skel->data->label_err, "label_err");
	assert_zone(pod_fd, "pod_zone");

	/* And so does the payload cgroup nested inside it. */
	payload_fd = create_and_get_cgroup(PAYLOAD_CG);
	if (!ASSERT_OK_FD(payload_fd, "create_payload"))
		goto out;
	assert_zone(payload_fd, "payload_zone");

	ASSERT_EQ(skel->bss->nr_labelled, 2, "nr_labelled");

	/* A pod outside the zoned tree stays unlabelled. */
	plain_pod_fd = create_and_get_cgroup(PLAIN_POD_CG);
	if (!ASSERT_OK_FD(plain_pod_fd, "create_unzoned_pod"))
		goto out;
	ASSERT_EQ(read_zone(plain_pod_fd, buf, sizeof(buf)), -ENODATA,
		  "unzoned_pod_absent");
	ASSERT_EQ(skel->bss->nr_labelled, 2, "nr_labelled_unchanged");

	/*
	 * With the label on the cgroup itself, a program on an unrelated hook
	 * can tell which zone the task is running in.
	 */
	if (!ASSERT_OK(join_cgroup(PAYLOAD_CG), "join_payload"))
		goto out;

	fd = open(TMP_FILE, O_RDONLY | O_CREAT, 0644);
	if (!ASSERT_OK_FD(fd, "open_tmp_file"))
		goto out;
	close(fd);

	if (ASSERT_EQ(skel->bss->seen_len, sizeof(ZONE), "seen_len"))
		ASSERT_STREQ(skel->bss->seen_zone, ZONE, "seen_zone");
out:
	if (payload_fd >= 0)
		close(payload_fd);
	if (pod_fd >= 0)
		close(pod_fd);
	if (plain_pod_fd >= 0)
		close(plain_pod_fd);
	if (plain_fd >= 0)
		close(plain_fd);
	if (root_fd >= 0)
		close(root_fd);
	lsm_cgroup_init_xattr__destroy(skel);
	unlink(TMP_FILE);
	cleanup_cgroup_environment();
}
