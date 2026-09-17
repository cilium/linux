// SPDX-License-Identifier: GPL-2.0
/* Cgroups under the zone policy: a cgroup created below a labelled one comes
 * up labelled, control files included; one in the trusted zone is created,
 * entered or written only from inside it; an enforced task cannot leave for
 * an unlabelled cgroup; and only the trusted zone writes the label at all,
 * with or without CAP_SYS_ADMIN.
 *
 * The tree is brought up before the policy attaches, the zoned root labelled
 * "default" and a first pod "trusted", with the manager parked in that pod
 * to place the test process. The pods are created under policy.
 */
#define ZONE_TMP "/tmp/test_progs_zone_cgroup_"
#include "lsm_zone_helpers.h"
#include "cap_helpers.h"
#include "lsm_zone_cgroup.skel.h"

#define FILE_CAPLESS	ZONE_TMP "capless"

static struct zone_env zenv;
static int pod_fd = -1, payload_fd = -1, pod1_fd = -1;
static int trusted_payload_fd = -1, plain_pod_fd = -1;

/* The cgroup the test process sits in, read back from /proc/self/cgroup and
 * compared by its path below the work directory.
 */
static void assert_in(const char *cg, const char *what)
{
	char line[PATH_MAX] = {}, want[PATH_MAX];
	const char *got = line;
	size_t n, len;
	FILE *f;

	n = snprintf(want, sizeof(want), "%s", cg) - 1;
	want[n] = 0;	/* drop the trailing slash */
	f = fopen("/proc/self/cgroup", "r");
	if (!ASSERT_OK_PTR(f, "open /proc/self/cgroup"))
		return;
	while (fgets(line, sizeof(line), f)) {
		if (!strncmp(line, "0::", 3))
			break;
		line[0] = 0;
	}
	fclose(f);
	line[strcspn(line, "\n")] = 0;
	len = strlen(line);
	if (len >= n)
		got = line + len - n;
	ASSERT_STREQ(got, want, what);
}

/* A pod and its payload come up carrying the zone of what they were created
 * under: "default" below the zoned root, "trusted" below the trusted pod.
 */
static void test_pod_inherits_zone(struct lsm_zone_cgroup *skel)
{
	ASSERT_OK(skel->data->label_err, "label_err");
	assert_zone(pod_fd, ZONE_DEFAULT, "pod inherits default");
	assert_zone(payload_fd, ZONE_DEFAULT, "payload inherits default");
	assert_zone(trusted_payload_fd, ZONE_TRUSTED, "trusted payload inherits trusted");
	ASSERT_GE(skel->bss->nr_labelled, 4, "nr_labelled");
}

/* The control files come up labelled too, so that a hook holding one open
 * can tell which zone its cgroup is in.
 */
static void test_control_files_inherit(struct lsm_zone_cgroup *skel)
{
	int fd;

	fd = openat(payload_fd, "cgroup.procs", O_RDONLY);
	if (ASSERT_OK_FD(fd, "open payload procs")) {
		assert_zone(fd, ZONE_DEFAULT, "payload procs inherits default");
		close(fd);
	}
	fd = openat(payload_fd, "cgroup.threads", O_RDONLY);
	if (ASSERT_OK_FD(fd, "open payload threads")) {
		assert_zone(fd, ZONE_DEFAULT, "payload threads inherits default");
		close(fd);
	}
	fd = openat(trusted_payload_fd, "cgroup.procs", O_RDONLY);
	if (ASSERT_OK_FD(fd, "open trusted payload procs")) {
		assert_zone(fd, ZONE_TRUSTED, "trusted payload procs inherits trusted");
		close(fd);
	}
	ASSERT_GE(skel->bss->nr_labelled_files, 4, "nr_labelled_files");
}

/* A pod outside the zoned tree stays unlabelled: nothing to inherit. */
static void test_unzoned_pod_stays_unlabelled(struct lsm_zone_cgroup *skel)
{
	char buf[64] = {};
	int fd;

	ASSERT_EQ(read_zone(plain_pod_fd, buf, sizeof(buf)), -ENODATA,
		  "unzoned pod stays unlabelled");
	fd = openat(plain_pod_fd, "cgroup.procs", O_RDONLY);
	if (ASSERT_OK_FD(fd, "open unzoned pod procs")) {
		ASSERT_EQ(read_zone(fd, buf, sizeof(buf)), -ENODATA,
			  "unzoned pod procs stays unlabelled");
		close(fd);
	}
}

/* A cgroup in the trusted zone cannot be created from the default zone or
 * from none: the mkdir fails with the hook's own EPERM, not ENOMEM, and
 * leaves nothing behind.
 */
static void test_trusted_mkdir_from_outside_refused(struct lsm_zone_cgroup *skel)
{
	__u32 denied = skel->bss->grow_denied;

	if (!ASSERT_OK(enter(PAYLOAD_CG), "enter default payload"))
		return;
	ASSERT_EQ(mkdirat(zenv.trusted_fd, "evil", 0755) ? -errno : 0, -EPERM,
		  "default: mkdir below trusted pod");
	ASSERT_EQ(faccessat(zenv.trusted_fd, "evil", F_OK, 0) ? -errno : 0, -ENOENT,
		  "default: nothing created");
	if (!ASSERT_OK(enter(PLAIN_POD_CG), "enter unzoned pod"))
		return;
	ASSERT_EQ(mkdirat(zenv.trusted_fd, "evil", 0755) ? -errno : 0, -EPERM,
		  "unzoned: mkdir below trusted pod");
	ASSERT_EQ(faccessat(zenv.trusted_fd, "evil", F_OK, 0) ? -errno : 0, -ENOENT,
		  "unzoned: nothing created");
	ASSERT_EQ(skel->bss->grow_denied - denied, 2, "grow_denied");
}

/* From inside the trusted zone the mkdir goes through, and the new cgroup
 * comes up trusted like its parent.
 */
static void test_trusted_mkdir_from_inside_allowed(struct lsm_zone_cgroup *skel)
{
	int fd;

	if (!ASSERT_OK(enter(TRUSTED_CG), "enter trusted pod"))
		return;
	if (!ASSERT_OK(mkdirat(zenv.trusted_fd, "inside", 0755) ? -errno : 0,
		       "trusted: mkdir below trusted pod"))
		return;
	fd = openat(zenv.trusted_fd, "inside", O_RDONLY);
	if (ASSERT_OK_FD(fd, "open new cgroup")) {
		assert_zone(fd, ZONE_TRUSTED, "trusted: new cgroup inherits trusted");
		close(fd);
	}
	ASSERT_OK(unlinkat(zenv.trusted_fd, "inside", AT_REMOVEDIR) ? -errno : 0,
		  "rmdir new cgroup");
}

/* Nothing enters the trusted zone from outside it: writing one's own pid
 * into a trusted cgroup's cgroup.procs is refused at the open already, since
 * the control file carries the trusted label.
 */
static void test_enter_trusted_by_procs_denied(struct lsm_zone_cgroup *skel)
{
	__u32 denied = skel->bss->write_denied;

	if (!ASSERT_OK(enter(PAYLOAD_CG), "enter default payload"))
		return;
	ASSERT_EQ(self_enter(TRUSTED_PAYLOAD_CG), -EPERM,
		  "default: self-migrate into trusted payload");
	ASSERT_EQ(self_enter(TRUSTED_CG), -EPERM,
		  "default: self-migrate into trusted pod");
	assert_in(PAYLOAD_CG, "default: still in the payload");
	if (!ASSERT_OK(enter(PLAIN_POD_CG), "enter unzoned pod"))
		return;
	ASSERT_EQ(self_enter(TRUSTED_PAYLOAD_CG), -EPERM,
		  "unzoned: self-migrate into trusted payload");
	assert_in(PLAIN_POD_CG, "unzoned: still in the unzoned pod");
	ASSERT_EQ(skel->bss->write_denied - denied, 3, "write_denied");
}

/* Nor by cgroup.threads, labelled like cgroup.procs. */
static void test_enter_trusted_by_threads_denied(struct lsm_zone_cgroup *skel)
{
	__u32 denied = skel->bss->write_denied;

	if (!ASSERT_OK(enter(PAYLOAD_CG), "enter default payload"))
		return;
	ASSERT_EQ(self_enter_thread(TRUSTED_PAYLOAD_CG), -EPERM,
		  "default: thread into trusted payload");
	ASSERT_EQ(self_enter_thread(TRUSTED_CG), -EPERM,
		  "default: thread into trusted pod");
	assert_in(PAYLOAD_CG, "default: still in the payload");
	ASSERT_EQ(skel->bss->write_denied - denied, 2, "write_denied");
}

/* Nor by clone3(CLONE_INTO_CGROUP), which opens no control file and goes
 * straight to task_cgroup_attach, from the default zone or from none.
 */
static void test_enter_trusted_by_clone3_denied(struct lsm_zone_cgroup *skel)
{
	__u32 denied = skel->bss->enter_denied;

	if (!ASSERT_OK(enter(PAYLOAD_CG), "enter default payload"))
		return;
	ASSERT_EQ(clone_into(trusted_payload_fd), -EPERM,
		  "default: clone3 into trusted payload");
	if (!ASSERT_OK(enter(PLAIN_POD_CG), "enter unzoned pod"))
		return;
	ASSERT_EQ(clone_into(trusted_payload_fd), -EPERM,
		  "unzoned: clone3 into trusted payload");
	ASSERT_EQ(skel->bss->enter_denied - denied, 2, "enter_denied");
}

/* An enforced task cannot leave for an unlabelled cgroup to shed enforcement,
 * by writing its own pid there or by forking a child into it: the unlabelled
 * control file opens fine, and task_cgroup_attach refuses the move.
 */
static void test_escape_to_unlabelled_denied(struct lsm_zone_cgroup *skel)
{
	__u32 denied = skel->bss->enter_denied;

	if (!ASSERT_OK(enter(PAYLOAD_CG), "enter default payload"))
		return;
	ASSERT_EQ(self_enter(PLAIN_POD_CG), -EPERM,
		  "default: self-migrate into unlabelled cgroup");
	ASSERT_EQ(clone_into(plain_pod_fd), -EPERM,
		  "default: clone3 into unlabelled cgroup");
	ASSERT_EQ(skel->bss->enter_denied - denied, 2,
		  "escape refused by task_cgroup_attach");
	assert_in(PAYLOAD_CG, "default: still in the payload");
}

/* The trusted zone is the control plane: it writes a trusted cgroup's control
 * files and places a task anywhere, into the trusted zone, into an unlabelled
 * cgroup, or itself into the default zone.
 */
static void test_trusted_moves_anything(struct lsm_zone_cgroup *skel)
{
	if (!ASSERT_OK(enter(TRUSTED_PAYLOAD_CG), "enter trusted payload"))
		return;
	ASSERT_OK(try_open(trusted_payload_fd, "cgroup.procs", O_WRONLY),
		  "trusted: write trusted payload procs");
	ASSERT_OK(clone_into(trusted_payload_fd),
		  "trusted: clone3 into trusted payload");
	ASSERT_OK(clone_into(plain_pod_fd),
		  "trusted: clone3 into unlabelled cgroup");
	ASSERT_OK(self_enter(PAYLOAD_CG),
		  "trusted: self-migrate into default payload");
	assert_in(PAYLOAD_CG, "trusted: moved into the payload");
}

/* The default zone cannot promote its own cgroup, nor any other. */
static void test_default_cannot_relabel_cgroup(struct lsm_zone_cgroup *skel)
{
	__u32 denied = skel->bss->relabel_denied;

	if (!ASSERT_OK(enter(PAYLOAD_CG), "enter default payload"))
		return;
	ASSERT_EQ(set_cg_zone(PAYLOAD_CG, ZONE_TRUSTED), -EPERM,
		  "default: relabel own cgroup");
	ASSERT_EQ(set_cg_zone(POD1_CG, ZONE_TRUSTED), -EPERM,
		  "default: relabel another pod");
	assert_zone(payload_fd, ZONE_DEFAULT, "default: own label intact");
	assert_zone(pod1_fd, ZONE_DEFAULT, "default: other label intact");
	ASSERT_EQ(skel->bss->relabel_denied - denied, 2, "relabel_denied");
}

/* Nor strip the label off, which would take it out of the policy. */
static void test_default_cannot_strip_cgroup_label(struct lsm_zone_cgroup *skel)
{
	if (!ASSERT_OK(enter(PAYLOAD_CG), "enter default payload"))
		return;
	ASSERT_EQ(fremovexattr(payload_fd, ZONE_XATTR) ? -errno : 0, -EPERM,
		  "default: strip own cgroup label");
	assert_zone(payload_fd, ZONE_DEFAULT, "default: label intact");
}

/* A task in no zone cannot label its cgroup into one, trusted or not. */
static void test_unzoned_cannot_mint_trust(struct lsm_zone_cgroup *skel)
{
	char buf[64] = {};

	if (!ASSERT_OK(enter(PLAIN_POD_CG), "enter unzoned pod"))
		return;
	ASSERT_EQ(set_cg_zone(PLAIN_POD_CG, ZONE_TRUSTED), -EPERM,
		  "unzoned: mint trust");
	ASSERT_EQ(set_cg_zone(PLAIN_POD_CG, ZONE_DEFAULT), -EPERM,
		  "unzoned: label own cgroup");
	ASSERT_EQ(read_zone(plain_pod_fd, buf, sizeof(buf)), -ENODATA,
		  "unzoned: pod still unlabelled");
}

/* The trusted zone relabels a pod, strips the label and restores it. */
static void test_trusted_relabels_pod(struct lsm_zone_cgroup *skel)
{
	char buf[64] = {};

	if (!ASSERT_OK(enter(TRUSTED_PAYLOAD_CG), "enter trusted payload"))
		return;
	ASSERT_OK(set_cg_zone(POD1_CG, ZONE_TRUSTED), "trusted: relabel a pod");
	assert_zone(pod1_fd, ZONE_TRUSTED, "trusted: pod relabelled");
	ASSERT_OK(fremovexattr(pod1_fd, ZONE_XATTR) ? -errno : 0,
		  "trusted: strip pod label");
	ASSERT_EQ(read_zone(pod1_fd, buf, sizeof(buf)), -ENODATA,
		  "trusted: pod label gone");
	ASSERT_OK(set_cg_zone(POD1_CG, ZONE_DEFAULT), "trusted: relabel it back");
	assert_zone(pod1_fd, ZONE_DEFAULT, "trusted: pod relabelled back");
}

/* The policy claims the label for the capability check, so a trusted task
 * relabels a file and a cgroup without CAP_SYS_ADMIN, while any other
 * security. name still needs it.
 */
static void test_relabel_without_cap_sys_admin(struct lsm_zone_cgroup *skel)
{
	char buf[64] = {};
	__u64 caps = 0;
	int err;

	if (!ASSERT_OK(enter(TRUSTED_PAYLOAD_CG), "enter trusted payload"))
		return;
	if (!ASSERT_OK(make_page_file(FILE_CAPLESS), "make capless file"))
		return;
	err = getxattr(FILE_CAPLESS, ZONE_XATTR, buf, sizeof(buf)) < 0 ? -errno : 0;
	if (err == -EOPNOTSUPP) {
		printf("%s:SKIP:local fs doesn't support xattr (%d)\n"
		       "To run this test, make sure /tmp filesystem supports xattr.\n",
		       __func__, -err);
		test__skip();
		goto out;
	}
	ASSERT_OK(skel->data->stamp_err, "stamp_err");
	assert_file_zone(FILE_CAPLESS, ZONE_TRUSTED, "trusted: file stamped trusted");
	if (!ASSERT_OK(cap_disable_effective(1ULL << CAP_SYS_ADMIN, &caps),
		       "drop CAP_SYS_ADMIN"))
		goto out;
	ASSERT_OK(set_zone(FILE_CAPLESS, ZONE_DEFAULT),
		  "trusted, no CAP_SYS_ADMIN: relabel file");
	assert_file_zone(FILE_CAPLESS, ZONE_DEFAULT,
			 "trusted, no CAP_SYS_ADMIN: file relabelled");
	ASSERT_OK(removexattr(FILE_CAPLESS, ZONE_XATTR) ? -errno : 0,
		  "trusted, no CAP_SYS_ADMIN: strip file label");
	err = getxattr(FILE_CAPLESS, ZONE_XATTR, buf, sizeof(buf)) < 0 ? -errno : 0;
	ASSERT_EQ(err, -ENODATA, "trusted, no CAP_SYS_ADMIN: file label gone");
	ASSERT_OK(set_cg_zone(POD1_CG, ZONE_TRUSTED),
		  "trusted, no CAP_SYS_ADMIN: relabel a pod");
	assert_zone(pod1_fd, ZONE_TRUSTED, "trusted, no CAP_SYS_ADMIN: pod relabelled");
	ASSERT_OK(set_cg_zone(POD1_CG, ZONE_DEFAULT),
		  "trusted, no CAP_SYS_ADMIN: relabel it back");
	ASSERT_EQ(setxattr(FILE_CAPLESS, "security.bpf.other", "x", 2, 0) ?
		  -errno : 0, -EPERM,
		  "trusted, no CAP_SYS_ADMIN: unowned name");
	ASSERT_OK(cap_enable_effective(caps, NULL), "restore CAP_SYS_ADMIN");
out:
	remove(FILE_CAPLESS);
}

/* A trusted cgroup's control files cannot be opened for writing from the
 * default zone or from none.
 */
static void test_write_trusted_procs_denied(struct lsm_zone_cgroup *skel)
{
	__u32 denied = skel->bss->write_denied;

	if (!ASSERT_OK(enter(PAYLOAD_CG), "enter default payload"))
		return;
	ASSERT_EQ(try_open(trusted_payload_fd, "cgroup.procs", O_WRONLY), -EPERM,
		  "default: write trusted payload procs");
	ASSERT_EQ(try_open(trusted_payload_fd, "cgroup.threads", O_RDWR), -EPERM,
		  "default: write trusted payload threads");
	ASSERT_EQ(try_open(zenv.trusted_fd, "cgroup.procs", O_WRONLY), -EPERM,
		  "default: write trusted pod procs");
	if (!ASSERT_OK(enter(PLAIN_POD_CG), "enter unzoned pod"))
		return;
	ASSERT_EQ(try_open(trusted_payload_fd, "cgroup.procs", O_WRONLY), -EPERM,
		  "unzoned: write trusted payload procs");
	ASSERT_EQ(skel->bss->write_denied - denied, 4, "write_denied");
}

/* Reading them is fine from anywhere, as is opening a default-zone cgroup's
 * control file for writing: it is the move that is gated there.
 */
static void test_read_trusted_procs_allowed(struct lsm_zone_cgroup *skel)
{
	if (!ASSERT_OK(enter(PAYLOAD_CG), "enter default payload"))
		return;
	ASSERT_OK(try_open(trusted_payload_fd, "cgroup.procs", O_RDONLY),
		  "default: read trusted payload procs");
	ASSERT_OK(try_open(zenv.trusted_fd, "cgroup.procs", O_RDONLY),
		  "default: read trusted pod procs");
	ASSERT_OK(try_open(payload_fd, "cgroup.procs", O_WRONLY),
		  "default: write own payload procs");
	if (!ASSERT_OK(enter(PLAIN_POD_CG), "enter unzoned pod"))
		return;
	ASSERT_OK(try_open(trusted_payload_fd, "cgroup.procs", O_RDONLY),
		  "unzoned: read trusted payload procs");
}

void test_lsm_zone_cgroup(void)
{
	struct lsm_zone_cgroup *skel = NULL;
	int err;

	remove(FILE_CAPLESS);
	err = zone_bootstrap(&zenv);
	if (err == -EOPNOTSUPP) {
		printf("%s:SKIP:cannot set %s on a cgroup\n", __func__, ZONE_XATTR);
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(err, "zone_bootstrap"))
		goto out;

	skel = lsm_zone_cgroup__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel open_and_load"))
		goto out;
	skel->bss->monitored_pid = getpid();
	if (!ASSERT_OK(lsm_zone_cgroup__attach(skel), "skel attach"))
		goto out;

	/* The manager's pods, created under policy: two below the zoned root,
	 * one with a payload; one below the trusted pod, from inside it; and
	 * one below the unzoned root.
	 */
	pod_fd = create_and_get_cgroup(POD_CG);
	if (!ASSERT_OK_FD(pod_fd, "create pod"))
		goto out;
	payload_fd = create_and_get_cgroup(PAYLOAD_CG);
	if (!ASSERT_OK_FD(payload_fd, "create payload"))
		goto out;
	pod1_fd = create_and_get_cgroup(POD1_CG);
	if (!ASSERT_OK_FD(pod1_fd, "create second pod"))
		goto out;
	if (!ASSERT_OK(enter(TRUSTED_CG), "enter trusted pod"))
		goto out;
	trusted_payload_fd = create_and_get_cgroup(TRUSTED_PAYLOAD_CG);
	if (!ASSERT_OK_FD(trusted_payload_fd, "create trusted payload"))
		goto out;
	plain_pod_fd = create_and_get_cgroup(PLAIN_POD_CG);
	if (!ASSERT_OK_FD(plain_pod_fd, "create unzoned pod"))
		goto out;

	if (test__start_subtest("pod_inherits_zone"))
		test_pod_inherits_zone(skel);
	if (test__start_subtest("control_files_inherit"))
		test_control_files_inherit(skel);
	if (test__start_subtest("unzoned_pod_stays_unlabelled"))
		test_unzoned_pod_stays_unlabelled(skel);
	if (test__start_subtest("trusted_mkdir_from_outside_refused"))
		test_trusted_mkdir_from_outside_refused(skel);
	if (test__start_subtest("trusted_mkdir_from_inside_allowed"))
		test_trusted_mkdir_from_inside_allowed(skel);
	if (test__start_subtest("enter_trusted_by_procs_denied"))
		test_enter_trusted_by_procs_denied(skel);
	if (test__start_subtest("enter_trusted_by_threads_denied"))
		test_enter_trusted_by_threads_denied(skel);
	if (test__start_subtest("enter_trusted_by_clone3_denied"))
		test_enter_trusted_by_clone3_denied(skel);
	if (test__start_subtest("escape_to_unlabelled_denied"))
		test_escape_to_unlabelled_denied(skel);
	if (test__start_subtest("trusted_moves_anything"))
		test_trusted_moves_anything(skel);
	if (test__start_subtest("default_cannot_relabel_cgroup"))
		test_default_cannot_relabel_cgroup(skel);
	if (test__start_subtest("default_cannot_strip_cgroup_label"))
		test_default_cannot_strip_cgroup_label(skel);
	if (test__start_subtest("unzoned_cannot_mint_trust"))
		test_unzoned_cannot_mint_trust(skel);
	if (test__start_subtest("trusted_relabels_pod"))
		test_trusted_relabels_pod(skel);
	if (test__start_subtest("relabel_without_cap_sys_admin"))
		test_relabel_without_cap_sys_admin(skel);
	if (test__start_subtest("write_trusted_procs_denied"))
		test_write_trusted_procs_denied(skel);
	if (test__start_subtest("read_trusted_procs_allowed"))
		test_read_trusted_procs_allowed(skel);
out:
	if (plain_pod_fd >= 0)
		close(plain_pod_fd);
	if (trusted_payload_fd >= 0)
		close(trusted_payload_fd);
	if (pod1_fd >= 0)
		close(pod1_fd);
	if (payload_fd >= 0)
		close(payload_fd);
	if (pod_fd >= 0)
		close(pod_fd);
	plain_pod_fd = trusted_payload_fd = pod1_fd = payload_fd = pod_fd = -1;
	lsm_zone_cgroup__destroy(skel);
	zone_teardown(&zenv);
	remove(FILE_CAPLESS);
}
