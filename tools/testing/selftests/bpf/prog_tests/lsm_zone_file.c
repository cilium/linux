// SPDX-License-Identifier: GPL-2.0
/* W^X and code provenance on files, scoped by cgroup zone. The zoned root
 * plays the default zone, its trusted pod the trusted zone and the unzoned
 * root a tree the policy never labelled; the manager parked in the trusted
 * pod places the test process. What may be mapped executable follows the
 * file's label alone: byte-identical files with and without it, plus one on
 * ramfs where the label cannot be read at all.
 */
#define ZONE_TMP	"/tmp/test_progs_zone_file_"
#include "lsm_zone_helpers.h"
#include "lsm_zone_file.skel.h"

#define DEFAULT_CG	ROOT_CG
#define UNZONED_CG	PLAIN_CG

#define FILE_EXEC_PLAIN	ZONE_TMP "exec_plain"
#define FILE_EXEC_TRUSTED ZONE_TMP "exec_trusted"
#define NOXATTR_DIR	ZONE_TMP "noxattr"
#define FILE_EXEC_NOXATTR NOXATTR_DIR "/exec"
#define FILE_MADE_PLAIN	ZONE_TMP "made_plain"
#define FILE_MADE_DEFAULT ZONE_TMP "made_default"
#define FILE_MADE_TRUSTED ZONE_TMP "made_trusted"
#define FILE_GUARDED	ZONE_TMP "guarded"
#define FILE_TRUNC	ZONE_TMP "trunc"
#define FILE_OWN	ZONE_TMP "own"
#define FILE_RELABEL	ZONE_TMP "relabel"
#define FILE_STRIP	ZONE_TMP "strip"
#define FILE_CLAIM_OPEN	ZONE_TMP "claim_open"
#define FILE_CLAIM_WRITE ZONE_TMP "claim_write"
#define FILE_CLAIM_READ	ZONE_TMP "claim_read"
#define FILE_CLAIMED	ZONE_TMP "claimed"
#define FILE_PASS_DEFAULT ZONE_TMP "pass_default"
#define FILE_PASS_TRUSTED ZONE_TMP "pass_trusted"
#define FILE_COW	ZONE_TMP "cow"
#define FILE_RELABEL_A	ZONE_TMP "relabel_a"
#define FILE_RELABEL_B	ZONE_TMP "relabel_b"
#define FILE_UNENFORCED	ZONE_TMP "unenforced"

/* Step at which a sequence joins the enforced cgroup; before it, the task
 * runs in an unzoned one.
 */
enum { AT_OPEN, AT_MMAP, AT_MPROTECT };

static const struct scoped {
	const char *path;
	bool trusted;
	int from;
	int expect;
	const char *name;
} scoped[] = {
	/* Measured at open. */
	{ ZONE_TMP "open_u", false, AT_OPEN, -EPERM,
	  "default: untrusted, measured at open: denied" },
	{ ZONE_TMP "open_t", true, AT_OPEN, 0,
	  "default: trusted, measured at open: allowed" },
	/* Opened outside the zone, measured at mmap. */
	{ ZONE_TMP "mmap_u", false, AT_MMAP, -EPERM,
	  "default: untrusted, measured at mmap: denied" },
	{ ZONE_TMP "mmap_t", true, AT_MMAP, 0,
	  "default: trusted, measured at mmap: allowed" },
	/* Opened and mapped outside the zone: no verdict, fail closed. */
	{ ZONE_TMP "miss_t", true, AT_MPROTECT, -EPERM,
	  "default: trusted, never measured: denied" },
};

static const char * const files[] = {
	FILE_EXEC_PLAIN, FILE_EXEC_TRUSTED, FILE_MADE_PLAIN, FILE_MADE_DEFAULT,
	FILE_MADE_TRUSTED, FILE_GUARDED, FILE_TRUNC, FILE_OWN, FILE_RELABEL,
	FILE_STRIP, FILE_CLAIM_OPEN, FILE_CLAIM_WRITE, FILE_CLAIM_READ,
	FILE_CLAIMED, FILE_PASS_DEFAULT, FILE_PASS_TRUSTED, FILE_COW,
	FILE_RELABEL_A, FILE_RELABEL_B, FILE_UNENFORCED,
};

static void cleanup_files(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(files); i++)
		remove(files[i]);
	for (i = 0; i < ARRAY_SIZE(scoped); i++)
		remove(scoped[i].path);
	remove(FILE_EXEC_NOXATTR);
	umount(NOXATTR_DIR);
	rmdir(NOXATTR_DIR);
}

/* A page file made by a task in @cg, which the policy stamps with @zone. */
static bool make_zoned_file(const char *cg, const char *path, const char *zone)
{
	if (!ASSERT_OK(enter(cg), cg) || !ASSERT_OK(make_page_file(path), path))
		return false;
	assert_file_zone(path, zone, path);
	return true;
}

/* open, map read-only, then mprotect(+PROT_EXEC), joining @cg at step @from so
 * that the steps before it run in an unzoned cgroup. Returns 0 if the exec
 * transition was allowed, else -errno.
 */
static int map_then_exec(const char *path, const char *cg, int from)
{
	int fd, ret = 0;
	void *p;

	if (enter(from == AT_OPEN ? cg : UNZONED_CG))
		return -EIO;
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;
	if (from == AT_MMAP && enter(cg)) {
		ret = -EIO;
		goto out_fd;
	}
	p = mmap(NULL, MAPLEN, PROT_READ, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED) {
		ret = -errno;
		goto out_fd;
	}
	if (from == AT_MPROTECT && enter(cg)) {
		ret = -EIO;
		goto out_map;
	}
	if (mprotect(p, MAPLEN, PROT_READ | PROT_EXEC))
		ret = -errno;
out_map:
	munmap(p, MAPLEN);
out_fd:
	close(fd);
	return ret;
}

/* open and map read-only in the default zone, relabel the file to @newval from
 * the trusted zone, then mprotect(+PROT_EXEC) back in the default zone.
 * Returns 0 if the exec transition was allowed, else -errno.
 */
static int map_relabel_exec(const char *path, const char *newval)
{
	int fd, ret;
	void *p;

	if (enter(DEFAULT_CG))
		return -EIO;
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;
	p = mmap(NULL, MAPLEN, PROT_READ, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED) {
		close(fd);
		return -errno;
	}
	ret = enter(TRUSTED_CG) ? -EIO : set_zone(path, newval);
	if (!ret && enter(DEFAULT_CG))
		ret = -EIO;
	if (!ret && mprotect(p, MAPLEN, PROT_READ | PROT_EXEC))
		ret = -errno;
	munmap(p, MAPLEN);
	close(fd);
	return ret;
}

static void run_scoped(int from)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(scoped); i++) {
		if (scoped[i].from != from)
			continue;
		ASSERT_EQ(map_then_exec(scoped[i].path, DEFAULT_CG, from),
			  scoped[i].expect, scoped[i].name);
	}
}

/* A file is stamped with its creator's zone as it is created: none outside
 * the policy, "default" in the default zone, "trusted" in the trusted one.
 */
static void test_created_file_carries_zone(struct lsm_zone_file *skel)
{
	__u32 stamped = skel->bss->nr_stamped;
	char buf[64];
	int err;

	if (!ASSERT_OK(enter(UNZONED_CG), "enter unzoned") ||
	    !ASSERT_OK(make_page_file(FILE_MADE_PLAIN), "make file unzoned"))
		return;
	err = getxattr(FILE_MADE_PLAIN, ZONE_XATTR, buf, sizeof(buf)) < 0 ? -errno : 0;
	ASSERT_EQ(err, -ENODATA, "unzoned: file left unlabelled");
	if (!ASSERT_OK(enter(DEFAULT_CG), "enter default") ||
	    !ASSERT_OK(make_page_file(FILE_MADE_DEFAULT), "make file default"))
		return;
	assert_file_zone(FILE_MADE_DEFAULT, ZONE_DEFAULT, "default: file stamped default");
	if (!ASSERT_OK(enter(TRUSTED_CG), "enter trusted") ||
	    !ASSERT_OK(make_page_file(FILE_MADE_TRUSTED), "make file trusted"))
		return;
	assert_file_zone(FILE_MADE_TRUSTED, ZONE_TRUSTED, "trusted: file stamped trusted");
	ASSERT_OK(skel->data->stamp_err, "stamp_err");
	ASSERT_EQ(skel->bss->nr_stamped - stamped, 2, "nr_stamped");
}

/* A trusted file is code the default zone may run: from any zone but the
 * trusted one it opens read-only, never for writing.
 */
static void test_default_cannot_write_trusted_file(struct lsm_zone_file *skel)
{
	__u32 denied = skel->bss->write_denied;

	if (!make_zoned_file(TRUSTED_CG, FILE_GUARDED, ZONE_TRUSTED) ||
	    !ASSERT_OK(enter(DEFAULT_CG), "enter default"))
		return;
	ASSERT_EQ(try_open(AT_FDCWD, FILE_GUARDED, O_WRONLY), -EPERM,
		  "default: open trusted file for write: denied");
	ASSERT_EQ(try_open(AT_FDCWD, FILE_GUARDED, O_RDWR), -EPERM,
		  "default: open trusted file read-write: denied");
	ASSERT_OK(try_open(AT_FDCWD, FILE_GUARDED, O_RDONLY),
		  "default: open trusted file read-only: allowed");
	if (!ASSERT_OK(enter(UNZONED_CG), "enter unzoned"))
		return;
	ASSERT_EQ(try_open(AT_FDCWD, FILE_GUARDED, O_WRONLY), -EPERM,
		  "unzoned: open trusted file for write: denied");
	if (!ASSERT_OK(enter(TRUSTED_CG), "enter trusted"))
		return;
	ASSERT_OK(try_open(AT_FDCWD, FILE_GUARDED, O_WRONLY),
		  "trusted: open trusted file for write: allowed");
	ASSERT_EQ(skel->bss->write_denied - denied, 3, "write_denied");
}

/* Truncation needs no writable descriptor and is refused all the same. */
static void test_default_cannot_truncate_trusted(struct lsm_zone_file *skel)
{
	__u32 denied = skel->bss->write_denied;
	struct stat st;

	if (!make_zoned_file(TRUSTED_CG, FILE_TRUNC, ZONE_TRUSTED) ||
	    !ASSERT_OK(enter(DEFAULT_CG), "enter default"))
		return;
	ASSERT_EQ(truncate(FILE_TRUNC, 0) ? -errno : 0, -EPERM,
		  "default: truncate trusted file: denied");
	if (ASSERT_OK(stat(FILE_TRUNC, &st), "stat trusted file"))
		ASSERT_EQ(st.st_size, MAPLEN, "default: trusted file intact");
	ASSERT_EQ(skel->bss->write_denied - denied, 1, "write_denied");
	if (!ASSERT_OK(enter(TRUSTED_CG), "enter trusted"))
		return;
	ASSERT_OK(truncate(FILE_TRUNC, 0) ? -errno : 0,
		  "trusted: truncate trusted file: allowed");
	if (ASSERT_OK(stat(FILE_TRUNC, &st), "stat truncated file"))
		ASSERT_EQ(st.st_size, 0, "trusted: trusted file truncated");
}

/* What the default zone made itself it may write to and truncate. */
static void test_default_writes_own_file(struct lsm_zone_file *skel)
{
	struct stat st;
	int fd;

	if (!make_zoned_file(DEFAULT_CG, FILE_OWN, ZONE_DEFAULT))
		return;
	fd = open(FILE_OWN, O_WRONLY);
	if (!ASSERT_OK_FD(fd, "default: open own file for write: allowed"))
		return;
	ASSERT_EQ(write(fd, "x", 1), 1, "default: write own file");
	close(fd);
	ASSERT_OK(truncate(FILE_OWN, 0) ? -errno : 0,
		  "default: truncate own file: allowed");
	if (ASSERT_OK(stat(FILE_OWN, &st), "stat own file"))
		ASSERT_EQ(st.st_size, 0, "default: own file truncated");
	assert_file_zone(FILE_OWN, ZONE_DEFAULT, "default: own file stays default");
}

/* Only the trusted zone writes the label: neither the default zone nor a
 * task in no zone can promote a file.
 */
static void test_default_cannot_relabel_file(struct lsm_zone_file *skel)
{
	__u32 denied = skel->bss->relabel_denied;

	if (!make_zoned_file(DEFAULT_CG, FILE_RELABEL, ZONE_DEFAULT))
		return;
	ASSERT_EQ(set_zone(FILE_RELABEL, ZONE_TRUSTED), -EPERM,
		  "default: relabel own file: denied");
	assert_file_zone(FILE_RELABEL, ZONE_DEFAULT, "default: file label intact");
	if (!ASSERT_OK(enter(UNZONED_CG), "enter unzoned"))
		return;
	ASSERT_EQ(set_zone(FILE_RELABEL, ZONE_TRUSTED), -EPERM,
		  "unzoned: mint trust on a file: denied");
	assert_file_zone(FILE_RELABEL, ZONE_DEFAULT, "unzoned: file label intact");
	ASSERT_EQ(skel->bss->relabel_denied - denied, 2, "relabel_denied");
	if (!ASSERT_OK(enter(TRUSTED_CG), "enter trusted"))
		return;
	ASSERT_OK(set_zone(FILE_RELABEL, ZONE_TRUSTED),
		  "trusted: relabel file: allowed");
	assert_file_zone(FILE_RELABEL, ZONE_TRUSTED, "trusted: file relabelled");
}

/* Nor can the label be stripped from outside the trusted zone. */
static void test_default_cannot_strip_file_label(struct lsm_zone_file *skel)
{
	__u32 denied = skel->bss->relabel_denied;
	char buf[64];
	int err;

	if (!make_zoned_file(DEFAULT_CG, FILE_STRIP, ZONE_DEFAULT))
		return;
	ASSERT_EQ(removexattr(FILE_STRIP, ZONE_XATTR) ? -errno : 0, -EPERM,
		  "default: strip own file label: denied");
	assert_file_zone(FILE_STRIP, ZONE_DEFAULT, "default: file label intact");
	if (!ASSERT_OK(enter(UNZONED_CG), "enter unzoned"))
		return;
	ASSERT_EQ(removexattr(FILE_STRIP, ZONE_XATTR) ? -errno : 0, -EPERM,
		  "unzoned: strip file label: denied");
	assert_file_zone(FILE_STRIP, ZONE_DEFAULT, "unzoned: file label intact");
	ASSERT_EQ(skel->bss->relabel_denied - denied, 2, "relabel_denied");
	if (!ASSERT_OK(enter(TRUSTED_CG), "enter trusted"))
		return;
	ASSERT_OK(removexattr(FILE_STRIP, ZONE_XATTR) ? -errno : 0,
		  "trusted: strip file label: allowed");
	err = getxattr(FILE_STRIP, ZONE_XATTR, buf, sizeof(buf)) < 0 ? -errno : 0;
	ASSERT_EQ(err, -ENODATA, "trusted: file label gone");
}

/* What the trusted zone opens for writing becomes trusted on the spot; what
 * it opens for reading is left alone.
 */
static void test_trusted_claims_on_open(struct lsm_zone_file *skel)
{
	__u32 claimed = skel->bss->nr_claimed;

	if (!make_zoned_file(DEFAULT_CG, FILE_CLAIM_OPEN, ZONE_DEFAULT) ||
	    !ASSERT_OK(enter(TRUSTED_CG), "enter trusted"))
		return;
	ASSERT_OK(try_open(AT_FDCWD, FILE_CLAIM_OPEN, O_RDONLY),
		  "trusted: open default-zone file for read: allowed");
	assert_file_zone(FILE_CLAIM_OPEN, ZONE_DEFAULT, "trusted: not claimed by a read open");
	ASSERT_OK(try_open(AT_FDCWD, FILE_CLAIM_OPEN, O_WRONLY),
		  "trusted: open default-zone file for write: allowed");
	assert_file_zone(FILE_CLAIM_OPEN, ZONE_TRUSTED, "trusted: file claimed on open");
	ASSERT_EQ(skel->bss->nr_claimed - claimed, 1, "nr_claimed");
}

/* A descriptor the trusted zone writes through is claimed too, whichever
 * zone opened it; one it only reads through is not.
 */
static void test_trusted_claims_on_write_through_inherited_fd(struct lsm_zone_file *skel)
{
	__u32 claimed = skel->bss->nr_claimed;
	int wfd = -1, rfd = -1;
	char c;

	if (!make_zoned_file(DEFAULT_CG, FILE_CLAIM_WRITE, ZONE_DEFAULT) ||
	    !make_zoned_file(DEFAULT_CG, FILE_CLAIM_READ, ZONE_DEFAULT))
		return;
	wfd = open(FILE_CLAIM_WRITE, O_WRONLY);
	rfd = open(FILE_CLAIM_READ, O_RDONLY);
	if (!ASSERT_OK_FD(wfd, "default: open own file for write") ||
	    !ASSERT_OK_FD(rfd, "default: open own file for read") ||
	    !ASSERT_OK(enter(TRUSTED_CG), "enter trusted"))
		goto out;
	ASSERT_EQ(read(rfd, &c, 1), 1, "trusted: read through inherited descriptor");
	assert_file_zone(FILE_CLAIM_READ, ZONE_DEFAULT, "trusted: not claimed by a read");
	ASSERT_EQ(write(wfd, "x", 1), 1, "trusted: write through inherited descriptor");
	assert_file_zone(FILE_CLAIM_WRITE, ZONE_TRUSTED, "trusted: file claimed on write");
	ASSERT_EQ(skel->bss->nr_claimed - claimed, 1, "nr_claimed");
out:
	if (wfd >= 0)
		close(wfd);
	if (rfd >= 0)
		close(rfd);
}

/* Once claimed, a file the default zone made is code it may run and can no
 * longer write to.
 */
static void test_default_cannot_open_claimed_file(struct lsm_zone_file *skel)
{
	if (!make_zoned_file(DEFAULT_CG, FILE_CLAIMED, ZONE_DEFAULT) ||
	    !ASSERT_OK(enter(TRUSTED_CG), "enter trusted"))
		return;
	ASSERT_OK(try_open(AT_FDCWD, FILE_CLAIMED, O_WRONLY),
		  "trusted: open default-zone file for write: allowed");
	assert_file_zone(FILE_CLAIMED, ZONE_TRUSTED, "trusted: file claimed");
	if (!ASSERT_OK(enter(DEFAULT_CG), "enter default"))
		return;
	ASSERT_EQ(try_open(AT_FDCWD, FILE_CLAIMED, O_WRONLY), -EPERM,
		  "default: open claimed file for write: denied");
	ASSERT_OK(try_open(AT_FDCWD, FILE_CLAIMED, O_RDONLY),
		  "default: open claimed file for read: allowed");
	ASSERT_OK(map_then_exec(FILE_CLAIMED, DEFAULT_CG, AT_OPEN),
		  "default: claimed file made executable: allowed");
}

/* A writable descriptor to a trusted file does not enter the default zone
 * by SCM_RIGHTS either: the message arrives, the descriptor does not.
 */
static void test_scm_rights_writable_trusted_denied(struct lsm_zone_file *skel)
{
	__u32 denied = skel->bss->recv_denied;

	if (!make_zoned_file(TRUSTED_CG, FILE_PASS_DEFAULT, ZONE_TRUSTED) ||
	    !ASSERT_OK(enter(DEFAULT_CG), "enter default"))
		return;
	ASSERT_EQ(request_fd(FILE_PASS_DEFAULT), -ENOMSG,
		  "default: receive writable fd to trusted file: denied");
	ASSERT_EQ(skel->bss->recv_denied - denied, 1, "recv_denied");
}

/* The trusted zone receives it and may write through it. */
static void test_scm_rights_to_trusted_allowed(struct lsm_zone_file *skel)
{
	int fd;

	if (!make_zoned_file(TRUSTED_CG, FILE_PASS_TRUSTED, ZONE_TRUSTED) ||
	    !ASSERT_OK(enter(TRUSTED_CG), "enter trusted"))
		return;
	fd = request_fd(FILE_PASS_TRUSTED);
	if (!ASSERT_OK_FD(fd, "trusted: receive writable fd to trusted file: allowed"))
		return;
	ASSERT_EQ(write(fd, "x", 1), 1, "trusted: write through received fd");
	close(fd);
}

/* W^X: no mapping both writable and executable at once. */
static void test_wx_mapping_denied(struct lsm_zone_file *skel)
{
	__u32 denied = skel->bss->wx_denied;

	if (!ASSERT_OK(enter(DEFAULT_CG), "enter default"))
		return;
	ASSERT_EQ(map_rwx(), -EPERM, "default: W+X mapping denied");
	ASSERT_EQ(skel->bss->wx_denied - denied, 1, "wx_denied");
}

/* W^X: anonymous memory written to cannot be made executable afterwards. */
static void test_anon_made_exec_denied(struct lsm_zone_file *skel)
{
	__u32 denied = skel->bss->wx_denied;

	if (!ASSERT_OK(enter(DEFAULT_CG), "enter default"))
		return;
	ASSERT_EQ(anon_then_exec(), -EPERM, "default: written anon made exec denied");
	ASSERT_EQ(skel->bss->wx_denied - denied, 1, "wx_denied");
}

/* W^X: a private mapping of trusted code written through is no longer the
 * trusted code, so it cannot be made executable either.
 */
static void test_cow_made_exec_denied(struct lsm_zone_file *skel)
{
	__u32 denied = skel->bss->wx_denied;

	if (!make_zoned_file(TRUSTED_CG, FILE_COW, ZONE_TRUSTED) ||
	    !ASSERT_OK(enter(DEFAULT_CG), "enter default"))
		return;
	ASSERT_EQ(cow_then_exec(FILE_COW), -EPERM,
		  "default: written file mapping made exec denied");
	ASSERT_EQ(skel->bss->wx_denied - denied, 1, "wx_denied");
}

/* Provenance: a file without the label is not mapped executable at all. */
static void test_unlabelled_exec_refused(struct lsm_zone_file *skel)
{
	__u32 denied = skel->bss->code_denied;

	if (!ASSERT_OK(enter(DEFAULT_CG), "enter default"))
		return;
	ASSERT_EQ(map_exec(FILE_EXEC_PLAIN), -EPERM,
		  "default: unlabelled file mapped exec refused");
	ASSERT_GE(skel->bss->code_denied - denied, 1, "code_denied");
}

/* The byte-identical file carrying the trusted label is admitted. */
static void test_labelled_exec_admitted(struct lsm_zone_file *skel)
{
	__u32 was = skel->bss->allowed;

	if (!ASSERT_OK(enter(DEFAULT_CG), "enter default"))
		return;
	ASSERT_OK(map_exec(FILE_EXEC_TRUSTED),
		  "default: labelled file mapped exec admitted");
	ASSERT_GE(skel->bss->allowed - was, 1, "allowed");
}

/* On ramfs the label is not absent but unreadable, and "cannot tell" must
 * not become "allow".
 */
static void test_unreadable_label_refused(struct lsm_zone_file *skel)
{
	__u32 denied = skel->bss->code_denied;
	int err;

	err = getxattr(FILE_EXEC_NOXATTR, ZONE_XATTR, NULL, 0) < 0 ? -errno : 0;
	ASSERT_EQ(err, -EOPNOTSUPP, "label unreadable on ramfs");
	if (!ASSERT_OK(enter(DEFAULT_CG), "enter default"))
		return;
	ASSERT_EQ(map_exec(FILE_EXEC_NOXATTR), -EPERM,
		  "default: unreadable-label file refused");
	ASSERT_GE(skel->bss->code_denied - denied, 1, "code_denied");
}

/* Opened in the default zone: measured at open, enforced at mprotect. */
static void test_measured_at_open(struct lsm_zone_file *skel)
{
	run_scoped(AT_OPEN);
}

/* Opened outside the zone, mapped inside it: measured at mmap instead. */
static void test_measured_at_mmap(struct lsm_zone_file *skel)
{
	run_scoped(AT_MMAP);
}

/* Opened and mapped outside the zone: no verdict to enforce, so even the
 * trusted file is refused.
 */
static void test_never_measured_fails_closed(struct lsm_zone_file *skel)
{
	__u32 denied = skel->bss->code_denied;

	run_scoped(AT_MPROTECT);
	ASSERT_EQ(skel->bss->code_denied - denied, 1, "code_denied");
}

/* A verdict cached at open follows a relabel by the trusted zone before the
 * mapping is made executable, in both directions.
 */
static void test_relabel_refreshes_verdict(struct lsm_zone_file *skel)
{
	if (!make_zoned_file(TRUSTED_CG, FILE_RELABEL_A, ZONE_TRUSTED) ||
	    !make_zoned_file(DEFAULT_CG, FILE_RELABEL_B, ZONE_DEFAULT))
		return;
	ASSERT_EQ(map_relabel_exec(FILE_RELABEL_A, ZONE_DEFAULT), -EPERM,
		  "default: relabelled away: denied");
	assert_file_zone(FILE_RELABEL_A, ZONE_DEFAULT, "relabelled away");
	ASSERT_OK(map_relabel_exec(FILE_RELABEL_B, ZONE_TRUSTED),
		  "default: relabelled trusted: allowed");
	assert_file_zone(FILE_RELABEL_B, ZONE_TRUSTED, "relabelled trusted");
}

/* In the trusted zone nothing is enforced: the same code and the same
 * transitions go through.
 */
static void test_trusted_zone_unenforced(struct lsm_zone_file *skel)
{
	__u32 wx = skel->bss->wx_denied, code = skel->bss->code_denied;

	if (!make_zoned_file(TRUSTED_CG, FILE_UNENFORCED, ZONE_TRUSTED))
		return;
	ASSERT_OK(map_rwx(), "trusted: W+X mapping allowed");
	ASSERT_OK(anon_then_exec(), "trusted: written anon made exec allowed");
	ASSERT_OK(cow_then_exec(FILE_UNENFORCED),
		  "trusted: written file mapping made exec allowed");
	ASSERT_OK(map_exec(FILE_EXEC_PLAIN), "trusted: unlabelled file admitted");
	ASSERT_OK(map_exec(FILE_EXEC_NOXATTR),
		  "trusted: unreadable-label file admitted");
	ASSERT_EQ(skel->bss->wx_denied, wx, "wx_denied unchanged");
	ASSERT_EQ(skel->bss->code_denied, code, "code_denied unchanged");
}

void test_lsm_zone_file(void)
{
	struct lsm_zone_file *skel = NULL;
	struct zone_env env = { -1, -1, -1 };
	int i, err;

	cleanup_files();
	err = zone_bootstrap(&env);
	if (err == -EOPNOTSUPP) {
		printf("%s:SKIP:cannot set %s on a cgroup\n", __func__, ZONE_XATTR);
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(err, "zone_bootstrap"))
		goto out;

	/* Byte-identical files with and without the trusted zone label, and
	 * the page files for the mapping sequences, made before the policy
	 * attaches so that none of them has been measured.
	 */
	if (!ASSERT_OK(make_page_file(FILE_EXEC_PLAIN), "make unlabelled file") ||
	    !ASSERT_OK(make_page_file(FILE_EXEC_TRUSTED), "make labelled file"))
		goto out;
	err = set_zone(FILE_EXEC_TRUSTED, ZONE_TRUSTED);
	if (err == -EOPNOTSUPP) {
		printf("%s:SKIP:local fs doesn't support xattr (%d)\n"
		       "To run this test, make sure /tmp filesystem supports xattr.\n",
		       __func__, -err);
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(err, "label trusted file"))
		goto out;
	for (i = 0; i < ARRAY_SIZE(scoped); i++) {
		if (!ASSERT_OK(make_page_file(scoped[i].path), "make page file"))
			goto out;
		if (scoped[i].trusted &&
		    !ASSERT_OK(set_zone(scoped[i].path, ZONE_TRUSTED), "label page file"))
			goto out;
	}
	/* A copy on ramfs, which has no xattr handlers. */
	if (!ASSERT_OK(mkdir(NOXATTR_DIR, 0755) && errno != EEXIST ? -errno : 0,
		       "mkdir noxattr") ||
	    !ASSERT_OK(mount("ramfs", NOXATTR_DIR, "ramfs", 0, NULL) ? -errno : 0,
		       "mount ramfs") ||
	    !ASSERT_OK(make_page_file(FILE_EXEC_NOXATTR), "make noxattr file"))
		goto out;

	skel = lsm_zone_file__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel open_and_load"))
		goto out;
	skel->bss->monitored_pid = getpid();
	if (!ASSERT_OK(lsm_zone_file__attach(skel), "skel attach"))
		goto out;

	if (test__start_subtest("created_file_carries_zone"))
		test_created_file_carries_zone(skel);
	if (test__start_subtest("default_cannot_write_trusted_file"))
		test_default_cannot_write_trusted_file(skel);
	if (test__start_subtest("default_cannot_truncate_trusted"))
		test_default_cannot_truncate_trusted(skel);
	if (test__start_subtest("default_writes_own_file"))
		test_default_writes_own_file(skel);
	if (test__start_subtest("default_cannot_relabel_file"))
		test_default_cannot_relabel_file(skel);
	if (test__start_subtest("default_cannot_strip_file_label"))
		test_default_cannot_strip_file_label(skel);
	if (test__start_subtest("trusted_claims_on_open"))
		test_trusted_claims_on_open(skel);
	if (test__start_subtest("trusted_claims_on_write_through_inherited_fd"))
		test_trusted_claims_on_write_through_inherited_fd(skel);
	if (test__start_subtest("default_cannot_open_claimed_file"))
		test_default_cannot_open_claimed_file(skel);
	if (test__start_subtest("scm_rights_writable_trusted_denied"))
		test_scm_rights_writable_trusted_denied(skel);
	if (test__start_subtest("scm_rights_to_trusted_allowed"))
		test_scm_rights_to_trusted_allowed(skel);
	if (test__start_subtest("wx_mapping_denied"))
		test_wx_mapping_denied(skel);
	if (test__start_subtest("anon_made_exec_denied"))
		test_anon_made_exec_denied(skel);
	if (test__start_subtest("cow_made_exec_denied"))
		test_cow_made_exec_denied(skel);
	if (test__start_subtest("unlabelled_exec_refused"))
		test_unlabelled_exec_refused(skel);
	if (test__start_subtest("labelled_exec_admitted"))
		test_labelled_exec_admitted(skel);
	if (test__start_subtest("unreadable_label_refused"))
		test_unreadable_label_refused(skel);
	if (test__start_subtest("measured_at_open"))
		test_measured_at_open(skel);
	if (test__start_subtest("measured_at_mmap"))
		test_measured_at_mmap(skel);
	if (test__start_subtest("never_measured_fails_closed"))
		test_never_measured_fails_closed(skel);
	if (test__start_subtest("relabel_refreshes_verdict"))
		test_relabel_refreshes_verdict(skel);
	if (test__start_subtest("trusted_zone_unenforced"))
		test_trusted_zone_unenforced(skel);
out:
	lsm_zone_file__destroy(skel);
	zone_teardown(&env);
	cleanup_files();
}
