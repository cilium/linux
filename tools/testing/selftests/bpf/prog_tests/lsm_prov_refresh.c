// SPDX-License-Identifier: GPL-2.0
/*
 * Closes the measure-time-of-use race for the provenance label: a file measured
 * at open can be relabeled before its mapping is made executable. The
 * inode_post_setxattr hook refreshes the cached verdict so file_mprotect always
 * sees the current label.
 *
 * Two directions are exercised, each with the mapping already in place before
 * the relabel:
 *   - trusted at open, then relabeled away: the exec transition is refused;
 *   - unlabeled at open, then relabeled trusted: the exec transition is allowed.
 */
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <stdlib.h>
#include <string.h>
#include <test_progs.h>
#include "lsm_mprotect_guard.skel.h"

#define FILE_A		"/tmp/test_progs_prov_refresh_a"
#define FILE_B		"/tmp/test_progs_prov_refresh_b"
#define PROV_XATTR	"security.bpf.prov"
#define MAPLEN		4096

static int make_file(const char *path)
{
	char page[MAPLEN] = {};
	int fd, err;

	fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0755);
	if (fd < 0)
		return -errno;
	err = write(fd, page, sizeof(page));
	close(fd);
	return err == sizeof(page) ? 0 : -EIO;
}

/* open @path (measures at open), map it read-only, relabel it to @newval, then
 * attempt mprotect(PROT_EXEC). Returns 0 if the exec transition was allowed,
 * else -errno.
 */
static int map_relabel_exec(const char *path, const char *newval)
{
	int fd, ret = 0;
	void *p;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;
	p = mmap(NULL, MAPLEN, PROT_READ, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED) {
		close(fd);
		return -errno;
	}
	if (setxattr(path, PROV_XATTR, newval, strlen(newval) + 1, 0)) {
		ret = -errno;
		goto out;
	}
	if (mprotect(p, MAPLEN, PROT_READ | PROT_EXEC))
		ret = -errno;
out:
	munmap(p, MAPLEN);
	close(fd);
	return ret;
}

void test_lsm_prov_refresh(void)
{
	struct lsm_mprotect_guard *skel = NULL;
	int err;

	if (!ASSERT_OK(make_file(FILE_A), "make A"))
		goto out;
	if (!ASSERT_OK(make_file(FILE_B), "make B"))
		goto out;

	/* A starts trusted; B starts unlabeled. */
	err = setxattr(FILE_A, PROV_XATTR, "trusted", sizeof("trusted"), 0);
	if (err && (errno == EOPNOTSUPP || errno == EPERM)) {
		printf("%s:SKIP:cannot set %s (errno %d)\n",
		       __func__, PROV_XATTR, errno);
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(err, "setxattr A trusted"))
		goto out;

	skel = lsm_mprotect_guard__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel open_and_load"))
		goto out;
	if (!ASSERT_OK(lsm_mprotect_guard__attach(skel), "skel attach"))
		goto out;

	skel->bss->monitored_pid = getpid();

	/* Measured trusted, relabeled away before mprotect: refused. */
	ASSERT_EQ(map_relabel_exec(FILE_A, "revoked"), -EPERM,
		  "relabeled-away mprotect denied");
	/* Measured unlabeled, relabeled trusted before mprotect: allowed. */
	ASSERT_OK(map_relabel_exec(FILE_B, "trusted"),
		  "relabeled-trusted mprotect allowed");

	skel->bss->monitored_pid = 0;

	ASSERT_GE(skel->bss->refresh_hits, 2, "refresh_hits");
out:
	lsm_mprotect_guard__destroy(skel);
	remove(FILE_A);
	remove(FILE_B);
}
