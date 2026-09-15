// SPDX-License-Identifier: GPL-2.0
/*
 * Measure-at-open, enforce-at-mprotect: covers the "map read-only, then
 * mprotect(PROT_EXEC)" path that an mmap_file policy alone misses.
 *
 * Two byte-identical files under different inodes: one is labeled with trusted
 * provenance, the other is not. Opening each file lets the sleepable file_open
 * hook cache a verdict on the inode; the later mprotect(PROT_EXEC) is allowed or
 * denied by the non-sleepable file_mprotect hook from that cache. Only the label
 * differs.
 */
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <stdlib.h>
#include <string.h>
#include <test_progs.h>
#include "lsm_mprotect_guard.skel.h"

#define UNTRUSTED	"/tmp/test_progs_mprotect_untrusted"
#define TRUSTED		"/tmp/test_progs_mprotect_trusted"
#define PROV_XATTR	"security.bpf.prov"
#define PROV_VALUE	"trusted"
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

/* open (triggers measure), map read-only, then attempt mprotect(+PROT_EXEC).
 * Returns 0 if the exec transition was allowed, else -errno.
 */
static int map_then_exec(const char *path)
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
	if (mprotect(p, MAPLEN, PROT_READ | PROT_EXEC))
		ret = -errno;
	munmap(p, MAPLEN);
	close(fd);
	return ret;
}

void test_lsm_mprotect_guard(void)
{
	struct lsm_mprotect_guard *skel = NULL;
	int err;

	if (!ASSERT_OK(make_file(UNTRUSTED), "make untrusted"))
		goto out;
	if (!ASSERT_OK(make_file(TRUSTED), "make trusted"))
		goto out;

	err = setxattr(TRUSTED, PROV_XATTR, PROV_VALUE, sizeof(PROV_VALUE), 0);
	if (err && (errno == EOPNOTSUPP || errno == EPERM)) {
		printf("%s:SKIP:cannot set %s (errno %d)\n",
		       __func__, PROV_XATTR, errno);
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(err, "setxattr provenance"))
		goto out;

	skel = lsm_mprotect_guard__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel open_and_load"))
		goto out;
	if (!ASSERT_OK(lsm_mprotect_guard__attach(skel), "skel attach"))
		goto out;

	skel->bss->monitored_pid = getpid();

	/* Unlabeled: the exec transition is refused. */
	ASSERT_EQ(map_then_exec(UNTRUSTED), -EPERM, "untrusted mprotect denied");
	/* Labeled, byte-identical: the exec transition is allowed. */
	ASSERT_OK(map_then_exec(TRUSTED), "trusted mprotect allowed");

	skel->bss->monitored_pid = 0;

	ASSERT_GE(skel->bss->measure_hits, 2, "measure_hits");
	ASSERT_GE(skel->bss->deny_hits, 1, "deny_hits");
	ASSERT_GE(skel->bss->allow_hits, 1, "allow_hits");
out:
	lsm_mprotect_guard__destroy(skel);
	remove(UNTRUSTED);
	remove(TRUSTED);
}
