// SPDX-License-Identifier: GPL-2.0
/*
 * End-to-end demonstration that a BPF LSM policy keyed on a provenance xattr
 * prevents a CVE-2024-3094 style attack, and does so on the file's content
 * label rather than its name.
 *
 * libxz_ifunc.so is a stand-in for the backdoored liblzma: loading it runs code
 * from an IFUNC resolver (as liblzma's crc resolvers were hijacked to do) and
 * from a constructor that drops a marker file (standing in for the pre-auth
 * RCE). We make two byte-identical copies under different names and inodes. The
 * only difference between them is that one carries a trusted "security.bpf.prov"
 * label. The unlabeled copy is refused an executable mapping; the labeled copy
 * is admitted. Same content, same loader, different provenance: the decision
 * follows the label, not the path.
 */
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <stdlib.h>
#include <string.h>
#include <test_progs.h>
#include "lsm_xz_backdoor.skel.h"

#define LIB_SRC		"./libxz_ifunc.so"
#define LIB_UNTRUSTED	"/tmp/test_progs_xz_untrusted.so"
#define LIB_TRUSTED	"/tmp/test_progs_xz_trusted.so"
#define PROV_XATTR	"security.bpf.prov"
#define PROV_VALUE	"trusted"
#define MARKER		"/tmp/test_progs_xz_backdoor_marker"

static int copy_file(const char *src, const char *dst)
{
	char buf[4096];
	int in, out, n, ret = 0;

	in = open(src, O_RDONLY);
	if (in < 0)
		return -errno;
	out = open(dst, O_CREAT | O_WRONLY | O_TRUNC, 0755);
	if (out < 0) {
		close(in);
		return -errno;
	}
	while ((n = read(in, buf, sizeof(buf))) > 0) {
		if (write(out, buf, n) != n) {
			ret = -EIO;
			break;
		}
	}
	close(in);
	close(out);
	return ret;
}

static bool marker_present(void)
{
	struct stat st;

	return stat(MARKER, &st) == 0;
}

void test_lsm_xz_backdoor(void)
{
	struct lsm_xz_backdoor *skel = NULL;
	void *h = NULL;
	int err;

	if (!ASSERT_OK(copy_file(LIB_SRC, LIB_UNTRUSTED), "copy untrusted"))
		goto out;
	if (!ASSERT_OK(copy_file(LIB_SRC, LIB_TRUSTED), "copy trusted"))
		goto out;

	/* Stamp a trusted provenance label on one copy only. The security.*
	 * namespace needs privilege to write, which is the point: an
	 * unprivileged attacker cannot forge it.
	 */
	err = setxattr(LIB_TRUSTED, PROV_XATTR, PROV_VALUE, sizeof(PROV_VALUE), 0);
	if (err && (errno == EOPNOTSUPP || errno == EPERM)) {
		printf("%s:SKIP:cannot set %s (errno %d)\n",
		       __func__, PROV_XATTR, errno);
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(err, "setxattr provenance"))
		goto out;

	setenv("XZ_BACKDOOR_MARKER", MARKER, 1);

	skel = lsm_xz_backdoor__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel open_and_load"))
		goto out;
	if (!ASSERT_OK(lsm_xz_backdoor__attach(skel), "skel attach"))
		goto out;

	skel->bss->monitored_pid = getpid();

	/*
	 * Phase A: the unlabeled copy is the smuggled backdoor. It has no
	 * trusted provenance, so its executable mapping is refused, dlopen()
	 * fails, and neither the resolver nor the constructor ever runs.
	 */
	remove(MARKER);
	h = dlopen(LIB_UNTRUSTED, RTLD_NOW | RTLD_LOCAL);
	ASSERT_EQ(h, NULL, "dlopen untrusted denied");
	ASSERT_FALSE(marker_present(), "untrusted payload prevented");
	if (h) {
		dlclose(h);
		h = NULL;
	}

	/*
	 * Phase B: the labeled copy is byte-identical and loaded by the same
	 * loader, but it carries trusted provenance, so it is admitted and its
	 * code runs. The label, not the name or the bytes, is what decides.
	 */
	remove(MARKER);
	h = dlopen(LIB_TRUSTED, RTLD_NOW | RTLD_LOCAL);
	ASSERT_OK_PTR(h, "dlopen trusted allowed");
	ASSERT_TRUE(marker_present(), "trusted payload ran");

	skel->bss->monitored_pid = 0;

	ASSERT_GE(skel->bss->deny_hits, 1, "deny_hits");
	ASSERT_GE(skel->bss->allow_hits, 1, "allow_hits");
out:
	if (h)
		dlclose(h);
	lsm_xz_backdoor__destroy(skel);
	remove(MARKER);
	remove(LIB_UNTRUSTED);
	remove(LIB_TRUSTED);
	unsetenv("XZ_BACKDOOR_MARKER");
}
