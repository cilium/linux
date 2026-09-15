// SPDX-License-Identifier: GPL-2.0
/*
 * A stand-in for the backdoored liblzma of CVE-2024-3094, built as a helper
 * shared object for the lsm_xz_backdoor selftest.
 *
 * It reproduces the two properties that made the xz backdoor work at runtime:
 *
 *   1. It executes attacker code the instant it is mapped into a process, via
 *      a GNU IFUNC resolver. This is the very mechanism liblzma's crc32/crc64
 *      resolvers were hijacked to abuse: the resolver is invoked by ld.so while
 *      relocating the object, before main() and before ELF constructors run.
 *      The reference from xz_crc_ptr forces that resolution at load time.
 *
 *   2. Its constructor "payload" drops a marker file, standing in for the
 *      pre-auth remote command execution the real backdoor achieved.
 *
 * There is nothing lzma-specific here. The point is only that *loading* the
 * library runs its code. A BPF LSM policy that refuses to map this object
 * executable into a protected daemon stops all of it: no first instruction.
 */
#include <stdio.h>
#include <stdlib.h>

/* Set to 1 by the IFUNC resolver at load/relocation time. Exported so the
 * loader (the test) can confirm the resolver actually ran.
 */
int xz_resolver_ran;

typedef long (*crc_fn)(void);

static long crc_impl(void)
{
	return 0;
}

/* The IFUNC resolver: invoked by ld.so while relocating this object. */
static crc_fn resolve_crc(void)
{
	xz_resolver_ran = 1;
	return crc_impl;
}

long xz_crc(void) __attribute__((ifunc("resolve_crc")));

/* A relocation against the ifunc, so the resolver is forced to run at load. */
crc_fn xz_crc_ptr = xz_crc;

/* The payload: stands in for the backdoor's pre-auth command execution. */
__attribute__((constructor))
static void xz_payload(void)
{
	const char *marker = getenv("XZ_BACKDOOR_MARKER");
	FILE *f;

	if (!marker)
		return;
	f = fopen(marker, "w");
	if (f) {
		fputs("pwned\n", f);
		fclose(f);
	}
}
