// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "bpf_gotox.skel.h"

/*
 * Jump tables (RELO_INSN_ARRAY / BPF_MAP_TYPE_INSN_ARRAY) are not wired up for
 * the light skeleton / signed loader: the relocation has no gen_loader path and
 * would bake a raw, process-local insn-array fd into the program instead of
 * binding it into the generated blob like every other map. libbpf must refuse
 * to emit such a loader rather than produce a broken and unauthenticated one.
 *
 * Drive a jump-table-using object through bpf_object__gen_loader() and assert
 * the subsequent load is rejected with -ENOTSUP.
 */
void test_gen_loader_jumptables(void)
{
	LIBBPF_OPTS(gen_loader_opts, gopts);
	struct bpf_gotox *skel;
	int err;

	skel = bpf_gotox__open();
	if (!ASSERT_OK_PTR(skel, "bpf_gotox__open"))
		return;

	/* Compiler without indirect-jump support emits no jump tables. */
	if (skel->data->skip) {
		test__skip();
		goto out;
	}

	err = bpf_object__gen_loader(skel->obj, &gopts);
	if (!ASSERT_OK(err, "bpf_object__gen_loader"))
		goto out;

	err = bpf_object__load(skel->obj);
	ASSERT_EQ(err, -ENOTSUP, "jump tables rejected for light skeleton");
out:
	bpf_gotox__destroy(skel);
}
