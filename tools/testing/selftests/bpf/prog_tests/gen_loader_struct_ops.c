// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "bpf_dctcp_release.skel.h"

/*
 * struct_ops is not supported by the light skeleton / signed loader: its kern
 * vdata is populated with raw, host-side program fds (bpf_map_prepare_vdata),
 * which for a generated loader are all -1, so the loader cannot work. libbpf
 * must refuse to emit such a loader rather than silently produce a broken one.
 *
 * Drive a struct_ops object through bpf_object__gen_loader() and assert the
 * load is rejected with -ENOTSUP. The rejection happens before any kernel-BTF
 * struct_ops resolution, so it does not require struct_ops support in the
 * running kernel.
 */
void test_gen_loader_struct_ops(void)
{
	LIBBPF_OPTS(gen_loader_opts, gopts);
	struct bpf_dctcp_release *skel;
	int err;

	skel = bpf_dctcp_release__open();
	if (!ASSERT_OK_PTR(skel, "bpf_dctcp_release__open"))
		return;

	err = bpf_object__gen_loader(skel->obj, &gopts);
	if (!ASSERT_OK(err, "bpf_object__gen_loader"))
		goto out;

	err = bpf_object__load(skel->obj);
	ASSERT_EQ(err, -ENOTSUP, "struct_ops rejected for light skeleton");
out:
	bpf_dctcp_release__destroy(skel);
}
