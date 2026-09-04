// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_kfuncs.h"
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

#define ZONE_MAX	32

extern struct cgroup *bpf_cgroup_from_id(__u64 cgid) __ksym;
extern void bpf_cgroup_release(struct cgroup *cgrp) __ksym;

const char xattr_zone[] = "security.bpf.zone";

__u32 monitored_pid;

/* What the hook did on the way down. */
__u32 nr_labelled;
__s32 label_err = 1;
char zone_scratch[ZONE_MAX];

/* What another hook sees for the cgroup the task ended up in. */
char seen_zone[ZONE_MAX];
__u32 seen_len;

/*
 * Push the zone of the cgroup a new one is created under onto the new cgroup
 * itself. The node is not linked into its parent yet, so nothing can look it
 * up before it carries the label.
 *
 * Only directories are cgroups; the control files created underneath a new
 * cgroup come through here too and are left alone.
 */
SEC("lsm.s/kernfs_init_security")
int BPF_PROG(inherit_zone, struct kernfs_node *kn_dir, struct kernfs_node *kn)
{
	struct bpf_dynptr value;
	int len;

	if ((bpf_get_current_pid_tgid() >> 32) != monitored_pid)
		return 0;
	if (!(kn->flags & KERNFS_DIR))
		return 0;

	bpf_dynptr_from_mem(zone_scratch, sizeof(zone_scratch), 0, &value);
	len = bpf_kernfs_read_xattr(kn_dir, xattr_zone, &value);
	if (len <= 0 || len > ZONE_MAX)
		return 0;

	bpf_dynptr_from_mem(zone_scratch, len, 0, &value);
	label_err = bpf_kernfs_set_xattr(kn, xattr_zone, &value);
	if (!label_err)
		nr_labelled++;
	return 0;
}

/*
 * The label is now on the cgroup itself, so any other hook can ask which zone
 * the current task is running in without walking back up the hierarchy.
 */
SEC("lsm.s/file_open")
int BPF_PROG(read_zone)
{
	struct bpf_dynptr value;
	struct cgroup *cgrp;
	int len;

	if ((bpf_get_current_pid_tgid() >> 32) != monitored_pid)
		return 0;

	cgrp = bpf_cgroup_from_id(bpf_get_current_cgroup_id());
	if (!cgrp)
		return 0;

	bpf_dynptr_from_mem(seen_zone, sizeof(seen_zone), 0, &value);
	len = bpf_cgroup_read_xattr(cgrp, xattr_zone, &value);
	if (len > 0)
		seen_len = len;

	bpf_cgroup_release(cgrp);
	return 0;
}
