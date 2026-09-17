// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_kfuncs.h"

char _license[] SEC("license") = "GPL";

#define LABEL_MAX	32

/* What the hook does with the node it is handed, set by the runner. */
enum {
	MODE_INHERIT,		/* push the parent's label onto the new node */
	MODE_RELABEL_PARENT,	/* write the parent node instead */
	MODE_SHORT_NAME,	/* set under a name equal to the prefix */
	MODE_USER_SET,		/* set under a user. name */
	MODE_READ_USER,		/* read a user. name off the parent */
	MODE_SHORT_BUFFER,	/* read into a buffer too short for the label */
	MODE_FOREIGN_NAME,	/* read and write another module's name */
};

const char xattr_zone[] = "security.bpf.zone";
const char xattr_note[] = "security.bpf.note";
const char xattr_prefix[] = "security.bpf.";
const char xattr_user_zone[] = "user.zone";
const char xattr_user_note[] = "user.note";
const char xattr_selinux[] = "security.selinux";
static const char label_sealed[] = "sealed";
char label_beta[] = "beta";
char buf[LABEL_MAX];
__u32 monitored_pid;
__u32 mode;
__u32 refuse_sealed;
__s32 get_ret;
__s32 set_ret;
__u32 labelled_dirs;
__u32 labelled_files;
__u32 refused;

/* Every node the test process creates in cgroupfs passes through here
 * before it is linked in: the cgroup directory first, then its control
 * files with that directory as their parent. The label is read off the
 * parent and written onto the new node; a directory below a "sealed"
 * parent is refused while the toggle is set.
 */
SEC("lsm.s/kernfs_init_security")
int BPF_PROG(label_node, struct kernfs_node *kn_dir, struct kernfs_node *kn)
{
	bool dir = kn->flags & KERNFS_DIR;
	struct bpf_dynptr value;
	int len;

	if (bpf_get_current_pid_tgid() >> 32 != monitored_pid)
		return 0;
	if (mode != MODE_INHERIT && !dir)
		return 0;

	switch (mode) {
	case MODE_INHERIT:
		bpf_dynptr_from_mem(buf, sizeof(buf), 0, &value);
		len = bpf_get_kernfs_xattr(kn_dir, xattr_zone, &value);
		get_ret = len;
		if (len <= 0 || len > LABEL_MAX)
			return 0;
		if (dir && refuse_sealed && len == sizeof(label_sealed) &&
		    !bpf_strncmp(buf, sizeof(label_sealed), label_sealed)) {
			refused++;
			return -EPERM;
		}
		bpf_dynptr_from_mem(buf, len, 0, &value);
		set_ret = bpf_set_kernfs_xattr(kn, xattr_zone, &value);
		if (set_ret)
			return 0;
		if (dir)
			labelled_dirs++;
		else
			labelled_files++;
		return 0;
	case MODE_RELABEL_PARENT:
		bpf_dynptr_from_mem(label_beta, sizeof(label_beta), 0, &value);
		set_ret = bpf_set_kernfs_xattr(kn_dir, xattr_zone, &value);
		return 0;
	case MODE_SHORT_NAME:
		bpf_dynptr_from_mem(label_beta, sizeof(label_beta), 0, &value);
		set_ret = bpf_set_kernfs_xattr(kn, xattr_prefix, &value);
		return 0;
	case MODE_USER_SET:
		bpf_dynptr_from_mem(label_beta, sizeof(label_beta), 0, &value);
		set_ret = bpf_set_kernfs_xattr(kn, xattr_user_zone, &value);
		return 0;
	case MODE_READ_USER:
		bpf_dynptr_from_mem(buf, sizeof(buf), 0, &value);
		len = bpf_get_kernfs_xattr(kn_dir, xattr_user_note, &value);
		get_ret = len;
		if (len <= 0 || len > LABEL_MAX)
			return 0;
		/* Hand what was read on, so that userspace can see it. */
		bpf_dynptr_from_mem(buf, len, 0, &value);
		set_ret = bpf_set_kernfs_xattr(kn, xattr_note, &value);
		return 0;
	case MODE_SHORT_BUFFER:
		bpf_dynptr_from_mem(buf, 2, 0, &value);
		get_ret = bpf_get_kernfs_xattr(kn_dir, xattr_zone, &value);
		return 0;
	case MODE_FOREIGN_NAME:
		bpf_dynptr_from_mem(buf, sizeof(buf), 0, &value);
		get_ret = bpf_get_kernfs_xattr(kn_dir, xattr_selinux, &value);
		bpf_dynptr_from_mem(label_beta, sizeof(label_beta), 0, &value);
		set_ret = bpf_set_kernfs_xattr(kn, xattr_selinux, &value);
		return 0;
	}
	return 0;
}
