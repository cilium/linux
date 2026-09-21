// SPDX-License-Identifier: GPL-2.0
/* A labelled socket does not cross to a task that was never granted its zone.
 *
 * The label lives on the socket's sockfs inode, so it rides along when the
 * descriptor is handed to another process over SCM_RIGHTS: the receiver ends
 * up holding a socket that carries a zone of its own accord. Relabelling it
 * is not the answer -- that would make a socket's label mutable after
 * creation, which is exactly what the creation-only restriction exists to
 * prevent. The pass itself is refused instead, at file_receive, which is
 * handed the struct file the receiver is about to be given.
 *
 * The label is read there with bpf_get_file_xattr(), which reaches the
 * sockfs inode through file_dentry(). No socket-specific kfunc is involved
 * and the file never has to be recognised as a socket at all: an unlabelled
 * file simply reads back nothing and is none of the policy's business.
 */
#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_kfuncs.h"
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

#define ZONE_MAX	32

const char xattr_zone[] = "security.bpf.zone";

__u32 owner_pid;		/* the task allowed to hold zoned sockets */
__u32 zone_len;			/* length the runner wrote into zone_value */
char zone_value[ZONE_MAX] = "prod";
char seen_zone[ZONE_MAX];	/* what file_receive read off the passed fd */
int sockets_labelled;
int receives_seen;
int receives_denied;
int label_ret = -999;

SEC("lsm.s/socket_post_create")
int BPF_PROG(label_at_create, struct socket *sock, int family, int type,
	     int protocol, int kern)
{
	struct bpf_dynptr value;

	if ((bpf_get_current_pid_tgid() >> 32) != owner_pid)
		return 0;
	if (!zone_len || zone_len > sizeof(zone_value))
		return 0;

	bpf_dynptr_from_mem(zone_value, sizeof(zone_value), 0, &value);
	bpf_dynptr_adjust(&value, 0, zone_len);
	if (!bpf_set_sock_xattr(sock, xattr_zone, &value))
		sockets_labelled++;
	return 0;
}

/* Every descriptor crossing SCM_RIGHTS passes through here, in the context
 * of the task about to receive it. A file with no label of ours reads back
 * nothing and is let through untouched.
 */
SEC("lsm.s/file_receive")
int BPF_PROG(guard_receive, struct file *file)
{
	struct bpf_dynptr value;
	int len;

	bpf_dynptr_from_mem(seen_zone, sizeof(seen_zone), 0, &value);
	len = bpf_get_file_xattr(file, xattr_zone, &value);
	if (len <= 0)
		return 0;

	receives_seen++;
	label_ret = len;
	if ((bpf_get_current_pid_tgid() >> 32) == owner_pid)
		return 0;

	receives_denied++;
	return -EPERM;
}
