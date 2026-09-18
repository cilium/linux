// SPDX-License-Identifier: GPL-2.0
/* What a policy may not do with a socket label.
 *
 * bpf_set_sock_xattr() is admitted on the three hooks that are handed a
 * socket the kernel has just allocated, and nowhere else, so a label cannot
 * be rewritten under a hook that has already acted on it. The socket's own
 * struct file stays out of reach as before: struct socket carries only ->sk
 * in its trusted field set.
 */
#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_kfuncs.h"
#include "bpf_experimental.h"
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

#define ZONE_MAX	32

const char xattr_zone[] = "security.bpf.zone";
char probe[ZONE_MAX];

/* Relabelling on the data path: refused at load time. */
SEC("lsm.s/socket_sendmsg")
__failure __msg("calling kernel function bpf_set_sock_xattr is not allowed")
int BPF_PROG(set_at_sendmsg, struct socket *sock)
{
	struct bpf_dynptr value;

	bpf_dynptr_from_mem(probe, sizeof(probe), 0, &value);
	bpf_set_sock_xattr(sock, xattr_zone, &value);
	return 0;
}

SEC("lsm.s/socket_connect")
__failure __msg("calling kernel function bpf_set_sock_xattr is not allowed")
int BPF_PROG(set_at_connect, struct socket *sock)
{
	struct bpf_dynptr value;

	bpf_dynptr_from_mem(probe, sizeof(probe), 0, &value);
	bpf_set_sock_xattr(sock, xattr_zone, &value);
	return 0;
}

/* The socket's file is still untrusted, so the file xattr kfuncs cannot be
 * turned on a socket to reach the same store by another road.
 */
SEC("lsm.s/socket_post_create")
__failure __msg("must be referenced or trusted")
int BPF_PROG(set_xattr_on_sock_file, struct socket *sock)
{
	struct bpf_dynptr value;

	bpf_dynptr_from_mem(probe, sizeof(probe), 0, &value);
	bpf_set_file_xattr(sock->file, xattr_zone, &value, 0);
	return 0;
}
