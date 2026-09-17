// SPDX-License-Identifier: GPL-2.0
/* Unix sockets, scoped by the zone of the cgroup a task runs in. A unix
 * socket belongs to the cgroup it was created in, which the kernel records
 * on the sock, so its zone is read like a task's: one of the trusted zone
 * cannot be connected or sent to from any other zone, and a stream
 * connection is checked again on every send, so a descriptor handed to the
 * default zone or kept across a zone change carries nothing either.
 */
#include "lsm_zone.h"

char _license[] SEC("license") = "GPL";

__u32 monitored_pid;
__u32 socket_denied;

static __always_inline bool monitored(void)
{
	return (bpf_get_current_pid_tgid() >> 32) == monitored_pid;
}

/* Connecting or sending to a unix socket of the trusted zone from any other
 * is refused; the trusted zone may still connect outward.
 */
static __always_inline int guard_peer(struct sock *other)
{
	struct scratch *s;

	if (!monitored())
		return 0;
	s = scratch();
	if (sock_zone(s, other) != ZONE_TRUSTED)
		return 0;
	if (current_zone(s) == ZONE_TRUSTED)
		return 0;
	socket_denied++;
	return -EPERM;
}

SEC("lsm/unix_stream_connect")
int BPF_PROG(guard_unix_connect, struct sock *sock, struct sock *other,
	     struct sock *newsk)
{
	return guard_peer(other);
}

SEC("lsm/unix_may_send")
int BPF_PROG(guard_unix_send, struct socket *sock, struct socket *other)
{
	return guard_peer(BPF_CORE_READ(other, sk));
}

/* A connected unix stream has no hook of its own per message, so check the
 * peer again on every send: a connection made before the policy attached,
 * or handed over, or kept by a task moved out of the trusted zone, carries
 * nothing to a trusted socket.
 */
SEC("lsm/socket_sendmsg")
int BPF_PROG(guard_sendmsg, struct socket *sock, struct msghdr *msg, int size)
{
	struct sock *sk = BPF_CORE_READ(sock, sk), *peer;
	__u16 family, type;

	if (!sk)
		return 0;
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	type = BPF_CORE_READ(sk, sk_type);
	if (family != AF_UNIX || (type != SOCK_STREAM && type != SOCK_SEQPACKET))
		return 0;
	peer = BPF_CORE_READ((struct unix_sock *)sk, peer);
	if (!peer)
		return 0;
	return guard_peer(peer);
}
