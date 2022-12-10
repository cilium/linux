// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#define AF_INET6 10

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 1);
        __type(key, __u32);
        __type(value, __u64);
} tcp_conn_sockets SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 2);
        __type(key, __u32);
        __type(value, __u64);
} udp_conn_sockets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} sockmap SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 10);
        __type(key, __u32);
        __type(value, int);
} output SEC(".maps");


SEC("cgroup/connect6")
int sock_connect(struct bpf_sock_addr *ctx)
{
	int key = 0;
	__u64 sock_cookie = 0;
	__u32 keyc = 0;
	__u32 keyc1 = 1;

	if (ctx->family != AF_INET6 || ctx->user_family != AF_INET6)
		return 1;

	sock_cookie = bpf_get_socket_cookie(ctx);
	if (ctx->protocol == IPPROTO_TCP)
		bpf_map_update_elem(&tcp_conn_sockets, &key, &sock_cookie, 0);
	else if (ctx->protocol == IPPROTO_UDP)
		bpf_map_update_elem(&udp_conn_sockets, &keyc1, &sock_cookie, 0);
	else
		return 1;

	if (ctx->sk) 
		bpf_map_update_elem(&sockmap, &keyc, ctx->sk, 0);

	return 1;
}

SEC("iter/sockmap")
int iter_sockmap(struct bpf_iter__sockmap *ctx)
{
	struct sock *sk = ctx->sk;
	__u32 *key = ctx->key;
	__u64 sock_cookie = 0;
	__u32 key_s = 0;
	__u64 *val;
	__u16 proto;

	if (!key || !sk)
		return 0;

	proto = sk->sk_protocol;
	if (proto == IPPROTO_TCP)
		val = bpf_map_lookup_elem(&tcp_conn_sockets, &key_s);
	else if (proto == IPPROTO_UDP)
		val = bpf_map_lookup_elem(&udp_conn_sockets, &key_s);
	else
		return 0;

	if (val == (void *) 0)
		return 0;

	sock_cookie  = bpf_get_socket_cookie(sk);
	if (sock_cookie == *val)
		bpf_sock_destroy(sk);

	return 0;
}

SEC("iter/tcp")
int iter_tcp6(struct bpf_iter__tcp *ctx)
{
	struct sock_common *sk_common = ctx->sk_common;
	struct seq_file *seq = ctx->meta->seq;
	__u64 sock_cookie = 0;
	__u64 *val;
	int key = 0;

	if (sk_common == (void *) 0)
		return 0;

	if (sk_common->skc_family != AF_INET6)
		return 0;

	sock_cookie  = bpf_get_socket_cookie(sk_common);
	val = bpf_map_lookup_elem(&tcp_conn_sockets, &key);

	if (val == (void *) 0)
		return 0;

	if (sock_cookie == *val) {
		bpf_sock_destroy(sk_common);
	}
	
	return 0;
}

SEC("iter/udp")
int iter_udp6(struct bpf_iter__udp *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct udp_sock *udp_sk = ctx->udp_sk;
	struct sock *sk = (struct sock *) udp_sk;
	__u64 sock_cookie = 0;
	int key = 1;
	__u64 *val;

	if (sk == (void *)0)
		return 0;

	sock_cookie  = bpf_get_socket_cookie(sk);
	val = bpf_map_lookup_elem(&udp_conn_sockets, &key);

	if (val == (void *) 0)
		return 0;

	if (sock_cookie == *val) {
		bpf_sock_destroy(sk);
	}
	
	return 0;
}

char _license[] SEC("license") = "GPL";
