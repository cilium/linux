// SPDX-License-Identifier: GPL-2.0
#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

enum {
	AFTER_ASSIGN_PASS,
	AFTER_ASSIGN_DROP,
	AFTER_ASSIGN_REDIRECT,
};

const volatile __u16 dest_port;
const volatile __u16 proxy_port;
const volatile bool measure_queue;
const volatile bool use_proxy_map;
const volatile __u32 after_assign;
const volatile __u32 redirect_ifindex;
__u64 reuse_calls;
__u64 reuse_errors;
__u64 listener_assignments;
__u64 established_assignments;
__u64 assign_errors;
__u64 request_rejections;
__u64 measurement_started;
__u64 measurement_done;
__u64 blocked_syns;
struct bpf_sock_tuple probe_tuple;
__u32 probe_len;
__u32 probe_state;
int probe_result;

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} proxy_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} reuse_map SEC(".maps");

SEC("netkit/peer")
int assign_socket(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct bpf_sock_tuple tuple = {};
	struct ethhdr *eth = data;
	struct bpf_sock *sk;
	struct tcphdr *th;
	bool ipv4;
	__u32 len;
	int ret;

	if (eth + 1 > data_end)
		return TCX_PASS;
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = (void *)(eth + 1);

		if (iph + 1 > data_end || iph->ihl != 5 ||
		    iph->protocol != IPPROTO_TCP)
			return TCX_PASS;
		tuple.ipv4.saddr = iph->saddr;
		tuple.ipv4.daddr = iph->daddr;
		th = (void *)(iph + 1);
		len = sizeof(tuple.ipv4);
		ipv4 = true;
	} else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h = (void *)(eth + 1);

		if (ip6h + 1 > data_end || ip6h->nexthdr != IPPROTO_TCP)
			return TCX_PASS;
		__builtin_memcpy(tuple.ipv6.saddr, &ip6h->saddr,
				 sizeof(tuple.ipv6.saddr));
		__builtin_memcpy(tuple.ipv6.daddr, &ip6h->daddr,
				 sizeof(tuple.ipv6.daddr));
		th = (void *)(ip6h + 1);
		len = sizeof(tuple.ipv6);
		ipv4 = false;
	} else {
		return TCX_PASS;
	}
	if (th + 1 > data_end || th->dest != bpf_htons(dest_port))
		return TCX_PASS;
	if (measure_queue) {
		skb->mark = 0;
		if (th->syn && !th->ack) {
			if (__sync_val_compare_and_swap(&measurement_started, 0, 1)) {
				__sync_fetch_and_add(&blocked_syns, 1);
				return TCX_DROP;
			}
			skb->mark = 1;
		} else if (!__sync_val_compare_and_swap(&measurement_done, 0, 0)) {
			return TCX_DROP;
		}
	}
	if (ipv4) {
		tuple.ipv4.sport = th->source;
		tuple.ipv4.dport = th->dest;
	} else {
		tuple.ipv6.sport = th->source;
		tuple.ipv6.dport = th->dest;
	}

	sk = bpf_skc_lookup_tcp(skb, &tuple, len, BPF_F_CURRENT_NETNS, 0);
	if (sk) {
		if (sk->state == BPF_TCP_NEW_SYN_RECV) {
			ret = bpf_sk_assign(skb, sk, 0);
			bpf_sk_release(sk);
			if (ret == -EOPNOTSUPP)
				__sync_fetch_and_add(&request_rejections, 1);
			else
				__sync_fetch_and_add(&assign_errors, 1);
			return TCX_PASS;
		}
		if (sk->state != BPF_TCP_LISTEN &&
		    sk->state != BPF_TCP_TIME_WAIT) {
			if (sk->state == BPF_TCP_ESTABLISHED)
				__sync_fetch_and_add(&established_assignments, 1);
			goto assign;
		}
		bpf_sk_release(sk);
	}

	if (use_proxy_map) {
		__u32 zero = 0;

		sk = bpf_map_lookup_elem(&proxy_map, &zero);
	} else {
		__builtin_memset(&tuple, 0, sizeof(tuple));
		if (ipv4)
			tuple.ipv4.dport = bpf_htons(proxy_port);
		else
			tuple.ipv6.dport = bpf_htons(proxy_port);
		sk = bpf_skc_lookup_tcp(skb, &tuple, len, BPF_F_CURRENT_NETNS,
					0);
	}
	if (!sk) {
		__sync_fetch_and_add(&assign_errors, 1);
		return TCX_DROP;
	}
	__sync_fetch_and_add(&listener_assignments, 1);
assign:
	ret = bpf_sk_assign(skb, sk, 0);
	bpf_sk_release(sk);
	if (ret) {
		__sync_fetch_and_add(&assign_errors, 1);
		return TCX_DROP;
	}
	if (after_assign == AFTER_ASSIGN_DROP)
		return TCX_DROP;
	if (after_assign == AFTER_ASSIGN_REDIRECT)
		return bpf_redirect(redirect_ifindex, 0);
	return TCX_PASS;
}

SEC("sk_reuseport")
int select_second(struct sk_reuseport_md *ctx)
{
	__u32 index = 1;

	__sync_fetch_and_add(&reuse_calls, 1);
	if (bpf_sk_select_reuseport(ctx, &reuse_map, &index, 0)) {
		__sync_fetch_and_add(&reuse_errors, 1);
		return SK_DROP;
	}
	return SK_PASS;
}

SEC("tc")
int probe_timewait(struct __sk_buff *skb)
{
	struct bpf_sock *sk;

	if (probe_len == sizeof(probe_tuple.ipv4))
		sk = bpf_skc_lookup_tcp(skb, &probe_tuple,
					sizeof(probe_tuple.ipv4),
					BPF_F_CURRENT_NETNS, 0);
	else
		sk = bpf_skc_lookup_tcp(skb, &probe_tuple,
					sizeof(probe_tuple.ipv6),
					BPF_F_CURRENT_NETNS, 0);
	if (!sk)
		return TCX_PASS;
	probe_state = sk->state;
	probe_result = bpf_sk_assign(skb, sk, 0);
	bpf_sk_release(sk);
	return TCX_PASS;
}

char LICENSE[] SEC("license") = "GPL";
