// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "bpf_tracing_net.h"

const volatile __u16 service_port;
const volatile __u16 proxy_port;
const volatile bool udp;
__u64 assigned;
__u64 errors;
int clone_ret = 1;
int egress_ret = 1;

SEC("netkit/peer")
int assign_proxy(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct bpf_sock_tuple tuple = {};
	struct ethhdr *eth = data;
	struct bpf_sock *sk;
	struct udphdr *uh;
	struct tcphdr *th;
	__u8 proto;
	void *l4;
	__u32 len;
	int ret;

	if (eth + 1 > data_end)
		return NETKIT_PASS;
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = (void *)(eth + 1);

		if (iph + 1 > data_end || iph->ihl != 5)
			return NETKIT_PASS;
		proto = iph->protocol;
		l4 = iph + 1;
		tuple.ipv4.dport = bpf_htons(proxy_port);
		len = sizeof(tuple.ipv4);
	} else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h = (void *)(eth + 1);

		if (ip6h + 1 > data_end)
			return NETKIT_PASS;
		proto = ip6h->nexthdr;
		l4 = ip6h + 1;
		tuple.ipv6.dport = bpf_htons(proxy_port);
		len = sizeof(tuple.ipv6);
	} else {
		return NETKIT_PASS;
	}
	if (proto == IPPROTO_TCP) {
		th = l4;
		if (th + 1 > data_end || th->dest != bpf_htons(service_port) ||
		    !th->syn || th->ack)
			return NETKIT_PASS;
		sk = bpf_sk_lookup_tcp(skb, &tuple, len, BPF_F_CURRENT_NETNS,
				       0);
	} else if (proto == IPPROTO_UDP) {
		uh = l4;
		if (uh + 1 > data_end || uh->dest != bpf_htons(service_port))
			return NETKIT_PASS;
		sk = bpf_sk_lookup_udp(skb, &tuple, len, BPF_F_CURRENT_NETNS,
				       0);
	} else {
		return NETKIT_PASS;
	}
	if (!sk)
		goto err;
	ret = bpf_sk_assign(skb, sk, 0);
	bpf_sk_release(sk);
	if (ret)
		goto err;
	__sync_fetch_and_add(&assigned, 1);
	clone_ret = bpf_clone_redirect(skb, skb->ifindex, 0);
	return NETKIT_PASS;
err:
	__sync_fetch_and_add(&errors, 1);
	return NETKIT_DROP;
}

SEC("tcx/egress")
int egress_assign(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	__u8 want = udp ? IPPROTO_UDP : IPPROTO_TCP;
	void *data = (void *)(long)skb->data;
	struct bpf_sock_tuple tuple = {};
	struct ethhdr *eth = data;
	struct bpf_sock *sk;
	__u32 len;

	if (egress_ret != 1 || eth + 1 > data_end)
		return TCX_PASS;
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = (void *)(eth + 1);

		if (iph + 1 > data_end || iph->protocol != want)
			return TCX_PASS;
		tuple.ipv4.dport = bpf_htons(proxy_port);
		len = sizeof(tuple.ipv4);
	} else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h = (void *)(eth + 1);

		if (ip6h + 1 > data_end || ip6h->nexthdr != want)
			return TCX_PASS;
		tuple.ipv6.dport = bpf_htons(proxy_port);
		len = sizeof(tuple.ipv6);
	} else {
		return TCX_PASS;
	}
	if (udp)
		sk = bpf_sk_lookup_udp(skb, &tuple, len, BPF_F_CURRENT_NETNS,
				       0);
	else
		sk = bpf_sk_lookup_tcp(skb, &tuple, len, BPF_F_CURRENT_NETNS,
				       0);
	if (!sk)
		return TCX_PASS;
	egress_ret = bpf_sk_assign(skb, sk, 0);
	bpf_sk_release(sk);
	return TCX_PASS;
}

char LICENSE[] SEC("license") = "GPL";
