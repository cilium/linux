// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Isovalent */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

__u64 deliver_rcu_count = 0;
__u64 drop_count = 0;

SEC("fentry/ip6_protocol_deliver_rcu")
int BPF_PROG(trace_deliver_rcu, struct net *net, struct sk_buff *skb,
	     int nexthdr, bool have_final)
{
	__sync_fetch_and_add(&deliver_rcu_count, 1);
	return 0;
}

SEC("tp_btf/kfree_skb")
int BPF_PROG(trace_kfree_skb, struct sk_buff *skb, void *location,
	     enum skb_drop_reason reason)
{
	if (reason == SKB_DROP_REASON_IPV6_TOO_MANY_EXTHDRS)
		__sync_fetch_and_add(&drop_count, 1);
	return 0;
}
