// SPDX-License-Identifier: GPL-2.0
/* Atomics need an address the verifier knows to be aligned */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} ringbuf SEC(".maps");

struct lpm_key {
	__u32 prefixlen;
	__u32 addr;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 1);
	__type(key, struct lpm_key);
	__type(value, __u64);
} lpm SEC(".maps");

__u64 buf[2];

SEC("tc")
__description("atomic add on dynptr data")
__failure __msg("BPF_ATOMIC stores into R0 mem is not allowed")
int atomic_dynptr_data(void *ctx)
{
	struct bpf_dynptr ptr;
	__u64 *p;

	if (bpf_ringbuf_reserve_dynptr(&ringbuf, 16, 0, &ptr))
		goto out;
	p = bpf_dynptr_data(&ptr, 4, sizeof(*p));
	if (p)
		__sync_fetch_and_add(p, 1);
out:
	bpf_ringbuf_discard_dynptr(&ptr, 0);
	return 0;
}

__noinline int atomic_add_to(__u64 *p)
{
	if (p)
		__sync_fetch_and_add(p, 1);
	return 0;
}

SEC("tc")
__description("atomic add through the pointer argument of a global subprog")
__failure __msg("BPF_ATOMIC stores into R1 mem is not allowed")
int atomic_global_arg(void *ctx)
{
	return atomic_add_to(&buf[1]);
}

SEC("tc")
__description("atomic add on a ring buffer record")
__success __retval(0)
int atomic_ringbuf_record(void *ctx)
{
	__u64 *p;

	p = bpf_ringbuf_reserve(&ringbuf, sizeof(*p), 0);
	if (!p)
		return 1;
	*p = 0;
	__sync_fetch_and_add(p, 1);
	bpf_ringbuf_discard(p, 0);
	return 0;
}

SEC("tc")
__description("atomic add on the value of an LPM trie with a 4 byte key")
__success __retval(0)
int atomic_lpm_value(void *ctx)
{
	struct lpm_key key = { .prefixlen = 32, .addr = 1 };
	__u64 val = 0, *p;

	if (bpf_map_update_elem(&lpm, &key, &val, 0))
		return 1;
	p = bpf_map_lookup_elem(&lpm, &key);
	if (!p)
		return 2;
	__sync_fetch_and_add(p, 1);
	return (__u64)p & 7 ? 3 : 0;
}

char _license[] SEC("license") = "GPL";
