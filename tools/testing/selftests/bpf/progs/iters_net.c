// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Isovalent */

#include "vmlinux.h"

#include <errno.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_misc.h"
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

pid_t target_pid;
__u64 cookie;
int count;
bool seen;

SEC("fentry/" SYS_PREFIX "sys_getpgid")
int foo(void *ctx)
{
	struct task_struct *cur_task = bpf_get_current_task_btf();
	struct net *net, *init = bpf_net_init();

	if (cur_task->pid == target_pid) {
		bpf_for_each(net, net) {
			count++;
			if (net == init)
				seen = true;
		}
	}
	return 0;
}

SEC("fentry/" SYS_PREFIX "sys_getpgid")
int foo_nested(void *ctx)
{
	struct task_struct *cur_task = bpf_get_current_task_btf();
	struct bpf_iter__tcp *tcp;
	struct sock_common *skc;
	struct net *net;

	if (cur_task->pid == target_pid) {
		bpf_for_each(net, net) {
			bpf_for_each(tcp, tcp, net) {
				skc = tcp->sk_common;
				if (bpf_get_socket_cookie(skc) == cookie) {
					bpf_sock_destroy(skc);
				}
			}
		}
	}
	return 0;
}
