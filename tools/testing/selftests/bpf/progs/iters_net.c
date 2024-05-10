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
int count;

SEC("fentry/" SYS_PREFIX "sys_getpgid")
int foo(void *ctx)
{
	struct task_struct *cur_task = bpf_get_current_task_btf();
	struct net *net;

	if (cur_task->pid == target_pid) {
		bpf_for_each(net, net)
			count++;
	}
	return 0;
}
