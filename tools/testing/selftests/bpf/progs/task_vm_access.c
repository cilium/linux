// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

#include "bpf_misc.h"

int target_pid = 0;
int victim_pid = 0;
void *user_ptr = NULL;
int copy_task_ret = 0;
int copy_task_str_ret = 0;
char copy_task_str_buf[16];

char _license[] SEC("license") = "GPL";

int bpf_copy_from_user_task_str(void *dst, u32 dst__sz, const void *unsafe_ptr,
				struct task_struct *tsk, u64 flags) __weak __ksym;
struct task_struct *bpf_task_from_pid(s32 pid) __weak __ksym;
void bpf_task_release(struct task_struct *p) __weak __ksym;

SEC("fentry.s/" SYS_PREFIX "sys_nanosleep")
int do_copy_from_task(void *ctx)
{
	struct task_struct *task;
	char buf[16];

	if ((bpf_get_current_pid_tgid() >> 32) != target_pid)
		return 0;

	task = bpf_task_from_pid(victim_pid);
	if (!task)
		return 0;

	copy_task_ret = bpf_copy_from_user_task(buf, sizeof(buf), user_ptr, task, 0);
	copy_task_str_ret = bpf_copy_from_user_task_str(copy_task_str_buf,
							sizeof(copy_task_str_buf),
							user_ptr, task, 0);
	bpf_task_release(task);
	return 0;
}
