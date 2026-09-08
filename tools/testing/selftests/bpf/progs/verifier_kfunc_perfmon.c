// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

void *user_ptr;
char dynptr_buf[8];
char str_buf[8];
u64 bits_data;

SEC("socket")
__success
__caps_unpriv(CAP_BPF)
__failure_unpriv
__msg_unpriv("bpf_rdonly_cast is allowed only to CAP_PERFMON and CAP_SYS_ADMIN")
int rdonly_cast_noperfmon(void *ctx)
{
	char *p = bpf_rdonly_cast(0, 0);

	return p[0x7fff];
}

SEC("socket")
__success
__caps_unpriv(CAP_BPF)
__failure_unpriv
__msg_unpriv("bpf_probe_read_kernel_dynptr is allowed only to CAP_PERFMON and CAP_SYS_ADMIN")
int probe_read_kernel_dynptr_noperfmon(void *ctx)
{
	struct bpf_dynptr dptr;

	bpf_dynptr_from_mem(dynptr_buf, sizeof(dynptr_buf), 0, &dptr);
	bpf_probe_read_kernel_dynptr(&dptr, 0, sizeof(dynptr_buf), user_ptr);
	return 0;
}

SEC("socket")
__success
__caps_unpriv(CAP_BPF)
__failure_unpriv
__msg_unpriv("bpf_probe_read_kernel_str_dynptr is allowed only to CAP_PERFMON and CAP_SYS_ADMIN")
int probe_read_kernel_str_dynptr_noperfmon(void *ctx)
{
	struct bpf_dynptr dptr;

	bpf_dynptr_from_mem(dynptr_buf, sizeof(dynptr_buf), 0, &dptr);
	bpf_probe_read_kernel_str_dynptr(&dptr, 0, sizeof(dynptr_buf), user_ptr);
	return 0;
}

SEC("socket")
__success
__caps_unpriv(CAP_BPF)
__failure_unpriv
__msg_unpriv("bpf_probe_read_user_dynptr is allowed only to CAP_PERFMON and CAP_SYS_ADMIN")
int probe_read_user_dynptr_noperfmon(void *ctx)
{
	struct bpf_dynptr dptr;

	bpf_dynptr_from_mem(dynptr_buf, sizeof(dynptr_buf), 0, &dptr);
	bpf_probe_read_user_dynptr(&dptr, 0, sizeof(dynptr_buf), user_ptr);
	return 0;
}

SEC("socket")
__success
__caps_unpriv(CAP_BPF)
__failure_unpriv
__msg_unpriv("bpf_probe_read_user_str_dynptr is allowed only to CAP_PERFMON and CAP_SYS_ADMIN")
int probe_read_user_str_dynptr_noperfmon(void *ctx)
{
	struct bpf_dynptr dptr;

	bpf_dynptr_from_mem(dynptr_buf, sizeof(dynptr_buf), 0, &dptr);
	bpf_probe_read_user_str_dynptr(&dptr, 0, sizeof(dynptr_buf), user_ptr);
	return 0;
}

SEC("syscall")
__success
__caps_unpriv(CAP_BPF)
__failure_unpriv
__msg_unpriv("bpf_copy_from_user_str is allowed only to CAP_PERFMON and CAP_SYS_ADMIN")
int copy_from_user_str_noperfmon(void *ctx)
{
	char buf[8];

	bpf_copy_from_user_str(buf, sizeof(buf), user_ptr, 0);
	return 0;
}

SEC("syscall")
__success
__caps_unpriv(CAP_BPF)
__failure_unpriv
__msg_unpriv("bpf_copy_from_user_dynptr is allowed only to CAP_PERFMON and CAP_SYS_ADMIN")
int copy_from_user_dynptr_noperfmon(void *ctx)
{
	struct bpf_dynptr dptr;

	bpf_dynptr_from_mem(dynptr_buf, sizeof(dynptr_buf), 0, &dptr);
	bpf_copy_from_user_dynptr(&dptr, 0, sizeof(dynptr_buf), user_ptr);
	return 0;
}

SEC("syscall")
__success
__caps_unpriv(CAP_BPF)
__failure_unpriv
__msg_unpriv("bpf_copy_from_user_str_dynptr is allowed only to CAP_PERFMON and CAP_SYS_ADMIN")
int copy_from_user_str_dynptr_noperfmon(void *ctx)
{
	struct bpf_dynptr dptr;

	bpf_dynptr_from_mem(dynptr_buf, sizeof(dynptr_buf), 0, &dptr);
	bpf_copy_from_user_str_dynptr(&dptr, 0, sizeof(dynptr_buf), user_ptr);
	return 0;
}

SEC("syscall")
__success
__caps_unpriv(CAP_BPF)
__failure_unpriv
__msg_unpriv("bpf_copy_from_user_task_str is allowed only to CAP_PERFMON and CAP_SYS_ADMIN")
int copy_from_user_task_str_noperfmon(void *ctx)
{
	struct task_struct *task;
	char buf[8];

	task = bpf_task_from_pid(1);
	if (!task)
		return 0;

	bpf_copy_from_user_task_str(buf, sizeof(buf), user_ptr, task, 0);
	bpf_task_release(task);
	return 0;
}

SEC("syscall")
__success
__caps_unpriv(CAP_BPF)
__failure_unpriv
__msg_unpriv("bpf_copy_from_user_task_dynptr is allowed only to CAP_PERFMON and CAP_SYS_ADMIN")
int copy_from_user_task_dynptr_noperfmon(void *ctx)
{
	struct task_struct *task;
	struct bpf_dynptr dptr;

	task = bpf_task_from_pid(1);
	if (!task)
		return 0;

	bpf_dynptr_from_mem(dynptr_buf, sizeof(dynptr_buf), 0, &dptr);
	bpf_copy_from_user_task_dynptr(&dptr, 0, sizeof(dynptr_buf), user_ptr, task);
	bpf_task_release(task);
	return 0;
}

SEC("syscall")
__success
__caps_unpriv(CAP_BPF)
__failure_unpriv
__msg_unpriv("bpf_copy_from_user_task_str_dynptr is allowed only to CAP_PERFMON and CAP_SYS_ADMIN")
int copy_from_user_task_str_dynptr_noperfmon(void *ctx)
{
	struct task_struct *task;
	struct bpf_dynptr dptr;

	task = bpf_task_from_pid(1);
	if (!task)
		return 0;

	bpf_dynptr_from_mem(dynptr_buf, sizeof(dynptr_buf), 0, &dptr);
	bpf_copy_from_user_task_str_dynptr(&dptr, 0, sizeof(dynptr_buf), user_ptr, task);
	bpf_task_release(task);
	return 0;
}

SEC("socket")
__success
__caps_unpriv(CAP_BPF)
__failure_unpriv
__msg_unpriv("bpf_iter_bits_new is allowed only to CAP_PERFMON and CAP_SYS_ADMIN")
int iter_bits_noperfmon(void *ctx)
{
	struct bpf_iter_bits it;

	bpf_iter_bits_new(&it, &bits_data, 1);
	bpf_iter_bits_next(&it);
	bpf_iter_bits_destroy(&it);
	return 0;
}

SEC("socket")
__success
__caps_unpriv(CAP_BPF)
__failure_unpriv
__msg_unpriv("bpf_strlen is allowed only to CAP_PERFMON and CAP_SYS_ADMIN")
int strlen_noperfmon(void *ctx)
{
	return bpf_strlen(str_buf);
}

SEC("socket")
__success
__caps_unpriv(CAP_BPF)
__failure_unpriv
__msg_unpriv("bpf_strcmp is allowed only to CAP_PERFMON and CAP_SYS_ADMIN")
int strcmp_noperfmon(void *ctx)
{
	return bpf_strcmp(str_buf, str_buf);
}

/*
 * bpf_rdonly_cast() is not the only way to obtain
 * PTR_TO_MEM | MEM_RDONLY | PTR_UNTRUSTED: a global subprogram argument
 * tagged __arg_untrusted yields the same thing without a kfunc call, so
 * the rejection has to come from the dereference rather than from
 * check_kfunc_call().
 */
__weak int subprog_untrusted_read(void *p __arg_untrusted)
{
	return *(char *)p;
}

SEC("socket")
__success
__caps_unpriv(CAP_BPF)
__failure_unpriv
__msg_unpriv("rdonly_untrusted_mem access is allowed only to CAP_PERFMON and CAP_SYS_ADMIN")
int arg_untrusted_read_noperfmon(void *ctx)
{
	return subprog_untrusted_read(0);
}

char _license[] SEC("license") = "GPL";
