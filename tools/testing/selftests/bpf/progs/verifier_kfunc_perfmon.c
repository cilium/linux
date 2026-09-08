// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bpf_misc.h"

/*
 * Every kfunc below hands out a read of memory the program has no other way
 * to reach, and the helper form of the same primitive is only returned by
 * bpf_base_func_proto() past the CAP_PERFMON gate, so a CAP_BPF only loader
 * has to be rejected for the kfunc form as well.
 *
 * The kfuncs that are not sleepable are called from SEC("socket"), which
 * also shows that they are reachable well outside the tracing program types.
 * The sleepable ones are called from SEC("syscall"), that being the
 * sleepable program type a CAP_BPF holder can load.
 *
 * This file has to load unprivileged, so unlike mem_rdonly_untrusted.c it
 * cannot pull in test_kmods kfuncs: resolving module BTF takes CAP_SYS_ADMIN.
 */

void *user_ptr;

/* bpf_dynptr_from_mem() takes a map value, so keep the buffer global. */
char dynptr_buf[8];

/*
 * A void type ID turns any value into unsized rdonly untrusted memory, and
 * reads from it are unbounded, so it takes CAP_PERFMON just like reading
 * through a PTR_TO_BTF_ID does.
 */
SEC("socket")
__success
__caps_unpriv(CAP_BPF)
__failure_unpriv
__msg_unpriv("bpf_rdonly_cast is allowed only to CAP_PERFMON and CAP_SYS_ADMIN")
int rdonly_cast_noperfmon(void *ctx)
{
	char *p;

	if (!bpf_core_enum_value_exists(enum bpf_features, BPF_FEAT_RDONLY_CAST_TO_VOID))
		return 42;

	p = bpf_rdonly_cast(0, 0);
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

/*
 * Reading the address space of another task is the same primitive
 * process_vm_readv(2) and /proc/<pid>/mem provide, so bpf_task_from_pid()
 * plus one of the three kfuncs below is an arbitrary read of any task on
 * the system.
 */
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

char _license[] SEC("license") = "GPL";
