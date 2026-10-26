// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_experimental.h"

#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

extern unsigned long bpf_user_mmap(unsigned long len, unsigned long prot) __ksym;
extern int bpf_user_munmap(unsigned long addr, unsigned long len) __ksym;
extern int bpf_copy_to_user_task(void *unsafe_ptr__ign, const void *src__srcptr,
				 u32 src__sz, struct task_struct *tsk,
				 u64 flags) __ksym;

enum {
	USER_PAGE_MMAP = 1,
	USER_PAGE_UNMAP,
	USER_PAGE_COPY_INSNS,
	USER_PAGE_COPY,
	USER_PAGE_WQ,
};

int monitored_pid;
int action;
unsigned long user_addr;
unsigned long map_len;
unsigned long map_prot;
u64 copy_flags;
u32 copy_size;
int ret;
#if defined(__TARGET_ARCH_x86)
static const unsigned char insns[] = {
	0xf3, 0x0f, 0x1e, 0xfa, /* endbr64 */
	0xb8, 42, 0, 0, 0, 0xc3, /* mov $42, %eax; ret */
};
#elif defined(__TARGET_ARCH_arm64)
static const unsigned char insns[] = {
	0x5f, 0x24, 0x03, 0xd5, /* bti c */
	0x40, 0x05, 0x80, 0x52, /* mov w0, #42 */
	0xc0, 0x03, 0x5f, 0xd6, /* ret */
};
#else
/* The execute tests are skipped on other architectures. */
static const unsigned char insns[] = { 0 };
#endif
static const char data[] = "fault-enabled BPF write";

SEC("uprobe.s//proc/self/exe:user_mem_trigger")
int user_mem_test(struct pt_regs *ctx)
{
	if ((bpf_get_current_pid_tgid() >> 32) != monitored_pid)
		return 0;

	switch (action) {
	case USER_PAGE_MMAP:
		user_addr = bpf_user_mmap(map_len, map_prot);
		break;
	case USER_PAGE_UNMAP:
		ret = bpf_user_munmap(user_addr, map_len);
		break;
	case USER_PAGE_COPY_INSNS:
		ret = bpf_copy_to_user_task((void *)user_addr, insns,
					       sizeof(insns),
					       bpf_get_current_task_btf(), 0);
		break;
	case USER_PAGE_COPY:
		if (copy_size > sizeof(data)) {
			ret = -22; /* -EINVAL */
			break;
		}
		ret = bpf_copy_to_user_task((void *)user_addr, data,
					       copy_size,
					       bpf_get_current_task_btf(), copy_flags);
		break;
	}

	return 0;
}

SEC("?uprobe//proc/self/exe:user_mem_trigger")
__failure
__msg("program must be sleepable to call sleepable kfunc bpf_user_mmap")
__msg("cannot be used in non-sleepable program")
int user_mem_nonsleepable(struct pt_regs *ctx)
{
	bpf_user_mmap(4096, 1);
	return 0;
}

struct wq_elem {
	struct bpf_wq wq;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct wq_elem);
} wq_map SEC(".maps");

unsigned long wq_mmap_ret;
int wq_munmap_ret;
int wq_done;

/* Runs on a kworker, which has no user mm. */
static int wq_callback(void *map, int *key, void *value)
{
	wq_mmap_ret = bpf_user_mmap(4096, 3 /* PROT_READ | PROT_WRITE */);
	wq_munmap_ret = bpf_user_munmap(4096, 4096);
	wq_done = 1;
	return 0;
}

SEC("uprobe//proc/self/exe:user_mem_trigger")
int user_mem_wq(struct pt_regs *ctx)
{
	struct wq_elem *val;
	int key = 0;

	if ((bpf_get_current_pid_tgid() >> 32) != monitored_pid || action != USER_PAGE_WQ)
		return 0;

	val = bpf_map_lookup_elem(&wq_map, &key);
	if (!val || bpf_wq_init(&val->wq, &wq_map, 0) ||
	    bpf_wq_set_callback(&val->wq, wq_callback, 0))
		return 0;
	bpf_wq_start(&val->wq, 0);
	return 0;
}

SEC("?uprobe.s//proc/self/exe:user_mem_trigger")
__failure_unpriv __caps_unpriv(CAP_BPF | CAP_PERFMON)
__msg_unpriv("calling kernel function bpf_user_mmap is not allowed")
int user_mem_no_sysadmin(struct pt_regs *ctx)
{
	bpf_user_mmap(4096, 1);
	return 0;
}
