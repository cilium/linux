// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <unistd.h>

#include "user_mem.skel.h"

enum {
	USER_PAGE_MMAP = 1,
	USER_PAGE_UNMAP,
	USER_PAGE_COPY_INSNS,
};

static noinline void user_mem_trigger(void)
{
	asm volatile ("");
}

static bool check_user_mem_vma(void *addr, long size, const char *perms)
{
	unsigned long start, end;
	bool found = false;
	char vma_perms[5];
	char line[512];
	FILE *maps;

	maps = fopen("/proc/self/maps", "r");
	if (!ASSERT_OK_PTR(maps, "open_maps"))
		return false;

	while (fgets(line, sizeof(line), maps)) {
		if (sscanf(line, "%lx-%lx %4s", &start, &end, vma_perms) != 3 ||
		    (unsigned long)addr < start || (unsigned long)addr >= end)
			continue;
		found = ASSERT_GE(end - (unsigned long)addr, (unsigned long)size,
				  "vma_size") &&
			(!perms || ASSERT_STREQ(vma_perms, perms, "vma_perms"));
		break;
	}
	fclose(maps);
	return ASSERT_TRUE(found, "user_mem_vma");
}

static bool check_user_mem_unmapped(void *addr)
{
	unsigned long start, end;
	bool found = false;
	char vma_perms[5];
	char line[512];
	FILE *maps;

	maps = fopen("/proc/self/maps", "r");
	if (!ASSERT_OK_PTR(maps, "open_maps"))
		return false;

	while (fgets(line, sizeof(line), maps)) {
		if (sscanf(line, "%lx-%lx %4s", &start, &end, vma_perms) != 3 ||
		    (unsigned long)addr < start || (unsigned long)addr >= end)
			continue;
		found = true;
		break;
	}
	fclose(maps);
	return ASSERT_FALSE(found, "user_mem_unmapped");
}

static bool alloc_user_mem(struct user_mem *skel, unsigned long len,
			   unsigned long prot, unsigned long *addr)
{
	skel->bss->map_len = len;
	skel->bss->map_prot = prot;
	skel->bss->action = USER_PAGE_MMAP;
	user_mem_trigger();
	/* vm_mmap() encodes errors in the top MAX_ERRNO unsigned-long values. */
	if (!ASSERT_LT(skel->bss->user_addr, -4095UL, "user_addr"))
		return false;

	*addr = skel->bss->user_addr;
	return true;
}

static bool unmap_user_mem(struct user_mem *skel, unsigned long addr,
			   unsigned long len)
{
	skel->bss->user_addr = addr;
	skel->bss->map_len = len;
	skel->bss->action = USER_PAGE_UNMAP;
	user_mem_trigger();
	return ASSERT_OK(skel->bss->ret, "user_munmap");
}

static bool write_user_mem(struct user_mem *skel, unsigned long addr)
{
	skel->bss->user_addr = addr;
	skel->bss->action = USER_PAGE_COPY_INSNS;
	user_mem_trigger();
	return ASSERT_OK(skel->bss->ret, "user_write");
}

static void test_allocations(struct user_mem *skel)
{
	void *pages[2] = { MAP_FAILED, MAP_FAILED };
	long page_size = sysconf(_SC_PAGESIZE);
	const unsigned long nr_pages = 3;
	const unsigned long len = page_size * nr_pages;
	unsigned long addr;
	int i;

	for (i = 0; i < ARRAY_SIZE(pages); i++) {
		if (!alloc_user_mem(skel, len, PROT_READ | PROT_WRITE, &addr))
			goto out;
		pages[i] = (void *)addr;
	}

	/* Ordinary mmap may merge adjacent allocations into a single VMA. */
	for (i = 0; i < ARRAY_SIZE(pages); i++) {
		if (!check_user_mem_vma(pages[i], len, "rw-p"))
			break;
		memset(pages[i], i + 1, len);
		if (!ASSERT_EQ(((unsigned char *)pages[i])[len - 1], i + 1,
			       "mapping_writable"))
			break;
	}

out:
	for (i = 0; i < ARRAY_SIZE(pages); i++)
		if (pages[i] != MAP_FAILED)
			munmap(pages[i], page_size * nr_pages);
}

static void test_reallocate_after_unmap(struct user_mem *skel)
{
	long page_size = sysconf(_SC_PAGESIZE);
	unsigned long addr = ~0UL;

	if (!alloc_user_mem(skel, page_size, PROT_READ | PROT_WRITE, &addr))
		goto out;

	if (!unmap_user_mem(skel, addr, page_size))
		goto out;
	if (!check_user_mem_unmapped((void *)addr))
		goto out;

	addr = ~0UL;
	alloc_user_mem(skel, page_size, PROT_READ | PROT_WRITE, &addr);

out:
	if (addr != ~0UL)
		munmap((void *)addr, page_size);
}

static void test_mapping_protections(struct user_mem *skel)
{
	long page_size = sysconf(_SC_PAGESIZE);
	unsigned long addr = ~0UL;
	int old_personality, set_personality;

	old_personality = personality(0xffffffffUL);
	if (!ASSERT_NEQ(old_personality, -1, "get_personality"))
		return;
	set_personality = old_personality & ~READ_IMPLIES_EXEC;
	if (!ASSERT_EQ(personality(set_personality), old_personality,
		       "set_personality"))
		return;

	if (!alloc_user_mem(skel, page_size, PROT_READ, &addr))
		goto out;

	if (check_user_mem_vma((void *)addr, page_size, "r--p"))
		ASSERT_EQ(*(volatile unsigned char *)addr, 0, "readonly_mapping_data");

	if (unmap_user_mem(skel, addr, page_size)) {
		if (check_user_mem_unmapped((void *)addr))
			addr = ~0UL;
	}

out:
	if (addr != ~0UL)
		munmap((void *)addr, page_size);
	ASSERT_EQ(personality(old_personality), set_personality,
		  "restore_personality");
}

static void test_zero_length_mapping(struct user_mem *skel)
{
	skel->bss->map_len = 0;
	skel->bss->map_prot = PROT_READ | PROT_WRITE;
	skel->bss->action = USER_PAGE_MMAP;
	user_mem_trigger();
	ASSERT_EQ(skel->bss->user_addr, (unsigned long)-EINVAL,
		  "zero_length_mapping");
}

static void test_execute_user_page(struct user_mem *skel)
{
	long page_size = sysconf(_SC_PAGESIZE);
	unsigned long addr = ~0UL;

#ifndef __x86_64__
	test__skip();
	return;
#endif

	if (!alloc_user_mem(skel, page_size, PROT_READ | PROT_EXEC, &addr))
		return;
	if (!check_user_mem_vma((void *)addr, page_size, "r-xp") ||
	    !write_user_mem(skel, addr))
		goto out;

	ASSERT_EQ(((int (*)(void))addr)(), 42, "execute_user_page");

out:
	if (addr != ~0UL)
		munmap((void *)addr, page_size);
}

static void test_partial_exec(struct user_mem *skel)
{
	long page_size = sysconf(_SC_PAGESIZE);
	unsigned long addr = ~0UL;

#ifndef __x86_64__
	test__skip();
	return;
#endif

	if (!alloc_user_mem(skel, page_size * 3, PROT_READ | PROT_WRITE, &addr))
		return;
	if (!write_user_mem(skel, addr + page_size) ||
	    !write_user_mem(skel, addr + 2 * page_size))
		goto out;

	if (!ASSERT_OK(mprotect((void *)(addr + page_size), page_size,
				PROT_READ | PROT_EXEC), "middle_page_mprotect") ||
	    !check_user_mem_vma((void *)addr, page_size, "rw-p") ||
	    !check_user_mem_vma((void *)(addr + page_size), page_size, "r-xp") ||
	    !check_user_mem_vma((void *)(addr + 2 * page_size), page_size, "rw-p"))
		goto out;

	if (!ASSERT_EQ(((int (*)(void))(addr + page_size))(), 42,
		       "execute_middle_page"))
		goto out;

	if (!ASSERT_OK(mprotect((void *)(addr + 2 * page_size), page_size,
				PROT_READ | PROT_EXEC), "last_page_mprotect") ||
	    !check_user_mem_vma((void *)(addr + 2 * page_size), page_size, "r-xp"))
		goto out;

	ASSERT_EQ(((int (*)(void))(addr + 2 * page_size))(), 42,
		  "execute_last_page");

out:
	if (addr != ~0UL)
		munmap((void *)addr, page_size * 3);
}

void test_user_mem(void)
{
	struct user_mem *skel;

	skel = user_mem__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	skel->bss->monitored_pid = getpid();
	if (!ASSERT_OK(user_mem__attach(skel), "attach"))
		goto out;

	if (test__start_subtest("allocations"))
		test_allocations(skel);
	if (test__start_subtest("reallocate_after_unmap"))
		test_reallocate_after_unmap(skel);
	if (test__start_subtest("mapping_protections"))
		test_mapping_protections(skel);
	if (test__start_subtest("zero_length_mapping"))
		test_zero_length_mapping(skel);
	if (test__start_subtest("execute_user_page"))
		test_execute_user_page(skel);
	if (test__start_subtest("partial_exec"))
		test_partial_exec(skel);

out:
	user_mem__destroy(skel);
}
