// SPDX-License-Identifier: GPL-2.0
/*
 * Reaching the file behind a memory mapping from file_mprotect, which runs
 * under mmap_lock and cannot read a file for itself: a sleepable hook
 * measures the file at mmap time into inode local storage, and the atomic
 * one acquires the vma's file, looks the record up by its inode and puts the
 * reference again.
 */
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <test_progs.h>
#include "lsm_vma_file.skel.h"

#define BASE		"/tmp/test_progs_vma_file"
#define FILE		BASE "/file"
#define PAGE		4096
#define ROUNDS		64

/* A file holding one page, so that a page of it can be mapped. */
static int make_file(const char *path)
{
	char page[PAGE] = {};
	int fd, n;

	fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		return -errno;
	n = write(fd, page, sizeof(page));
	close(fd);
	return n == sizeof(page) ? 0 : -EIO;
}

static void reset(struct lsm_vma_file *skel)
{
	skel->bss->target_ino = 0;
	skel->bss->mmap_ino = 0;
	skel->bss->mprotect_ino = 0;
	skel->bss->mapped_seen = 0;
	skel->bss->anon_seen = 0;
	skel->bss->matched = 0;
	skel->bss->mprotects = 0;
	skel->bss->cow = false;
	skel->bss->enabled = false;
}

static void test_file_backed(struct lsm_vma_file *skel)
{
	struct stat st;
	__u64 val = 0;
	void *p;
	int fd;

	reset(skel);
	fd = open(FILE, O_RDONLY);
	if (!ASSERT_OK_FD(fd, "open"))
		return;
	if (!ASSERT_OK(fstat(fd, &st) ? -errno : 0, "fstat"))
		goto out;
	skel->bss->target_ino = st.st_ino;
	skel->bss->enabled = true;

	p = mmap(NULL, PAGE, PROT_READ, MAP_PRIVATE, fd, 0);
	if (!ASSERT_NEQ(p, MAP_FAILED, "mmap"))
		goto out;
	ASSERT_EQ(skel->bss->mapped_seen, 1, "mapped_seen");
	ASSERT_EQ(skel->bss->mmap_ino, st.st_ino, "inode recorded at mmap");

	ASSERT_OK(mprotect(p, PAGE, PROT_READ | PROT_WRITE) ? -errno : 0,
		  "mprotect");
	ASSERT_EQ(skel->bss->matched, 1, "matched");
	ASSERT_EQ(skel->bss->mprotect_ino, st.st_ino, "same inode at mprotect");
	ASSERT_EQ(skel->bss->anon_seen, 0, "anon_seen");
	/* Nothing was written through it, so it carries no anon_vma. */
	ASSERT_FALSE(skel->bss->cow, "clean mapping");
	/* The record the hook found is the one the map holds for the file. */
	ASSERT_OK(bpf_map_lookup_elem(bpf_map__fd(skel->maps.mapped), &fd, &val),
		  "look the storage up by the file");
	ASSERT_EQ(val, st.st_ino, "stored inode");
	munmap(p, PAGE);
out:
	skel->bss->enabled = false;
	close(fd);
}

static void test_anonymous(struct lsm_vma_file *skel)
{
	void *p;

	reset(skel);
	skel->bss->enabled = true;
	p = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (!ASSERT_NEQ(p, MAP_FAILED, "mmap")) {
		skel->bss->enabled = false;
		return;
	}
	ASSERT_EQ(skel->bss->mapped_seen, 0, "nothing measured");
	ASSERT_OK(mprotect(p, PAGE, PROT_READ) ? -errno : 0, "mprotect");
	ASSERT_EQ(skel->bss->anon_seen, 1, "anon_seen");
	ASSERT_EQ(skel->bss->matched, 0, "no file behind it");
	skel->bss->enabled = false;
	munmap(p, PAGE);
}

/* Every acquired reference is put again: the mapping is walked many times,
 * and afterwards the file goes away as it would without any policy.
 */
static void test_refcount_balanced(struct lsm_vma_file *skel)
{
	struct stat st;
	void *p;
	int fd, i;

	reset(skel);
	fd = open(FILE, O_RDONLY);
	if (!ASSERT_OK_FD(fd, "open"))
		return;
	if (!ASSERT_OK(fstat(fd, &st) ? -errno : 0, "fstat"))
		goto out;
	skel->bss->target_ino = st.st_ino;
	skel->bss->enabled = true;

	p = mmap(NULL, PAGE, PROT_READ, MAP_PRIVATE, fd, 0);
	if (!ASSERT_NEQ(p, MAP_FAILED, "mmap"))
		goto out;
	for (i = 0; i < ROUNDS; i++) {
		int prot = (i & 1) ? PROT_READ : (PROT_READ | PROT_WRITE);

		if (mprotect(p, PAGE, prot))
			break;
	}
	ASSERT_EQ(i, ROUNDS, "mprotect rounds");
	ASSERT_EQ(skel->bss->mprotects, ROUNDS, "hook ran for each round");
	ASSERT_EQ(skel->bss->matched, ROUNDS, "the same file each round");
	munmap(p, PAGE);
	skel->bss->enabled = false;
	close(fd);

	ASSERT_OK(remove(FILE), "unlink");
	ASSERT_EQ(open(FILE, O_RDONLY) < 0 ? -errno : 0, -ENOENT, "gone");
	ASSERT_OK(make_file(FILE), "create again");
	return;
out:
	skel->bss->enabled = false;
	close(fd);
}

static void cleanup(void)
{
	remove(FILE);
	remove(BASE);
}

void test_lsm_vma_file(void)
{
	struct lsm_vma_file *skel = NULL;

	cleanup();
	if (!ASSERT_OK(mkdir(BASE, 0755), "mkdir base") ||
	    !ASSERT_OK(make_file(FILE), "create file"))
		goto out;

	skel = lsm_vma_file__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open and load"))
		goto out;
	skel->bss->monitored_pid = getpid();
	if (!ASSERT_OK(lsm_vma_file__attach(skel), "attach"))
		goto out;

	if (test__start_subtest("file_backed"))
		test_file_backed(skel);
	if (test__start_subtest("anonymous"))
		test_anonymous(skel);
	if (test__start_subtest("refcount_balanced"))
		test_refcount_balanced(skel);
out:
	lsm_vma_file__destroy(skel);
	cleanup();
}
