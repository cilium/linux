/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 Isovalent */
#ifndef __BPF_MPROG_H
#define __BPF_MPROG_H

#include <linux/bpf.h>

#define BPF_MPROG_MAX	32

struct bpf_mprog_entry {
	struct bpf_prog_array_item	items[BPF_MPROG_MAX] ____cacheline_aligned;
	struct bpf_mprog_entry_pair	*parent;
};

struct bpf_mprog_entry_pair {
	struct rcu_head			rcu;
	struct bpf_mprog_entry		a;
	struct bpf_mprog_entry		b;
	atomic_t			revision;
};

static inline struct bpf_mprog_entry *
bpf_mprog_peer(const struct bpf_mprog_entry *entry)
{
	if (entry == &entry->parent->a)
		return &entry->parent->b;
	else
		return &entry->parent->a;
}

static inline struct bpf_mprog_entry *bpf_mprog_create(size_t extra_size)
{
	struct bpf_mprog_entry_pair *pair;

	pair = kzalloc(sizeof(*pair) + extra_size, GFP_KERNEL);
	if (pair) {
		atomic_set(&pair->revision, 1);
		pair->a.parent = pair;
		pair->b.parent = pair;
		return &pair->a;
	}
	return NULL;
}

static inline void bpf_mprog_commit(struct bpf_mprog_entry *entry)
{
	atomic_inc(&entry->parent.revision);
	synchronize_rcu();
}

static inline void bpf_mprog_entry_clear(struct bpf_mprog_entry *entry)
{
	memset(entry->items, 0, sizeof(entry->items));
}

static inline void bpf_mprog_free(struct bpf_mprog_entry *entry)
{
	kfree_rcu(entry->parent, rcu);
}

static inline u32 bpf_mprog_revision(struct bpf_mprog_entry *entry)
{
	return atomic_read(&entry->parent.revision);
}

static inline u32 bpf_mprog_total(struct bpf_mprog_entry *entry)
{
	const struct bpf_prog_array_item *item;
	const struct bpf_prog *prog;
	u32 num = 0;

	item = &entry->items[0];
	while ((prog = READ_ONCE(item->prog))) {
		num++;
		item++;
	}
	return num;
}

#endif /* __BPF_MPROG_H */
