/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 Isovalent */
#ifndef __BPF_MPROG_H
#define __BPF_MPROG_H

#include <linux/bpf.h>

#define BPF_MPROG_MAX	64
#define BPF_MPROG_SWAP	1
#define BPF_MPROG_FREE	2

struct bpf_prog_item {
	struct bpf_prog *prog;
	u32 flags;
	u32 id;
};

struct bpf_mprog_entry {
	struct bpf_prog_item		items[BPF_MPROG_MAX] ____cacheline_aligned;
	struct bpf_mprog_entry_pair	*parent;
};

struct bpf_mprog_entry_pair {
	struct bpf_mprog_entry		a;
	struct bpf_mprog_entry		b;
	struct rcu_head			rcu;
	struct bpf_prog *		ref;
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

	BUILD_BUG_ON(sizeof(pair->a.items[0]) > 2 * sizeof(u64));
	pair = kzalloc(sizeof(*pair) + extra_size, GFP_KERNEL);
	if (pair) {
		atomic_set(&pair->revision, 1);
		pair->a.parent = pair;
		pair->b.parent = pair;
		return &pair->a;
	}
	return NULL;
}

static inline void bpf_mprog_free(struct bpf_mprog_entry *entry)
{
	kfree_rcu(entry->parent, rcu);
}

static inline void bpf_mprog_mark_ref(struct bpf_mprog_entry *entry,
				      struct bpf_prog *prog)
{
	WARN_ON_ONCE(entry->parent->ref);
	entry->parent->ref = prog;
}

static inline bool bpf_mprog_flags_ok(u32 flags, bool attach)
{
	if ((flags & BPF_F_REPLACE) && !attach)
		return false;
	if ((flags & BPF_F_REPLACE) && (flags & (BPF_F_BEFORE | BPF_F_AFTER)))
		return false;
	if ((flags & BPF_F_FIRST) && (flags & BPF_F_AFTER))
		return false;
	if ((flags & BPF_F_LAST) && (flags & BPF_F_BEFORE))
		return false;
	if ((flags & (BPF_F_BEFORE | BPF_F_AFTER)) == (BPF_F_BEFORE | BPF_F_AFTER))
		return false;
	if ((flags & (BPF_F_FIRST | BPF_F_LAST)) == (BPF_F_FIRST | BPF_F_LAST) &&
	    (flags & (BPF_F_BEFORE | BPF_F_AFTER)))
		return false;
	return true;
}

static inline bool bpf_mprog_rprog_ok(u32 flags, bool relative_prog)
{
	if (!relative_prog &&
	    (flags & (BPF_F_REPLACE | BPF_F_BEFORE | BPF_F_AFTER)))
		return false;
	if (relative_prog &&
	    !(flags & (BPF_F_REPLACE | BPF_F_BEFORE | BPF_F_AFTER)))
		return false;
	return true;
}

static inline u32 bpf_mprog_flags(u32 cur_flags, u32 req_flags, u32 flag)
{
	if (req_flags & flag)
		cur_flags |= flag;
	else
		cur_flags &= ~flag;
	return cur_flags;
}

static inline u32 bpf_mprog_max(void)
{
	return ARRAY_SIZE(((struct bpf_mprog_entry *)NULL)->items) - 1;
}

static inline struct bpf_prog *bpf_mprog_first(struct bpf_mprog_entry *entry)
{
	return READ_ONCE(entry->items[0].prog);
}

static inline struct bpf_prog *bpf_mprog_last(struct bpf_mprog_entry *entry)
{
	struct bpf_prog_item *item;
	struct bpf_prog *prog = NULL, *tmp;
	int i;

	for (i = 0; i < bpf_mprog_max(); i++) {
		item = &entry->items[i];
		tmp = READ_ONCE(item->prog);
		if (!tmp)
			break;
		prog = tmp;
	}
	return prog;
}

static inline void bpf_mprog_commit(struct bpf_mprog_entry *entry)
{
	do {
		atomic_inc(&entry->parent->revision);
	} while (atomic_read(&entry->parent->revision) == 0);
	synchronize_rcu();
	if (entry->parent->ref) {
		bpf_prog_put(entry->parent->ref);
		entry->parent->ref = NULL;
	}
}

static inline void bpf_mprog_entry_clear(struct bpf_mprog_entry *entry)
{
	memset(entry->items, 0, sizeof(entry->items));
}

static inline u64 bpf_mprog_revision(struct bpf_mprog_entry *entry)
{
	return atomic_read(&entry->parent->revision);
}

static inline void bpf_mprog_write(struct bpf_prog_item *item,
				   struct bpf_prog *prog, u32 flags, u32 id)
{
	WRITE_ONCE(item->prog, prog);
	item->flags = flags;
	item->id = id;
}

static inline u32 bpf_mprog_total(struct bpf_mprog_entry *entry)
{
	const struct bpf_prog_item *item;
	const struct bpf_prog *prog;
	u32 num = 0;

	item = &entry->items[0];
	while ((prog = READ_ONCE(item->prog))) {
		num++;
		item++;
	}
	return num;
}

static inline struct bpf_prog *
bpf_mprog_relative_prog(u32 relobj, u32 flags, enum bpf_prog_type type)
{
	struct bpf_prog *tmp;

	if (flags & BPF_F_ID) {
		tmp = bpf_prog_by_id(relobj);
	} else {
		if (!relobj)
			return NULL;
		tmp = bpf_prog_get(relobj);
	}
	if (IS_ERR(tmp))
		return ERR_CAST(tmp);
	if (tmp->type != type) {
		bpf_prog_put(tmp);
		return ERR_PTR(-EINVAL);
	}
	return tmp;
}

int bpf_mprog_attach(struct bpf_mprog_entry *entry, struct bpf_prog *nprog,
		     u32 nid, u32 expected_revision, u32 aflags, u32 relobj);
int bpf_mprog_detach(struct bpf_mprog_entry *entry, struct bpf_prog *dprog,
		     u32 did, u32 expected_revision, u32 dflags, u32 relobj);

int bpf_mprog_query(const union bpf_attr *attr, union bpf_attr __user *uattr,
		    struct bpf_mprog_entry *entry);

#endif /* __BPF_MPROG_H */
