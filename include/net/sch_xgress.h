/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2022 Isovalent */
#ifndef __NET_SCHED_XGRESS_H
#define __NET_SCHED_XGRESS_H

#include <linux/idr.h>
#include <linux/bpf.h>

#include <net/sch_generic.h>

#define SCH_MAX_ENTRIES 30
/* Adds 1 NULL entry. */
#define SCH_MAX	(SCH_MAX_ENTRIES + 1)

enum sch_entry_type {
	SCH_ENTRY_A,
	SCH_ENTRY_B,
};

struct sch_entry {
	struct bpf_prog_array_item items[SCH_MAX] ____cacheline_aligned;
	enum sch_entry_type        type;
};

struct mini_Qdisc;

struct sch_entry_pair {
	struct rcu_head		rcu;
	struct idr		idr;
	struct mini_Qdisc	*miniq;
	struct sch_entry	a;
	struct sch_entry	b;
};

struct bpf_tc_link {
	struct bpf_link link;
	struct net_device *dev;
	u32 priority;
	u32 location;
};

static inline void sch_set_ingress(struct sk_buff *skb, bool ingress)
{
#ifdef CONFIG_NET_XGRESS
	skb->tc_at_ingress = ingress;
#endif
}

#ifdef CONFIG_NET_XGRESS
static inline void
dev_sch_entry_update(struct net_device *dev, struct sch_entry *entry,
		     bool ingress)
{
	ASSERT_RTNL();
	if (ingress)
		rcu_assign_pointer(dev->sch_ingress, entry);
	else
		rcu_assign_pointer(dev->sch_egress, entry);
	synchronize_rcu();
}

static inline struct sch_entry_pair *dev_sch_entry_pair(struct sch_entry *entry)
{
	if (entry->type == SCH_ENTRY_A)
		return container_of(entry, struct sch_entry_pair, a);
	else
		return container_of(entry, struct sch_entry_pair, b);
}

static inline struct sch_entry *dev_sch_entry_peer(struct sch_entry *entry)
{
	if (entry->type == SCH_ENTRY_A)
		return &dev_sch_entry_pair(entry)->b;
	else
		return &dev_sch_entry_pair(entry)->a;
}

static inline struct sch_entry *dev_sch_entry_create(void)
{
	struct sch_entry_pair *pair = kzalloc(sizeof(*pair), GFP_KERNEL);

	if (pair) {
		pair->a.type = SCH_ENTRY_A;
		pair->b.type = SCH_ENTRY_B;
		idr_init(&pair->idr);
		return &pair->a;
	}
	return NULL;
}

static inline struct sch_entry *dev_sch_entry_fetch(struct net_device *dev,
						    bool ingress, bool *created)
{
	struct sch_entry *entry = ingress ?
		rcu_dereference_rtnl(dev->sch_ingress) :
		rcu_dereference_rtnl(dev->sch_egress);

	*created = false;
	if (!entry) {
		entry = dev_sch_entry_create();
		if (!entry)
			return NULL;
		*created = true;
	}
	return entry;
}

static inline void dev_sch_entry_clear(struct sch_entry *entry)
{
	memset(entry->items, 0, sizeof(entry->items));
}

static inline int dev_sch_entry_prio_new(struct sch_entry *entry, u32 prio,
					 struct bpf_prog *prog)
{
	struct sch_entry_pair *pair = dev_sch_entry_pair(entry);
	int ret;

	if (prio == 0)
		prio = 1;
	ret = idr_alloc_u32(&pair->idr, prog, &prio, U32_MAX, GFP_KERNEL);
	return ret < 0 ? ret : prio;
}

static inline void dev_sch_entry_prio_set(struct sch_entry *entry, u32 prio,
					  struct bpf_prog *prog)
{
	struct sch_entry_pair *pair = dev_sch_entry_pair(entry);

	idr_replace(&pair->idr, prog, prio);
}

static inline void dev_sch_entry_prio_del(struct sch_entry *entry, u32 prio)
{
	struct sch_entry_pair *pair = dev_sch_entry_pair(entry);

	idr_remove(&pair->idr, prio);
}

static inline void dev_sch_entry_free(struct sch_entry *entry)
{
	struct sch_entry_pair *pair = dev_sch_entry_pair(entry);

	idr_destroy(&pair->idr);
	kfree_rcu(pair, rcu);
}

static inline u32 dev_sch_entry_total(struct sch_entry *entry)
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

static inline int sch_action_code(int code)
{
	switch (code) {
	case TC_ACT_OK:
	case TC_ACT_SHOT:
	case TC_ACT_REDIRECT:
		return code;
	case TC_ACT_UNSPEC:
	default:
		return TC_ACT_UNSPEC;
	}
}

int sch_prog_attach(const union bpf_attr *attr, struct bpf_prog *prog);
int sch_prog_detach(const union bpf_attr *attr);
int sch_prog_query(const union bpf_attr *attr,
		   union bpf_attr __user *uattr);
void dev_sch_uninstall(struct net_device *dev);
int sch_link_attach(const union bpf_attr *attr, struct bpf_prog *prog);
#else
static inline int sch_prog_attach(const union bpf_attr *attr,
				  struct bpf_prog *prog)
{
	return -EINVAL;
}

static inline int sch_prog_detach(const union bpf_attr *attr)
{
	return -EINVAL;
}

static inline int sch_prog_query(const union bpf_attr *attr,
				 union bpf_attr __user *uattr)
{
	return -EINVAL;
}

static inline void dev_sch_uninstall(struct net_device *dev)
{
}

static inline int sch_link_attach(const union bpf_attr *attr,
				  struct bpf_prog *prog)
{
	return -EINVAL;
}
#endif /* CONFIG_NET_XGRESS */
#endif /* __NET_SCHED_XGRESS_H */
