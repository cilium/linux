// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2022 Isovalent */

#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/netdevice.h>

#include <net/sch_xgress.h>

#ifdef CONFIG_NET_CLS_ACT
static const struct bpf_prog sch_prog_ingress = {
	.bpf_func = sch_cls_ingress,
};
static const struct bpf_prog sch_prog_egress = {
	.bpf_func = sch_cls_egress,
};
#endif

static bool sch_prog_refcounted(const struct bpf_prog *prog)
{
#ifdef CONFIG_NET_CLS_ACT
	return prog == &sch_prog_ingress ||
	       prog == &sch_prog_egress ? false : true;
#else
	return true;
#endif
}

static int __sch_prog_attach(struct net_device *dev, bool ingress, u32 limit,
			     struct bpf_prog *nprog, u32 prio, u32 flags)
{
	struct bpf_prog_array_item *item, *tmp;
	struct sch_entry *entry, *peer;
	struct bpf_prog *oprog;
	bool created;
	int i, j;

	entry = dev_sch_entry_fetch(dev, ingress, &created);
	if (!entry)
		return -ENOMEM;
	for (i = 0; i < limit; i++) {
		item = &entry->items[i];
		oprog = item->prog;
		if (!oprog)
			break;
		if (item->bpf_priority == prio) {
			if (flags & BPF_F_REPLACE) {
				/* Pairs with READ_ONCE() in sch_run_progs(). */
				WRITE_ONCE(item->prog, nprog);
				if (sch_prog_refcounted(oprog))
					bpf_prog_put(oprog);
				dev_sch_entry_prio_set(entry, prio, nprog);
				return prio;
			}
			return -EBUSY;
		}
	}
	if (dev_sch_entry_total(entry) >= limit)
		return -ENOSPC;
	prio = dev_sch_entry_prio_new(entry, prio, nprog);
	if (prio < 0) {
		if (created)
			dev_sch_entry_free(entry);
		return -ENOMEM;
	}
	peer = dev_sch_entry_peer(entry);
	dev_sch_entry_clear(peer);
	for (i = 0, j = 0; i < limit; i++, j++) {
		item = &entry->items[i];
		tmp = &peer->items[j];
		oprog = item->prog;
		if (!oprog) {
			if (i == j) {
				tmp->prog = nprog;
				tmp->bpf_priority = prio;
			}
			break;
		} else if (item->bpf_priority < prio) {
			tmp->prog = oprog;
			tmp->bpf_priority = item->bpf_priority;
		} else if (item->bpf_priority > prio) {
			if (i == j) {
				tmp->prog = nprog;
				tmp->bpf_priority = prio;
				tmp = &peer->items[++j];
			}
			tmp->prog = oprog;
			tmp->bpf_priority = item->bpf_priority;
		}
	}
	dev_sch_entry_update(dev, peer, ingress);
	if (ingress)
		net_inc_ingress_queue();
	else
		net_inc_egress_queue();
	return prio;
}

int sch_prog_attach(const union bpf_attr *attr, struct bpf_prog *nprog)
{
	struct net *net = current->nsproxy->net_ns;
	bool ingress = attr->attach_type == BPF_NET_INGRESS;
	struct net_device *dev;
	int ret;

	if ((attr->attach_flags & ~BPF_F_REPLACE) ||
	    attr->attach_priority >= SCH_PRIO_RESERVED)
		return -EINVAL;
	rtnl_lock();
	dev = __dev_get_by_index(net, attr->target_ifindex);
	if (!dev) {
		rtnl_unlock();
		return -EINVAL;
	}
	ret = __sch_prog_attach(dev, ingress, SCH_MAX_ENTRIES, nprog,
				attr->attach_priority, attr->attach_flags);
	rtnl_unlock();
	return ret;
}

int sch_prog_attach_kern(struct net_device *dev, bool ingress)
{
#ifdef CONFIG_NET_CLS_ACT
	struct bpf_prog *prog = ingress ?
		(struct bpf_prog *)&sch_prog_ingress :
		(struct bpf_prog *)&sch_prog_egress;

	ASSERT_RTNL();
	return __sch_prog_attach(dev, ingress, SCH_MAX_ENTRIES + 1, prog,
				 SCH_PRIO_RESERVED, BPF_F_REPLACE);
#else
	return -EOPNOTSUPP;
#endif
}
EXPORT_SYMBOL_GPL(sch_prog_attach_kern);

static int __sch_prog_detach(struct net_device *dev, bool ingress, u32 limit,
			     u32 prio)
{
	struct bpf_prog_array_item *item, *tmp;
	struct bpf_prog *oprog, *fprog = NULL;
	struct sch_entry *entry, *peer;
	int i, j;

	entry = ingress ?
		rcu_dereference_rtnl(dev->sch_ingress) :
		rcu_dereference_rtnl(dev->sch_egress);
	if (!entry)
		return -ENOENT;
	peer = dev_sch_entry_peer(entry);
	dev_sch_entry_clear(peer);
	for (i = 0, j = 0; i < limit; i++) {
		item = &entry->items[i];
		tmp = &peer->items[j];
		oprog = item->prog;
		if (!oprog)
			break;
		if (item->bpf_priority != prio) {
			tmp->prog = oprog;
			tmp->bpf_priority = item->bpf_priority;
			j++;
		} else {
			fprog = oprog;
		}
	}
	if (fprog) {
		dev_sch_entry_prio_del(peer, prio);
		if (dev_sch_entry_total(peer) == 0)
			peer = NULL;
		dev_sch_entry_update(dev, peer, ingress);
		if (sch_prog_refcounted(fprog))
			bpf_prog_put(fprog);
		if (!peer)
			dev_sch_entry_free(entry);
		if (ingress)
			net_dec_ingress_queue();
		else
			net_dec_egress_queue();
		return 0;
	}
	return -ENOENT;
}

int sch_prog_detach(const union bpf_attr *attr)
{
	struct net *net = current->nsproxy->net_ns;
	bool ingress = attr->attach_type == BPF_NET_INGRESS;
	struct net_device *dev;
	int ret;

	if (attr->attach_flags || !attr->attach_priority ||
	    attr->attach_priority >= SCH_PRIO_RESERVED)
		return -EINVAL;
	rtnl_lock();
	dev = __dev_get_by_index(net, attr->target_ifindex);
	if (!dev) {
		rtnl_unlock();
		return -EINVAL;
	}
	ret = __sch_prog_detach(dev, ingress, SCH_MAX_ENTRIES,
				attr->attach_priority);
	rtnl_unlock();
	return ret;
}

int sch_prog_detach_kern(struct net_device *dev, bool ingress)
{
#ifdef CONFIG_NET_CLS_ACT
	ASSERT_RTNL();
	return __sch_prog_detach(dev, ingress, SCH_MAX_ENTRIES + 1,
				 SCH_PRIO_RESERVED);
#else
	return -EOPNOTSUPP;
#endif
}
EXPORT_SYMBOL_GPL(sch_prog_detach_kern);

static void __sch_prog_detach_all(struct net_device *dev, bool ingress, u32 limit)
{
	struct bpf_prog_array_item *item;
	struct sch_entry *entry;
	struct bpf_prog *prog;
	int i;

	ASSERT_RTNL();

	entry = ingress ?
		rcu_dereference_rtnl(dev->sch_ingress) :
		rcu_dereference_rtnl(dev->sch_egress);
	if (!entry)
		return;
	dev_sch_entry_update(dev, NULL, ingress);
	for (i = 0; i < limit; i++) {
		item = &entry->items[i];
		prog = item->prog;
		if (!prog)
			break;
		dev_sch_entry_prio_del(entry, item->bpf_priority);
		if (sch_prog_refcounted(prog))
			bpf_prog_put(prog);
		if (ingress)
			net_dec_ingress_queue();
		else
			net_dec_egress_queue();
	}
	dev_sch_entry_free(entry);
}

void dev_sch_uninstall(struct net_device *dev)
{
	__sch_prog_detach_all(dev, true,  SCH_MAX_ENTRIES + 1);
	__sch_prog_detach_all(dev, false, SCH_MAX_ENTRIES + 1);
}

static int
__sch_prog_query(const union bpf_attr *attr, union bpf_attr __user *uattr,
		 struct net_device *dev, bool ingress, u32 limit)
{
	struct bpf_prog_array_item *item;
	struct sch_entry *entry;
	struct bpf_prog *prog;
	u32 i, flags = 0, cnt;
	int ret = 0;
	struct {
		u32 id;
		u32 prio;
	} __packed idp, __user *prog_ids = u64_to_user_ptr(attr->query.prog_ids);

	entry = ingress ?
		rcu_dereference_rtnl(dev->sch_ingress) :
		rcu_dereference_rtnl(dev->sch_egress);
	if (!entry)
		return -ENOENT;
	cnt = dev_sch_entry_total(entry);
	if (copy_to_user(&uattr->query.attach_flags, &flags, sizeof(flags)))
		return -EFAULT;
	if (copy_to_user(&uattr->query.prog_cnt, &cnt, sizeof(cnt)))
		return -EFAULT;
	if (attr->query.prog_cnt == 0 || !prog_ids || !cnt)
		/* return early if user requested only program count + flags */
		return 0;
	if (attr->query.prog_cnt < cnt) {
		cnt = attr->query.prog_cnt;
		ret = -ENOSPC;
	}
	for (i = 0; i < limit; i++) {
		item = &entry->items[i];
		prog = item->prog;
		if (!prog)
			break;
		idp.id = sch_prog_refcounted(prog) ? prog->aux->id : 0;
		idp.prio = item->bpf_priority;
		if (copy_to_user(prog_ids + i, &idp, sizeof(idp)))
			return -EFAULT;
		if (i + 1 == cnt)
			break;
	}
	return ret;
}

int sch_prog_query(const union bpf_attr *attr, union bpf_attr __user *uattr)
{
	struct net *net = current->nsproxy->net_ns;
	bool ingress = attr->query.attach_type == BPF_NET_INGRESS;
	struct net_device *dev;
	int ret;

	if (attr->query.query_flags || attr->query.attach_flags)
		return -EINVAL;
	rtnl_lock();
	dev = __dev_get_by_index(net, attr->query.target_ifindex);
	if (!dev) {
		rtnl_unlock();
		return -EINVAL;
	}
	ret = __sch_prog_query(attr, uattr, dev, ingress, SCH_MAX_ENTRIES);
	rtnl_unlock();
	return ret;
}
