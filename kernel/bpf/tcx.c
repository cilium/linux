// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2023 Isovalent */

#include <linux/bpf.h>
#include <linux/bpf_mprog.h>
#include <linux/netdevice.h>

#include <net/tcx.h>

int tcx_prog_attach(const union bpf_attr *attr, struct bpf_prog *nprog)
{
	bool created, ingress = attr->attach_type == BPF_TCX_INGRESS;
	struct net *net = current->nsproxy->net_ns;
	struct bpf_mprog_entry *entry;
	struct net_device *dev;
	int ret;

	rtnl_lock();
	dev = __dev_get_by_index(net, attr->target_ifindex);
	if (!dev) {
		ret = -ENODEV;
		goto out;
	}
	entry = dev_tcx_entry_fetch_or_create(dev, ingress, &created);
	if (!entry) {
		ret = -ENOMEM;
		goto out;
	}
	ret = bpf_mprog_attach(entry, nprog, 0, attr->expected_revision,
			       attr->attach_flags, attr->relative_fd);
	if (ret >= 0) {
		if (ret == BPF_MPROG_SWAP)
			tcx_entry_update(dev, bpf_mprog_peer(entry), ingress);
		bpf_mprog_commit(entry);
		tcx_skeys_inc(ingress);
		ret = 0;
	} else if (created) {
		bpf_mprog_free(entry);
	}
out:
	rtnl_unlock();
	return ret;
}

int tcx_prog_detach(const union bpf_attr *attr, struct bpf_prog *dprog)
{
	bool tcx_release, ingress = attr->attach_type == BPF_TCX_INGRESS;
	struct net *net = current->nsproxy->net_ns;
	struct bpf_mprog_entry *entry, *peer;
	struct net_device *dev;
	int ret;

	rtnl_lock();
	dev = __dev_get_by_index(net, attr->target_ifindex);
	if (!dev) {
		ret = -ENODEV;
		goto out;
	}
	entry = dev_tcx_entry_fetch(dev, ingress);
	if (!entry) {
		ret = -ENOENT;
		goto out;
	}
	ret = bpf_mprog_detach(entry, dprog, 0, attr->expected_revision,
			       attr->attach_flags, attr->relative_fd);
	if (ret >= 0) {
		tcx_release = ret == BPF_MPROG_FREE && !tcx_entry(entry)->miniq;
		peer = tcx_release ? NULL : bpf_mprog_peer(entry);
		if (ret == BPF_MPROG_SWAP || ret == BPF_MPROG_FREE)
			tcx_entry_update(dev, peer, ingress);
		bpf_mprog_commit(entry);
		tcx_skeys_dec(ingress);
		if (tcx_release)
			bpf_mprog_free(entry);
		ret = 0;
	}
out:
	rtnl_unlock();
	return ret;
}

static void tcx_uninstall(struct net_device *dev, bool ingress)
{
	struct bpf_mprog_entry *entry;
	struct bpf_prog_item *item;
	struct bpf_prog *prog;

	entry = dev_tcx_entry_fetch(dev, ingress);
	if (!entry)
		return;
	tcx_entry_update(dev, NULL, ingress);
	bpf_mprog_commit(entry);
	item = &entry->items[0];
	while ((prog = READ_ONCE(item->prog))) {
		if (!item->id)
			bpf_prog_put(prog);
		tcx_skeys_dec(ingress);
		item++;
	}
	WARN_ON_ONCE(tcx_entry(entry)->miniq);
	bpf_mprog_free(entry);
}

void dev_tcx_uninstall(struct net_device *dev)
{
	ASSERT_RTNL();
	tcx_uninstall(dev, true);
	tcx_uninstall(dev, false);
}

int tcx_prog_query(const union bpf_attr *attr, union bpf_attr __user *uattr)
{
	bool ingress = attr->query.attach_type == BPF_TCX_INGRESS;
	struct net *net = current->nsproxy->net_ns;
	struct bpf_mprog_entry *entry;
	struct net_device *dev;
	int ret;

	rtnl_lock();
	dev = __dev_get_by_index(net, attr->query.target_ifindex);
	if (!dev) {
		ret = -ENODEV;
		goto out;
	}
	entry = dev_tcx_entry_fetch(dev, ingress);
	if (!entry) {
		ret = -ENOENT;
		goto out;
	}
	ret = bpf_mprog_query(attr, uattr, entry);
out:
	rtnl_unlock();
	return ret;
}

static int tcx_link_prog_attach(struct bpf_link *l, u32 id, u32 aflags,
				u32 expected_revision, u32 relobj)
{
	struct tcx_link *link = container_of(l, struct tcx_link, link);
	bool created, ingress = link->location == BPF_TCX_INGRESS;
	struct net_device *dev = link->dev;
	struct bpf_mprog_entry *entry;
	int ret;

	rtnl_lock();
	entry = dev_tcx_entry_fetch_or_create(dev, ingress, &created);
	if (!entry) {
		ret = -ENOMEM;
		goto out;
	}
	ret = bpf_mprog_attach(entry, l->prog, id, expected_revision,
			       aflags, relobj);
	if (ret >= 0) {
		if (ret == BPF_MPROG_SWAP)
			tcx_entry_update(dev, bpf_mprog_peer(entry), ingress);
		bpf_mprog_commit(entry);
		tcx_skeys_inc(ingress);
		ret = 0;
	} else if (created) {
		bpf_mprog_free(entry);
	}
out:
	rtnl_unlock();
	return ret;
}

static void tcx_link_release(struct bpf_link *l)
{
	struct tcx_link *link = container_of(l, struct tcx_link, link);
	bool tcx_release, ingress = link->location == BPF_TCX_INGRESS;
	struct bpf_mprog_entry *entry, *peer;
	struct net_device *dev = link->dev;
	int ret = 0;

	rtnl_lock();
	if (!dev)
		goto out;
	entry = dev_tcx_entry_fetch(dev, ingress);
	if (!entry) {
		ret = -ENOENT;
		goto out;
	}
	ret = bpf_mprog_detach(entry, l->prog, l->id, 0, link->flags, 0);
	if (ret >= 0) {
		tcx_release = ret == BPF_MPROG_FREE && !tcx_entry(entry)->miniq;
		peer = tcx_release ? NULL : bpf_mprog_peer(entry);
		if (ret == BPF_MPROG_SWAP || ret == BPF_MPROG_FREE)
			tcx_entry_update(dev, peer, ingress);
		bpf_mprog_commit(entry);
		tcx_skeys_dec(ingress);
		if (tcx_release)
			bpf_mprog_free(entry);
		link->dev = NULL;
		ret = 0;
	}
out:
	WARN_ON_ONCE(ret);
	rtnl_unlock();
}

static void tcx_link_dealloc(struct bpf_link *l)
{
	struct tcx_link *link = container_of(l, struct tcx_link, link);

	kfree(link);
}

static const struct bpf_link_ops tcx_link_lops = {
	.release	= tcx_link_release,
	.dealloc	= tcx_link_dealloc,
};

int tcx_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
	struct net *net = current->nsproxy->net_ns;
	struct bpf_link_primer link_primer;
	struct net_device *dev;
	struct tcx_link *link;
	int fd, err;

	dev = dev_get_by_index(net, attr->link_create.target_ifindex);
	if (!dev)
		return -EINVAL;
	link = kzalloc(sizeof(*link), GFP_USER);
	if (!link) {
		err = -ENOMEM;
		goto out_put;
	}

	bpf_link_init(&link->link, BPF_LINK_TYPE_TCX, &tcx_link_lops, prog);
	link->location = attr->link_create.attach_type;
	link->flags = attr->link_create.flags & (BPF_F_FIRST | BPF_F_LAST);
	link->dev = dev;

	err = bpf_link_prime(&link->link, &link_primer);
	if (err) {
		kfree(link);
		goto out_put;
	}
	err = tcx_link_prog_attach(&link->link, link_primer.id,
				   attr->link_create.flags,
				   attr->link_create.tcx.expected_revision,
				   attr->link_create.tcx.relative_fd);
	if (err) {
		link->dev = NULL;
		bpf_link_cleanup(&link_primer);
		goto out_put;
	}

	fd = bpf_link_settle(&link_primer);
	dev_put(dev);
	return fd;
out_put:
	dev_put(dev);
	return err;
}
