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
	ret = bpf_mprog_attach(entry, nprog, attr->expected_revision,
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
	ret = bpf_mprog_detach(entry, dprog, attr->expected_revision,
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
