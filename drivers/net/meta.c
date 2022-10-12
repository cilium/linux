// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2022 Isovalent */

#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include <linux/etherdevice.h>
#include <linux/filter.h>
#include <linux/bpf.h>

#include <net/dst.h>

#define DRV_NAME	"meta"
#define DRV_VERSION	"1.0"

struct meta {
	struct net_device __rcu *peer;
	struct bpf_prog   __rcu *prog;
	u32 headroom;
	bool primary;
};

static void meta_scrub_minimum(struct sk_buff *skb)
{
	skb->skb_iif = 0;
	skb->ignore_df = 0;
	skb_dst_drop(skb);
	skb_ext_reset(skb);
	nf_reset_ct(skb);
	nf_reset_trace(skb);
	ipvs_reset(skb);
}

enum {
	META_OKAY	= TC_ACT_OK,
	META_DROP	= TC_ACT_SHOT,
	META_REDIRECT	= TC_ACT_REDIRECT,
};

static struct rtnl_link_ops meta_link_ops;

static void __meta_bpf_prog_change(struct net_device *dev,
				   struct bpf_prog *new_prog)
{
	struct meta *meta = netdev_priv(dev);
	struct bpf_prog *old_prog = rtnl_dereference(meta->prog);

	rcu_assign_pointer(meta->prog, new_prog);
	if (old_prog)
		bpf_prog_put(old_prog);
}

static int meta_bpf_prog_change(struct net_device *dev, u32 bpf_fd, bool attach)
{
	struct bpf_prog *new_prog = NULL;

	if (attach) {
		new_prog = bpf_prog_get_type(bpf_fd, BPF_PROG_TYPE_SCHED_CLS);
		if (IS_ERR(new_prog))
			return PTR_ERR(new_prog);
	}

	__meta_bpf_prog_change(dev, new_prog);

	return 0;
}

static netdev_tx_t meta_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct meta *meta = netdev_priv(dev);
	struct net_device *peer;
	struct bpf_prog *prog;

	rcu_read_lock();
	peer = rcu_dereference(meta->peer);
	if (unlikely(!peer || skb_orphan_frags(skb, GFP_ATOMIC)))
		goto drop;

	meta_scrub_minimum(skb);
	skb->dev = peer;

	prog = rcu_dereference(meta->prog);
	if (unlikely(!prog))
		goto drop;
	switch (bpf_prog_run(prog, skb)) {
	case META_OKAY:
		skb->protocol = eth_type_trans(skb, skb->dev);
		skb_postpull_rcsum(skb, eth_hdr(skb), ETH_HLEN);
		__netif_rx(skb);
		break;
	case META_REDIRECT:
		skb_do_redirect(skb);
		break;
	case META_DROP:
	default:
drop:
		kfree_skb(skb);
		break;
	}
	rcu_read_unlock();
	return NETDEV_TX_OK;
}

static int meta_open(struct net_device *dev)
{
	struct meta *meta = netdev_priv(dev);
	struct net_device *peer = rtnl_dereference(meta->peer);

	if (!peer)
		return -ENOTCONN;
	if (peer->flags & IFF_UP) {
		netif_carrier_on(dev);
		netif_carrier_on(peer);
	}
	return 0;
}

static int meta_close(struct net_device *dev)
{
	struct meta *meta = netdev_priv(dev);
	struct net_device *peer = rtnl_dereference(meta->peer);

	netif_carrier_off(dev);
	if (peer)
		netif_carrier_off(peer);
	return 0;
}

static int meta_get_iflink(const struct net_device *dev)
{
	struct meta *meta = netdev_priv(dev);
	struct net_device *peer;
	int iflink = 0;

	rcu_read_lock();
	peer = rcu_dereference(meta->peer);
	if (peer)
		iflink = peer->ifindex;
	rcu_read_unlock();
	return iflink;
}

static void meta_set_multicast_list(struct net_device *dev)
{
}

static void meta_set_headroom(struct net_device *dev, int headroom)
{
	struct meta *meta = netdev_priv(dev), *meta2;
	struct net_device *peer;

	if (headroom < 0)
		headroom = NET_SKB_PAD;

	rcu_read_lock();
	peer = rcu_dereference(meta->peer);
	if (unlikely(!peer))
		goto out;

	meta2 = netdev_priv(peer);
	meta->headroom = headroom;
	headroom = max(meta->headroom, meta2->headroom);

	peer->needed_headroom = headroom;
	dev->needed_headroom = headroom;
out:
	rcu_read_unlock();
}

static struct net_device *meta_peer_dev(struct net_device *dev)
{
	struct meta *meta = netdev_priv(dev);

	return rcu_dereference(meta->peer);
}

static const struct net_device_ops meta_netdev_ops = {
	.ndo_open		= meta_open,
	.ndo_stop		= meta_close,
	.ndo_start_xmit		= meta_xmit,
	.ndo_set_rx_mode	= meta_set_multicast_list,
	.ndo_set_rx_headroom	= meta_set_headroom,
	.ndo_get_iflink		= meta_get_iflink,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_features_check	= passthru_features_check,
	.ndo_get_peer_dev	= meta_peer_dev,
};

static void meta_get_drvinfo(struct net_device *dev,
			     struct ethtool_drvinfo *info)
{
	strlcpy(info->driver, DRV_NAME, sizeof(info->driver));
	strlcpy(info->version, DRV_VERSION, sizeof(info->version));
}

static const struct ethtool_ops meta_ethtool_ops = {
	.get_drvinfo		= meta_get_drvinfo,
};

static void meta_setup(struct net_device *dev)
{
	static const netdev_features_t meta_features_hw_vlan =
		NETIF_F_HW_VLAN_CTAG_TX |
		NETIF_F_HW_VLAN_CTAG_RX |
		NETIF_F_HW_VLAN_STAG_TX |
		NETIF_F_HW_VLAN_STAG_RX;
	static const netdev_features_t meta_features =
		meta_features_hw_vlan |
		NETIF_F_SG |
		NETIF_F_FRAGLIST |
		NETIF_F_HW_CSUM |
		NETIF_F_RXCSUM |
		NETIF_F_SCTP_CRC |
		NETIF_F_HIGHDMA |
		NETIF_F_GSO_SOFTWARE |
		NETIF_F_GSO_ENCAP_ALL;

	ether_setup(dev);
	dev->min_mtu = ETH_MIN_MTU;
	dev->max_mtu = ETH_MAX_MTU;

	dev->flags |= IFF_NOARP;
	dev->priv_flags &= ~IFF_TX_SKB_SHARING;
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE;
	dev->priv_flags |= IFF_PHONY_HEADROOM;
	dev->priv_flags |= IFF_NO_QUEUE;

	dev->ethtool_ops = &meta_ethtool_ops;
	dev->netdev_ops  = &meta_netdev_ops;

	dev->features |= meta_features | NETIF_F_LLTX;
	dev->hw_features = meta_features;
	dev->hw_enc_features = meta_features;
	dev->mpls_features = NETIF_F_HW_CSUM | NETIF_F_GSO_SOFTWARE;
	dev->vlan_features = dev->features & ~meta_features_hw_vlan;

	dev->needs_free_netdev = true;

	netif_set_tso_max_size(dev, GSO_MAX_SIZE);
}

static struct net *meta_get_link_net(const struct net_device *dev)
{
	struct meta *meta = netdev_priv(dev);
	struct net_device *peer = rtnl_dereference(meta->peer);

	return peer ? dev_net(peer) : dev_net(dev);
}

static int meta_validate(struct nlattr *tb[], struct nlattr *data[],
			 struct netlink_ext_ack *extack)
{
	if (tb[IFLA_ADDRESS]) {
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN)
			return -EINVAL;
		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS])))
			return -EADDRNOTAVAIL;
	}

	return 0;
}

static int meta_new_link(struct net *src_net, struct net_device *dev,
			 struct nlattr *tb[], struct nlattr *data[],
			 struct netlink_ext_ack *extack)
{
	struct nlattr *peer_tb[IFLA_MAX + 1], **tbp = tb;
	unsigned char name_assign_type;
	struct ifinfomsg *ifmp = NULL;
	struct net_device *peer;
	char ifname[IFNAMSIZ];
	struct meta *meta;
	struct net *net;
	int err;

	if (data && data[IFLA_META_PEER_INFO]) {
		struct nlattr *nla_peer;

		nla_peer = data[IFLA_META_PEER_INFO];
		ifmp = nla_data(nla_peer);
		err = rtnl_nla_parse_ifla(peer_tb,
					  nla_data(nla_peer) + sizeof(struct ifinfomsg),
					  nla_len(nla_peer) - sizeof(struct ifinfomsg),
					  NULL);
		if (err < 0)
			return err;

		err = meta_validate(peer_tb, NULL, extack);
		if (err < 0)
			return err;

		tbp = peer_tb;
	}

	if (ifmp && tbp[IFLA_IFNAME]) {
		nla_strscpy(ifname, tbp[IFLA_IFNAME], IFNAMSIZ);
		name_assign_type = NET_NAME_USER;
	} else {
		snprintf(ifname, IFNAMSIZ, DRV_NAME "%%d");
		name_assign_type = NET_NAME_ENUM;
	}

	net = rtnl_link_get_net(src_net, tbp);
	if (IS_ERR(net))
		return PTR_ERR(net);

	peer = rtnl_create_link(net, ifname, name_assign_type,
				&meta_link_ops, tbp, extack);
	if (IS_ERR(peer)) {
		put_net(net);
		return PTR_ERR(peer);
	}

	if (!ifmp || !tbp[IFLA_ADDRESS])
		eth_hw_addr_random(peer);

	if (ifmp && dev->ifindex)
		peer->ifindex = ifmp->ifi_index;

	netif_inherit_tso_max(peer, dev);

	err = register_netdevice(peer);
	put_net(net);
	net = NULL;
	if (err < 0)
		goto err_register_peer;

	netif_carrier_off(peer);

	err = rtnl_configure_link(peer, ifmp);
	if (err < 0)
		goto err_configure_peer;

	if (!tb[IFLA_ADDRESS])
		eth_hw_addr_random(dev);

	if (tb[IFLA_IFNAME])
		nla_strscpy(dev->name, tb[IFLA_IFNAME], IFNAMSIZ);
	else
		snprintf(dev->name, IFNAMSIZ, DRV_NAME "%%d");

	err = register_netdevice(dev);
	if (err < 0)
		goto err_register_dev;

	netif_carrier_off(dev);

	if (data) {
		u32 bpf_fd;

		if (data[IFLA_META_BPF_FD]) {
			bpf_fd = nla_get_u32(data[IFLA_META_BPF_FD]);
			err = meta_bpf_prog_change(dev, bpf_fd, true);
			if (err)
				goto err_bpf_attach;
		}

		if (data[IFLA_META_PEER_BPF_FD]) {
			bpf_fd = nla_get_u32(data[IFLA_META_PEER_BPF_FD]);
			err = meta_bpf_prog_change(peer, bpf_fd, true);
			if (err)
				goto err_bpf_attach;
		}
	}

	meta = netdev_priv(dev);
	meta->primary = true;
	rcu_assign_pointer(meta->peer, peer);

	meta = netdev_priv(peer);
	rcu_assign_pointer(meta->peer, dev);
	return 0;

err_bpf_attach:
	/* detach both bpf programs */
	meta_bpf_prog_change(dev, 0, false);
	meta_bpf_prog_change(peer, 0, false);
err_register_dev:
	/* nothing to do */
err_configure_peer:
	unregister_netdevice(peer);
	return err;

err_register_peer:
	free_netdev(peer);
	return err;
}

static void meta_del_link(struct net_device *dev, struct list_head *head)
{
	struct meta *meta = netdev_priv(dev);
	struct net_device *peer = rtnl_dereference(meta->peer);

	meta_bpf_prog_change(dev, 0, false);
	RCU_INIT_POINTER(meta->peer, NULL);
	unregister_netdevice_queue(dev, head);
	if (peer) {
		meta = netdev_priv(peer);
		meta_bpf_prog_change(peer, 0, false);
		RCU_INIT_POINTER(meta->peer, NULL);
		unregister_netdevice_queue(peer, head);
	}
}

static int meta_change_link(struct net_device *dev, struct nlattr *tb[],
			    struct nlattr *data[],
			    struct netlink_ext_ack *extack)
{
	struct meta *meta = netdev_priv(dev);
	struct net_device *peer = rtnl_dereference(meta->peer);
	u32 bpf_fd;
	int err;

	if (!meta->primary) {
		NL_SET_ERR_MSG(extack,
			       "Meta settings can be changed only through the primary device");
		return -EACCES;
	}

	if (data[IFLA_META_BPF_FD]) {
		bpf_fd = nla_get_u32(data[IFLA_META_BPF_FD]);
		err = meta_bpf_prog_change(dev, bpf_fd, true);
		if (err) {
			NL_SET_ERR_MSG(extack,
				       "Could not attach meta device bpf program");
			return err;
		}
	}

	if (data[IFLA_META_PEER_BPF_FD]) {
		bpf_fd = nla_get_u32(data[IFLA_META_PEER_BPF_FD]);
		err = meta_bpf_prog_change(peer, bpf_fd, true);
		if (err) {
			NL_SET_ERR_MSG(extack,
				       "Could not attach meta peer device bpf program");
			return err;
		}
	}

	return 0;
}

static size_t meta_get_size(const struct net_device *dev)
{
	return nla_total_size(sizeof(u32)) + /* IFLA_META_BPF_FD */
	       nla_total_size(sizeof(u32)) + /* IFLA_META_PEER_BPF_FD */
	       nla_total_size(sizeof(u8))  + /* IFLA_META_PRIMARY */
	       0;
}

static int meta_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	struct meta *meta = netdev_priv(dev);
	struct net_device *peer = rtnl_dereference(meta->peer);
	struct meta *peer_meta;
	struct bpf_prog *prog;

	if (nla_put_u8(skb, IFLA_META_PRIMARY, meta->primary))
		return -EMSGSIZE;

	prog = rtnl_dereference(meta->prog);
	if (prog && nla_put_u32(skb, IFLA_META_BPF_FD, prog->aux->id))
		return -EMSGSIZE;

	if (peer) {
		peer_meta = netdev_priv(peer);
		prog = rtnl_dereference(peer_meta->prog);
		if (prog &&
		    nla_put_u32(skb, IFLA_META_PEER_BPF_FD, prog->aux->id))
			return -EMSGSIZE;
	}

	return 0;
}

static const struct nla_policy meta_policy[IFLA_META_MAX + 1] = {
	[IFLA_META_PEER_INFO]	= { .len = sizeof(struct ifinfomsg) },
	[IFLA_META_BPF_FD]	= { .type = NLA_U32 },
	[IFLA_META_PEER_BPF_FD]	= { .type = NLA_U32 },
	[IFLA_META_PRIMARY]	= { .type = NLA_REJECT,
				    .reject_message = "Primary attribute is read-only" },
};

static struct rtnl_link_ops meta_link_ops = {
	.kind		= DRV_NAME,
	.priv_size	= sizeof(struct meta),
	.setup		= meta_setup,
	.newlink	= meta_new_link,
	.dellink	= meta_del_link,
	.changelink	= meta_change_link,
	.get_link_net	= meta_get_link_net,
	.get_size	= meta_get_size,
	.fill_info	= meta_fill_info,
	.policy		= meta_policy,
	.validate	= meta_validate,
	.maxtype	= IFLA_META_MAX,
};

static __init int meta_init(void)
{
	return rtnl_link_register(&meta_link_ops);
}

static __exit void meta_exit(void)
{
	rtnl_link_unregister(&meta_link_ops);
}

module_init(meta_init);
module_exit(meta_exit);

MODULE_DESCRIPTION("BPF-programmable meta device");
MODULE_AUTHOR("Daniel Borkmann <daniel@iogearbox.net>");
MODULE_AUTHOR("Nikolay Aleksandrov <razor@blackwall.org>");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS_RTNL_LINK(DRV_NAME);
