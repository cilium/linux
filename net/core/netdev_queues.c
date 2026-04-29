// SPDX-License-Identifier: GPL-2.0-or-later

#include <net/netdev_lock.h>
#include <net/netdev_queues.h>
#include <net/netdev_rx_queue.h>
#include <net/xdp_sock_drv.h>

#include "dev.h"

void netdev_tx_queue_lease(struct netdev_queue *txq_dst,
			   struct netdev_queue *txq_src)
{
	netdev_assert_locked(txq_src->dev);
	netdev_assert_locked(txq_dst->dev);

	netdev_hold(txq_src->dev, &txq_src->lease_tracker, GFP_KERNEL);

	WRITE_ONCE(txq_src->lease, txq_dst);
	WRITE_ONCE(txq_dst->lease, txq_src);
}

void netdev_tx_queue_unlease(struct netdev_queue *txq_dst,
			     struct netdev_queue *txq_src)
{
	netdev_assert_locked(txq_dst->dev);
	netdev_assert_locked(txq_src->dev);

	WRITE_ONCE(txq_src->lease, NULL);
	WRITE_ONCE(txq_dst->lease, NULL);

	netdev_put(txq_src->dev, &txq_src->lease_tracker);
}

bool netif_txq_is_leased(struct net_device *dev, unsigned int txq_idx)
{
	if (txq_idx < dev->real_num_tx_queues)
		return READ_ONCE(netdev_get_tx_queue(dev, txq_idx)->lease);
	return false;
}

/* Find a NETMEM_TX_DMA-capable device for @dev. If @dev itself does
 * DMA-backed netmem TX (NETMEM_TX_DMA), return @dev with *@txq_idx
 * set to 0. Otherwise — when @dev is a NETMEM_TX_NO_DMA pass-through
 * (e.g. netkit) — walk @dev's TX queue leases and return the first
 * phys NIC with NETMEM_TX_DMA, with *@txq_idx set to the local
 * leased TX queue index that points at it. The caller passes
 * *@txq_idx to netdev_queue_get_dma_dev() to obtain the phys
 * dma_dev (using the existing lease-walk in there).
 *
 * Caller must hold @dev's netdev lock.
 */
struct net_device *netdev_find_netmem_tx_dev(struct net_device *dev,
					     unsigned int *txq_idx)
{
	struct net_device *phys;
	struct netdev_queue *txq;
	int i;

	netdev_ops_assert_locked(dev);

	if (dev->netmem_tx == NETMEM_TX_DMA) {
		*txq_idx = 0;
		return dev;
	}
	if (dev->netmem_tx != NETMEM_TX_NO_DMA)
		return NULL;
	for (i = 0; i < dev->real_num_tx_queues; i++) {
		txq = READ_ONCE(netdev_get_tx_queue(dev, i)->lease);
		if (!txq)
			continue;
		phys = txq->dev;
		if (netif_device_present(phys) &&
		    phys->netmem_tx == NETMEM_TX_DMA) {
			*txq_idx = i;
			return phys;
		}
	}
	return NULL;
}

static struct device *
__netdev_queue_get_dma_dev(struct net_device *dev, unsigned int idx)
{
	const struct netdev_queue_mgmt_ops *queue_ops = dev->queue_mgmt_ops;
	struct device *dma_dev;

	if (queue_ops && queue_ops->ndo_queue_get_dma_dev)
		dma_dev = queue_ops->ndo_queue_get_dma_dev(dev, idx);
	else
		dma_dev = dev->dev.parent;

	return dma_dev && dma_dev->dma_mask ? dma_dev : NULL;
}

/**
 * netdev_queue_get_dma_dev() - get dma device for zero-copy operations
 * @dev:	net_device
 * @idx:	queue index
 * @type:	queue type (RX or TX)
 *
 * Get dma device for zero-copy operations to be used for this queue. If
 * the queue is an RX queue leased from a physical queue, we retrieve the
 * physical queue's dma device. When the dma device is not available or
 * valid, the function will return NULL.
 *
 * Return: Device or NULL on error
 */
struct device *netdev_queue_get_dma_dev(struct net_device *dev,
					unsigned int idx,
					enum netdev_queue_type type)
{
	struct netdev_rx_queue *hw_rxq;
	struct netdev_queue *hw_txq;
	struct device *dma_dev;

	netdev_ops_assert_locked(dev);

	switch (type) {
	case NETDEV_QUEUE_TYPE_RX:
		if (!netif_rxq_is_leased(dev, idx))
			return __netdev_queue_get_dma_dev(dev, idx);
		if (!netif_is_queue_leasee(dev))
			return NULL;

		hw_rxq = __netif_get_rx_queue(dev, idx)->lease;

		netdev_lock(hw_rxq->dev);
		idx = get_netdev_rx_queue_index(hw_rxq);
		dma_dev = __netdev_queue_get_dma_dev(hw_rxq->dev, idx);
		netdev_unlock(hw_rxq->dev);
		return dma_dev;
	case NETDEV_QUEUE_TYPE_TX:
		if (!netif_txq_is_leased(dev, idx))
			return __netdev_queue_get_dma_dev(dev, idx);
		if (!netif_is_queue_leasee(dev))
			return NULL;

		hw_txq = netdev_get_tx_queue(dev, idx)->lease;

		netdev_lock(hw_txq->dev);
		idx = hw_txq - hw_txq->dev->_tx;
		dma_dev = __netdev_queue_get_dma_dev(hw_txq->dev, idx);
		netdev_unlock(hw_txq->dev);
		return dma_dev;
	}
	return NULL;
}

bool netdev_can_create_queue(const struct net_device *dev,
			     struct netlink_ext_ack *extack)
{
	if (dev->dev.parent) {
		NL_SET_ERR_MSG(extack, "Device is not a virtual device");
		return false;
	}
	if (!dev->queue_mgmt_ops ||
	    !dev->queue_mgmt_ops->ndo_queue_create) {
		NL_SET_ERR_MSG(extack, "Device does not support queue creation");
		return false;
	}
	if (dev->real_num_rx_queues < 1 ||
	    dev->real_num_tx_queues < 1) {
		NL_SET_ERR_MSG(extack, "Device must have at least one real queue");
		return false;
	}
	return true;
}

bool netdev_can_lease_queue(const struct net_device *dev,
			    struct netlink_ext_ack *extack)
{
	if (!dev->dev.parent) {
		NL_SET_ERR_MSG(extack, "Lease device is a virtual device");
		return false;
	}
	if (!netif_device_present(dev)) {
		NL_SET_ERR_MSG(extack, "Lease device has been removed from the system");
		return false;
	}
	if (!dev->queue_mgmt_ops) {
		NL_SET_ERR_MSG(extack, "Lease device does not support queue management operations");
		return false;
	}
	return true;
}

bool netdev_queue_busy(struct net_device *dev, unsigned int idx,
		       enum netdev_queue_type type,
		       struct netlink_ext_ack *extack)
{
	if (xsk_get_pool_from_qid(dev, idx)) {
		NL_SET_ERR_MSG(extack, "Device queue in use by AF_XDP");
		return true;
	}
	if (type == NETDEV_QUEUE_TYPE_TX) {
		if (netif_txq_is_leased(dev, idx)) {
			NL_SET_ERR_MSG(extack,
				       "Device queue in use due to queue leasing");
			return true;
		}
		return false;
	}
	if (netif_rxq_is_leased(dev, idx)) {
		NL_SET_ERR_MSG(extack, "Device queue in use due to queue leasing");
		return true;
	}
	if (netif_rxq_has_mp(dev, idx)) {
		NL_SET_ERR_MSG(extack, "Device queue in use by memory provider");
		return true;
	}
	return false;
}
