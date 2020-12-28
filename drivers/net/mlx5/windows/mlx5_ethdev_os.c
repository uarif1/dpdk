/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */
#include <stdio.h>

#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_ethdev_driver.h>
#include <rte_interrupts.h>

#include <mlx5_glue.h>
#include <mlx5_devx_cmds.h>
#include <mlx5_common.h>
#include <mlx5_win_ext.h>
#include <mlx5_malloc.h>
#include <mlx5.h>

/**
 * Get MAC address by querying netdevice.
 *
 * @param[in] dev
 *   Pointer to Ethernet device.
 * @param[out] mac
 *   MAC address output buffer.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_get_mac(struct rte_eth_dev *dev, uint8_t (*mac)[RTE_ETHER_ADDR_LEN])
{
	struct mlx5_priv *priv;
	mlx5_context_st *context_obj;

	if (!dev) {
		rte_errno = EINVAL;
		return -rte_errno;
	}
	priv = dev->data->dev_private;
	context_obj = (mlx5_context_st *)priv->sh->ctx;
	memcpy(mac, context_obj->mlx5_dev.eth_mac, RTE_ETHER_ADDR_LEN);
	return 0;
}

/**
 * Set device MTU.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param mtu
 *   MTU value to set.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_set_mtu(struct rte_eth_dev *dev, uint16_t mtu)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(mtu);
	return -ENOTSUP;
}

/*
 * Unregister callback handler safely. The handler may be active
 * while we are trying to unregister it, in this case code -EAGAIN
 * is returned by rte_intr_callback_unregister(). This routine checks
 * the return code and tries to unregister handler again.
 *
 * @param handle
 *   interrupt handle
 * @param cb_fn
 *   pointer to callback routine
 * @cb_arg
 *   opaque callback parameter
 */
void
mlx5_intr_callback_unregister(const struct rte_intr_handle *handle,
			      rte_intr_callback_fn cb_fn, void *cb_arg)
{
	RTE_SET_USED(handle);
	RTE_SET_USED(cb_fn);
	RTE_SET_USED(cb_arg);
}

/**
 * DPDK callback to get flow control status.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param[out] fc_conf
 *   Flow control output buffer.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_dev_get_flow_ctrl(struct rte_eth_dev *dev, struct rte_eth_fc_conf *fc_conf)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(fc_conf);
	return -ENOTSUP;
}

/**
 * DPDK callback to modify flow control parameters.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param[in] fc_conf
 *   Flow control parameters.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_dev_set_flow_ctrl(struct rte_eth_dev *dev, struct rte_eth_fc_conf *fc_conf)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(fc_conf);
	return -ENOTSUP;
}

/**
 * Query the number of statistics provided by ETHTOOL.
 *
 * @param dev
 *   Pointer to Ethernet device.
 *
 * @return
 *   Number of statistics on success, negative errno value otherwise and
 *   rte_errno is set.
 */
int
mlx5_os_get_stats_n(struct rte_eth_dev *dev)
{
	RTE_SET_USED(dev);
	return -ENOTSUP;
}

/**
 * Init the structures to read device counters.
 *
 * @param dev
 *   Pointer to Ethernet device.
 */
void
mlx5_os_stats_init(struct rte_eth_dev *dev)
{
	RTE_SET_USED(dev);
}

/**
 * Read device counters table.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param[out] stats
 *   Counters table output buffer.
 *
 * @return
 *   0 on success and stats is filled, negative errno value otherwise and
 *   rte_errno is set.
 */
int
mlx5_os_read_dev_counters(struct rte_eth_dev *dev, uint64_t *stats)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(stats);
	return -ENOTSUP;
}

/**
 * DPDK callback to bring the link DOWN.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise
 */
int
mlx5_set_link_down(struct rte_eth_dev *dev)
{
	RTE_SET_USED(dev);
	return -ENOTSUP;
}

/**
 * DPDK callback to bring the link UP.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise
 */
int
mlx5_set_link_up(struct rte_eth_dev *dev)
{
	RTE_SET_USED(dev);
	return -ENOTSUP;
}

/**
 * DPDK callback to retrieve plug-in module EEPROM information (type and size).
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param[out] modinfo
 *   Storage for plug-in module EEPROM information.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_get_module_info(struct rte_eth_dev *dev,
		     struct rte_eth_dev_module_info *modinfo)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(modinfo);
	return -ENOTSUP;
}

/**
 * DPDK callback to retrieve plug-in module EEPROM data.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param[out] info
 *   Storage for plug-in module EEPROM data.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int mlx5_get_module_eeprom(struct rte_eth_dev *dev,
			   struct rte_dev_eeprom_info *info)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(info);
	return -ENOTSUP;
}
