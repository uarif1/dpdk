/* SPDX-License-Idenitifier: BSD-3-Clause
 * Copyright(c) 2018 Red Hat, Inc.
 * Copyright(c) 2019 Arrikto, Inc.
 * Copyright (C) 2022 Bytedance Inc.
 */

/*
 * @file
 * virtio-vhost-user PCI transport driver
 *
 * This vhost-user transport communicates with the vhost-user master process
 * over the virtio-vhost-user PCI device.
 *
 * Interrupts are used since this is the control path, not the data path.  This
 * way the vhost-user command processing doesn't interfere with packet
 * processing.  This is similar to the AF_UNIX transport's fdman thread that
 * processes socket I/O separately.
 *
 * This transport replaces the usual vhost-user file descriptor passing with a
 * PCI BAR that contains doorbell registers for callfd and logfd, and shared
 * memory for the memory table regions.
 *
 * VIRTIO device specification:
 * https://stefanha.github.io/virtio/vhost-user-slave.html#x1-2830007
 */

#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_bus_pci.h>
#include <rte_io.h>

#include "vhost.h"
#include "virtio_pci.h"
#include "virtqueue.h"
#include "virtio_vhost_user_pci.h"
#include "vhost_user.h"

/*
 * Data structures:
 *
 * Successfully probed virtio-vhost-user PCI adapters are added to
 * vvu_pci_device_list as struct vvu_pci_device elements.
 *
 * When rte_vhost_driver_register() is called, a struct vvu_socket is created
 * as the endpoint for future vhost-user connections.  The struct vvu_socket is
 * associated with the struct vvu_pci_device that will be used for
 * communication.
 *
 * When a vhost-user protocol connection is established, a struct
 * vvu_connection is created and the application's new_device(int vid) callback
 * is invoked.
 */

/** Probed PCI devices for lookup by rte_vhost_driver_register() */
TAILQ_HEAD(, vvu_pci_device) vvu_pci_device_list =
	TAILQ_HEAD_INITIALIZER(vvu_pci_device_list);

struct vvu_socket;
struct vvu_connection;

/** A virtio-vhost-user PCI adapter */
struct vvu_pci_device {
	struct virtio_pci_dev virtio_pci_device;
	struct rte_pci_device *pci_dev;
	struct vvu_socket *vvu_socket;
	TAILQ_ENTRY(vvu_pci_device) next;
};

/** A vhost-user endpoint (aka per-path state) */
struct vvu_socket {
	struct vhost_user_socket socket; /* must be first field! */
	struct vvu_pci_device *pdev;
	struct vvu_connection *conn;

	/** Doorbell registers */
	uint16_t *doorbells;

	/** This struct virtio_vhost_user_config field determines the number of
	 * doorbells available so we keep it saved.
	 */
	uint32_t max_vhost_queues;

	/** Receive buffers */
	const struct rte_memzone *rxbuf_mz;

	/** Transmit buffers.  It is assumed that the device completes them
	 * in-order so a single wrapping index can be used to select the next
	 * free buffer.
	 */
	const struct rte_memzone *txbuf_mz;
	unsigned int txbuf_idx;
};

/** A vhost-user protocol session (aka per-vid state) */
struct vvu_connection {
	struct virtio_net device; /* must be first field! */
	struct vvu_socket *vvu_socket;
};

/** Virtio feature bits that we support */
#define VVU_VIRTIO_FEATURES ((1ULL << VIRTIO_F_NOTIFY_ON_EMPTY) | \
			     (1ULL << VIRTIO_F_ANY_LAYOUT) | \
			     (1ULL << VIRTIO_F_VERSION_1) | \
			     (1ULL << VIRTIO_F_IOMMU_PLATFORM))

/** Virtqueue indices */
enum {
	VVU_VQ_RX,
	VVU_VQ_TX,
	VVU_VQ_MAX,
};

enum {
	/** Receive buffer size, in bytes */
	VVU_RXBUF_SIZE = 1024,

	/** Transmit buffer size, in bytes */
	VVU_TXBUF_SIZE = 1024,
};

/** Look up a struct vvu_pci_device from a DomBDF string */
static struct vvu_pci_device *
vvu_pci_by_name(const char *name)
{
	struct vvu_pci_device *pdev;
	TAILQ_FOREACH(pdev, &vvu_pci_device_list, next) {
		if (!strcmp(pdev->pci_dev->device.name, name))
			return pdev;
	}
	return NULL;
}

/** Start connection establishment */
static void
vvu_connect(struct vvu_socket *vvu_socket)
{
	struct virtio_hw *hw = &vvu_socket->pdev->virtio_pci_device.hw;
	uint32_t status;

	virtio_read_dev_config(hw,
			offsetof(struct virtio_vhost_user_config, status),
			&status, sizeof(status));
	status |= RTE_LE32(1u << VIRTIO_VHOST_USER_STATUS_SLAVE_UP);
	virtio_write_dev_config(hw,
			offsetof(struct virtio_vhost_user_config, status),
			&status, sizeof(status));
}

static void
vvu_disconnect(struct vvu_socket *vvu_socket)
{
	struct vhost_user_socket *vsocket = &vvu_socket->socket;
	struct vvu_connection *conn = vvu_socket->conn;
	struct virtio_hw *hw = &vvu_socket->pdev->virtio_pci_device.hw;
	uint32_t status;

	if (conn) {
		if (vsocket->notify_ops->destroy_connection)
			vsocket->notify_ops->destroy_connection(conn->device.vid);

		vhost_destroy_device(conn->device.vid);
	}

	/* Make sure we're disconnected */
	virtio_read_dev_config(hw,
			offsetof(struct virtio_vhost_user_config, status),
			&status, sizeof(status));
	status &= ~RTE_LE32(1u << VIRTIO_VHOST_USER_STATUS_SLAVE_UP);
	virtio_write_dev_config(hw,
			offsetof(struct virtio_vhost_user_config, status),
			&status, sizeof(status));
}

static void
vvu_reconnect(struct vvu_socket *vvu_socket)
{
	vvu_disconnect(vvu_socket);
	vvu_connect(vvu_socket);
}

static void vvu_process_rxq(struct vvu_socket *vvu_socket);

static void
vvu_cleanup_device(struct virtio_net *dev, int destroy __rte_unused)
{
	struct vvu_connection *conn =
		container_of(dev, struct vvu_connection, device);
	struct vvu_socket *vvu_socket = conn->vvu_socket;

	vvu_socket->conn = NULL;
	vvu_process_rxq(vvu_socket); /* discard old replies from master */
	vvu_reconnect(vvu_socket);
}

static int
vvu_vring_call(struct virtio_net *dev, struct vhost_virtqueue *vq)
{
	struct vvu_connection *conn =
		container_of(dev, struct vvu_connection, device);
	struct vvu_socket *vvu_socket = conn->vvu_socket;
	struct virtio_hw *hw = &vvu_socket->pdev->virtio_pci_device.hw;
	uint16_t vq_idx = vq->vring_idx;
	uint16_t *notify_addr = (void *)((uint8_t *)vvu_socket->doorbells +
				vq_idx * hw->doorbell_off_multiplier);

	VHOST_LOG_CONFIG(DEBUG, "%s vq_idx %u\n", __func__, vq_idx);

	rte_write16(rte_cpu_to_le_16(vq_idx), notify_addr);
	return 0;
}

static int
vvu_send_reply(struct virtio_net *dev, struct vhu_msg_context *ctx)
{
	struct vvu_connection *conn =
		container_of(dev, struct vvu_connection, device);
	struct vvu_socket *vvu_socket = conn->vvu_socket;
	struct virtqueue *vq = vvu_socket->pdev->virtio_pci_device.hw.vqs[VVU_VQ_TX];
	struct vring_desc *desc;
	struct VhostUserMsg *msg = &ctx->msg;
	struct vq_desc_extra *descx;
	unsigned int i;
	void *buf;
	size_t len;

	VHOST_LOG_CONFIG(DEBUG,
		"%s request %u flags %#x size %u\n",
		__func__, msg->request.master,
		msg->flags, msg->size);

	/* TODO convert msg to little-endian */

	if (virtqueue_full(vq)) {
		VHOST_LOG_CONFIG(ERR, "Out of tx buffers\n");
		return -1;
	}

	i = vvu_socket->txbuf_idx;
	len = VHOST_USER_HDR_SIZE + msg->size;
	buf = (uint8_t *)vvu_socket->txbuf_mz->addr + i * VVU_TXBUF_SIZE;

	memcpy(buf, msg, len);

	desc = &vq->vq_split.ring.desc[i];
	descx = &vq->vq_descx[i];

	desc->addr = rte_cpu_to_le_64(vvu_socket->txbuf_mz->iova + i * VVU_TXBUF_SIZE);
	desc->len = rte_cpu_to_le_32(len);
	desc->flags = 0;

	descx->cookie = buf;
	descx->ndescs = 1;

	vq->vq_free_cnt--;
	vvu_socket->txbuf_idx = (vvu_socket->txbuf_idx + 1) & (vq->vq_nentries - 1);

	vq_update_avail_ring(vq, i);
	vq_update_avail_idx(vq);

	if (virtqueue_kick_prepare(vq))
		virtqueue_notify(vq);

	return 0;
}

static int
vvu_map_mem_regions(struct virtio_net *dev, struct vhu_msg_context *ctx __rte_unused)
{
	struct vvu_connection *conn =
		container_of(dev, struct vvu_connection, device);
	struct vvu_socket *vvu_socket = conn->vvu_socket;
	struct virtio_hw *hw = &vvu_socket->pdev->virtio_pci_device.hw;
	uint8_t *mmap_addr;
	uint32_t i;

	/* Get the starting address of vhost memory regions from
	 * the shared memory virtio PCI capability
	 */
	mmap_addr = hw->shared_memory_cfg;

	for (i = 0; i < dev->mem->nregions; i++) {
		struct rte_vhost_mem_region *reg = &dev->mem->regions[i];

		reg->mmap_addr = mmap_addr;
		reg->host_user_addr = (uint64_t)(uintptr_t)reg->mmap_addr +
				      reg->mmap_size - reg->size;

		mmap_addr += reg->mmap_size;

		VHOST_LOG_CONFIG(INFO,
			"guest memory region %u, size: 0x%" PRIx64 "\n"
			"\t guest physical addr: 0x%" PRIx64 "\n"
			"\t guest virtual  addr: 0x%" PRIx64 "\n"
			"\t host  virtual  addr: 0x%" PRIx64 "\n"
			"\t mmap addr : 0x%" PRIx64 "\n"
			"\t mmap size : 0x%" PRIx64 "\n"
			"\t mmap off  : 0x%" PRIx64 "\n",
			i, reg->size,
			reg->guest_phys_addr,
			reg->guest_user_addr,
			reg->host_user_addr,
			(uint64_t)(uintptr_t)reg->mmap_addr,
			reg->mmap_size,
			reg->mmap_size - reg->size);
	}

	return 0;
}

static void
vvu_unmap_mem_regions(struct virtio_net *dev)
{
	uint32_t i;

	for (i = 0; i < dev->mem->nregions; i++) {
		struct rte_vhost_mem_region *reg = &dev->mem->regions[i];

		/* Just clear the pointers, the PCI BAR stays there */
		reg->mmap_addr = NULL;
		reg->host_user_addr = 0;
	}
}

static void vvu_process_new_connection(struct vvu_socket *vvu_socket)
{
	struct vhost_user_socket *vsocket = &vvu_socket->socket;
	struct vvu_connection *conn;
	struct virtio_net *dev;
	size_t size;

	dev = vhost_new_device(vsocket->trans_ops);
	if (!dev) {
		vvu_reconnect(vvu_socket);
		return;
	}

	conn = container_of(dev, struct vvu_connection, device);
	conn->vvu_socket = vvu_socket;

	size = strnlen(vsocket->path, PATH_MAX);
	vhost_set_ifname(dev->vid, vsocket->path, size);

	vhost_setup_virtio_net(dev->vid, vsocket->use_builtin_virtio_net,
		vsocket->net_compliant_ol_flags);

	VHOST_LOG_CONFIG(INFO, "new device, handle is %d\n", dev->vid);

	if (vsocket->notify_ops->new_connection) {
		int ret = vsocket->notify_ops->new_connection(dev->vid);
		if (ret < 0) {
			VHOST_LOG_CONFIG(ERR,
				"failed to add vhost user connection\n");
			vhost_destroy_device(dev->vid);
			vvu_reconnect(vvu_socket);
			return;
		}
	}

	vvu_socket->conn = conn;
}

static void vvu_process_status_change(struct vvu_socket *vvu_socket, bool slave_up,
				      bool master_up)
{
	VHOST_LOG_CONFIG(DEBUG, "%s slave_up %d master_up %d\n",
		__func__, slave_up, master_up);

	/* Disconnected from the master, try reconnecting */
	if (!slave_up) {
		vvu_reconnect(vvu_socket);
		return;
	}

	if (master_up && !vvu_socket->conn) {
		vvu_process_new_connection(vvu_socket);
		return;
	}
}

static void
vvu_process_txq(struct vvu_socket *vvu_socket)
{
	struct virtio_hw *hw = &vvu_socket->pdev->virtio_pci_device.hw;
	struct virtqueue *vq = hw->vqs[VVU_VQ_TX];
	uint16_t n = VIRTQUEUE_NUSED(vq);

	rte_smp_rmb();

	/* Just mark the buffers complete */
	vq->vq_used_cons_idx += n;
	vq->vq_free_cnt += n;
}

static void
vvu_process_rxq(struct vvu_socket *vvu_socket)
{
	struct virtio_hw *hw = &vvu_socket->pdev->virtio_pci_device.hw;
	struct virtqueue *vq = hw->vqs[VVU_VQ_RX];
	bool refilled = false;

	while (VIRTQUEUE_NUSED(vq)) {
		struct vring_used_elem *uep;
		struct vhu_msg_context ctx;
		VhostUserMsg *msg;
		uint32_t len;
		uint32_t desc_idx;
		uint16_t used_idx;
		size_t i;

		rte_smp_rmb();

		used_idx = (uint16_t)(vq->vq_used_cons_idx & (vq->vq_nentries - 1));
		uep = &vq->vq_split.ring.used->ring[used_idx];
		desc_idx = rte_le_to_cpu_32(uep->id);

		msg = vq->vq_descx[desc_idx].cookie;
		ctx.msg = *msg;
		len = rte_le_to_cpu_32(uep->len);

		if (msg->size > sizeof(VhostUserMsg) ||
		    len != VHOST_USER_HDR_SIZE + msg->size) {
			VHOST_LOG_CONFIG(ERR,
				"Invalid vhost-user message size %u, got %u bytes\n",
				msg->size, len);
			/* TODO reconnect */
			abort();
		}

		VHOST_LOG_CONFIG(DEBUG,
			"%s request %u flags %#x size %u\n",
			__func__, msg->request.master,
			msg->flags, msg->size);

		/* Mark file descriptors invalid */
		for (i = 0; i < RTE_DIM(ctx.fds); i++)
			ctx.fds[i] = VIRTIO_INVALID_EVENTFD;

		/* Only process messages while connected */
		if (vvu_socket->conn) {
			if (vhost_user_msg_handler(vvu_socket->conn->device.vid,
						   &ctx) < 0) {
				/* TODO reconnect */
				abort();
			}
		}

		vq->vq_used_cons_idx++;

		/* Refill rxq */
		vq_update_avail_ring(vq, desc_idx);
		vq_update_avail_idx(vq);
		refilled = true;
	}

	if (!refilled)
		return;
	if (virtqueue_kick_prepare(vq))
		virtqueue_notify(vq);
}

/* TODO Audit thread safety.  There are 3 threads involved:
 * 1. The main process thread that calls vhost APIs during startup.
 * 2. The interrupt thread that calls vvu_interrupt_handler().
 * 3. Packet processing threads (lcores) calling vhost APIs.
 *
 * It may be necessary to use locks if any of these code paths can race.  The
 * vhost API entry points already do some locking but this needs to be
 * checked.
 */
static void
vvu_interrupt_handler(void *cb_arg)
{
	struct vvu_socket *vvu_socket = cb_arg;
	struct virtio_hw *hw = &vvu_socket->pdev->virtio_pci_device.hw;
	struct rte_intr_handle *intr_handle = vvu_socket->pdev->pci_dev->intr_handle;
	uint8_t isr;

	/* Read Interrupt Status Register (which also clears it) */
	isr = VIRTIO_OPS(hw)->get_isr(hw);

	if (isr & VIRTIO_ISR_CONFIG) {
		uint32_t status;
		bool slave_up;
		bool master_up;

		virtio_read_dev_config(hw,
				offsetof(struct virtio_vhost_user_config, status),
				&status, sizeof(status));
		status = rte_le_to_cpu_32(status);

		VHOST_LOG_CONFIG(DEBUG, "%s isr %#x status %#x\n", __func__, isr, status);

		slave_up = status & (1u << VIRTIO_VHOST_USER_STATUS_SLAVE_UP);
		master_up = status & (1u << VIRTIO_VHOST_USER_STATUS_MASTER_UP);
		vvu_process_status_change(vvu_socket, slave_up, master_up);
	} else {
		VHOST_LOG_CONFIG(DEBUG, "%s isr %#x\n", __func__, isr);
	}

	/* Re-arm before processing virtqueues so no interrupts are lost */
	rte_intr_enable(intr_handle);

	vvu_process_txq(vvu_socket);
	vvu_process_rxq(vvu_socket);
}

static int
vvu_virtio_pci_init_rxq(struct vvu_socket *vvu_socket)
{
	char name[sizeof("0000:00:00.00 vq 0 rxbufs")];
	struct virtqueue *vq;
	size_t size;
	size_t align;
	int i;

	vq = vvu_socket->pdev->virtio_pci_device.hw.vqs[VVU_VQ_RX];

	snprintf(name, sizeof(name), "%s vq %u rxbufs",
		 vvu_socket->pdev->pci_dev->device.name, VVU_VQ_RX);

	/* Allocate more than sizeof(VhostUserMsg) so there is room to grow */
	size = vq->vq_nentries * VVU_RXBUF_SIZE;
	align = 1024;
	vvu_socket->rxbuf_mz = rte_memzone_reserve_aligned(name, size, SOCKET_ID_ANY,
							   0, align);
	if (!vvu_socket->rxbuf_mz) {
		VHOST_LOG_CONFIG(ERR,
			"Failed to allocate rxbuf memzone\n");
		return -1;
	}

	for (i = 0; i < vq->vq_nentries; i++) {
		struct vring_desc *desc = &vq->vq_split.ring.desc[i];
		struct vq_desc_extra *descx = &vq->vq_descx[i];

		desc->addr = rte_cpu_to_le_64(vvu_socket->rxbuf_mz->iova +
			i * VVU_RXBUF_SIZE);
		desc->len = RTE_LE32(VVU_RXBUF_SIZE);
		desc->flags = RTE_LE16(VRING_DESC_F_WRITE);

		descx->cookie = (uint8_t *)vvu_socket->rxbuf_mz->addr + i * VVU_RXBUF_SIZE;
		descx->ndescs = 1;

		vq_update_avail_ring(vq, i);
		vq->vq_free_cnt--;
	}

	vq_update_avail_idx(vq);
	virtqueue_notify(vq);
	return 0;
}

static int
vvu_virtio_pci_init_txq(struct vvu_socket *vvu_socket)
{
	char name[sizeof("0000:00:00.00 vq 0 txbufs")];
	struct virtqueue *vq;
	size_t size;
	size_t align;

	vq = vvu_socket->pdev->virtio_pci_device.hw.vqs[VVU_VQ_TX];

	snprintf(name, sizeof(name), "%s vq %u txbufs",
		 vvu_socket->pdev->pci_dev->device.name, VVU_VQ_TX);

	/* Allocate more than sizeof(VhostUserMsg) so there is room to grow */
	size = vq->vq_nentries * VVU_TXBUF_SIZE;
	align = 1024;
	vvu_socket->txbuf_mz = rte_memzone_reserve_aligned(name, size, SOCKET_ID_ANY,
							   0, align);
	if (!vvu_socket->txbuf_mz) {
		VHOST_LOG_CONFIG(ERR,
			"Failed to allocate txbuf memzone\n");
		return -1;
	}

	vvu_socket->txbuf_idx = 0;
	return 0;
}

static void
virtio_init_vring(struct virtqueue *vq)
{
	int size = vq->vq_nentries;
	struct vring *vr = &vq->vq_split.ring;
	uint8_t *ring_mem = vq->vq_ring_virt_mem;

	memset(ring_mem, 0, vq->vq_ring_size);
	vring_init(vr, size, ring_mem, VIRTIO_VRING_ALIGN);
	vq->vq_used_cons_idx = 0;
	vq->vq_desc_head_idx = 0;
	vq->vq_avail_idx = 0;
	vq->vq_desc_tail_idx = (uint16_t)(vq->vq_nentries - 1);
	vq->vq_free_cnt = vq->vq_nentries;
	memset(vq->vq_descx, 0, sizeof(struct vq_desc_extra) * vq->vq_nentries);

	vring_desc_init_split(vr->desc, size);
	virtqueue_enable_intr(vq);
}

static int
vvu_virtio_pci_init_vq(struct vvu_socket *vvu_socket, int vq_idx)
{
	char vq_name[sizeof("0000:00:00.00 vq 0")];
	struct virtio_hw *hw = &vvu_socket->pdev->virtio_pci_device.hw;
	const struct rte_memzone *mz;
	struct virtqueue *vq;
	uint16_t q_num;
	size_t size;

	q_num = VIRTIO_OPS(hw)->get_queue_num(hw, vq_idx);
	VHOST_LOG_CONFIG(DEBUG, "vq %d q_num: %u\n", vq_idx, q_num);
	if (q_num == 0) {
		VHOST_LOG_CONFIG(ERR, "virtqueue %d does not exist\n",
			vq_idx);
		return -1;
	}

	if (!rte_is_power_of_2(q_num)) {
		VHOST_LOG_CONFIG(ERR,
			"virtqueue %d has non-power of 2 size (%u)\n",
			vq_idx, q_num);
		return -1;
	}

	snprintf(vq_name, sizeof(vq_name), "%s vq %u",
		 vvu_socket->pdev->pci_dev->device.name, vq_idx);

	size = RTE_ALIGN_CEIL(sizeof(*vq) +
			      q_num * sizeof(struct vq_desc_extra),
			      RTE_CACHE_LINE_SIZE);
	vq = rte_zmalloc(vq_name, size, RTE_CACHE_LINE_SIZE);
	if (!vq) {
		VHOST_LOG_CONFIG(ERR,
			"Failed to allocated virtqueue %d\n", vq_idx);
		return -1;
	}
	hw->vqs[vq_idx] = vq;

	vq->hw = hw;
	vq->vq_queue_index = vq_idx;
	vq->vq_nentries = q_num;

	size = vring_size(q_num, VIRTIO_VRING_ALIGN);
	vq->vq_ring_size = RTE_ALIGN_CEIL(size, VIRTIO_VRING_ALIGN);

	mz = rte_memzone_reserve_aligned(vq_name, vq->vq_ring_size,
					 SOCKET_ID_ANY, 0,
					 VIRTIO_VRING_ALIGN);
	if (mz == NULL) {
		VHOST_LOG_CONFIG(ERR,
			"Failed to reserve memzone for virtqueue %d\n",
			vq_idx);
		goto err_vq;
	}

	memset(mz->addr, 0, mz->len);

	vq->mz = mz;
	vq->vq_ring_mem = mz->iova;
	vq->vq_ring_virt_mem = mz->addr;
	virtio_init_vring(vq);

	if (VIRTIO_OPS(hw)->setup_queue(hw, vq) < 0)
		goto err_mz;

	return 0;

err_mz:
	rte_memzone_free(mz);

err_vq:
	hw->vqs[vq_idx] = NULL;
	rte_free(vq);
	return -1;
}

static void
vvu_virtio_pci_free_virtqueues(struct vvu_socket *vvu_socket)
{
	struct virtio_hw *hw = &vvu_socket->pdev->virtio_pci_device.hw;
	int i;

	if (vvu_socket->rxbuf_mz) {
		rte_memzone_free(vvu_socket->rxbuf_mz);
		vvu_socket->rxbuf_mz = NULL;
	}
	if (vvu_socket->txbuf_mz) {
		rte_memzone_free(vvu_socket->txbuf_mz);
		vvu_socket->txbuf_mz = NULL;
	}

	for (i = 0; i < VVU_VQ_MAX; i++) {
		struct virtqueue *vq = hw->vqs[i];

		if (!vq)
			continue;

		rte_memzone_free(vq->mz);
		rte_free(vq);
		hw->vqs[i] = NULL;
	}

	rte_free(hw->vqs);
	hw->vqs = NULL;
}

static void
vvu_virtio_pci_intr_cleanup(struct vvu_socket *vvu_socket)
{
	struct virtio_hw *hw = &vvu_socket->pdev->virtio_pci_device.hw;
	struct rte_intr_handle *intr_handle = vvu_socket->pdev->pci_dev->intr_handle;
	int i;

	for (i = 0; i < VVU_VQ_MAX; i++)
		VIRTIO_OPS(hw)->set_queue_irq(hw, hw->vqs[i],
					     VIRTIO_MSI_NO_VECTOR);
	VIRTIO_OPS(hw)->set_config_irq(hw, VIRTIO_MSI_NO_VECTOR);
	rte_intr_disable(intr_handle);
	rte_intr_callback_unregister(intr_handle, vvu_interrupt_handler, vvu_socket);
	rte_intr_efd_disable(intr_handle);
}

static int
vvu_virtio_pci_init_intr(struct vvu_socket *vvu_socket)
{
	struct virtio_hw *hw = &vvu_socket->pdev->virtio_pci_device.hw;
	struct rte_intr_handle *intr_handle = vvu_socket->pdev->pci_dev->intr_handle;
	int i;

	if (!rte_intr_cap_multiple(intr_handle)) {
		VHOST_LOG_CONFIG(ERR,
			"Multiple intr vector not supported\n");
		return -1;
	}

	if (rte_intr_efd_enable(intr_handle, VVU_VQ_MAX) < 0) {
		VHOST_LOG_CONFIG(ERR,
			"Failed to create eventfds\n");
		return -1;
	}

	if (rte_intr_callback_register(intr_handle, vvu_interrupt_handler, vvu_socket) < 0) {
		VHOST_LOG_CONFIG(ERR,
			"Failed to register interrupt callback\n");
		goto err_efd;
	}

	if (rte_intr_enable(intr_handle) < 0)
		goto err_callback;

	if (VIRTIO_OPS(hw)->set_config_irq(hw, 0) == VIRTIO_MSI_NO_VECTOR) {
		VHOST_LOG_CONFIG(ERR,
			"Failed to set config MSI-X vector\n");
		goto err_enable;
	}

	/* TODO use separate vectors and interrupt handler functions.  It seems
	 * <rte_interrupts.h> doesn't allow efds to have interrupt_handler
	 * functions and it just clears efds when they are raised.  As a
	 * workaround we use the configuration change interrupt for virtqueue
	 * interrupts!
	 */
	for (i = 0; i < VVU_VQ_MAX; i++) {
		if (VIRTIO_OPS(hw)->set_queue_irq(hw, hw->vqs[i], 0) ==
				VIRTIO_MSI_NO_VECTOR) {
			VHOST_LOG_CONFIG(ERR,
				"Failed to set virtqueue MSI-X vector\n");
			goto err_vq;
		}
	}

	return 0;

err_vq:
	for (i = 0; i < VVU_VQ_MAX; i++)
		VIRTIO_OPS(hw)->set_queue_irq(hw, hw->vqs[i],
					     VIRTIO_MSI_NO_VECTOR);
	VIRTIO_OPS(hw)->set_config_irq(hw, VIRTIO_MSI_NO_VECTOR);
err_enable:
	rte_intr_disable(intr_handle);
err_callback:
	rte_intr_callback_unregister(intr_handle, vvu_interrupt_handler, vvu_socket);
err_efd:
	rte_intr_efd_disable(intr_handle);
	return -1;
}

static int
vvu_virtio_pci_init_bar(struct vvu_socket *vvu_socket)
{
	struct virtio_hw *hw = &vvu_socket->pdev->virtio_pci_device.hw;
	struct virtio_net *dev = NULL; /* just for sizeof() */

	/* Get the starting address of the doorbells from
	 * the doorbell virtio PCI capability
	 */
	vvu_socket->doorbells = hw->doorbell_base;
	if (!vvu_socket->doorbells) {
		VHOST_LOG_CONFIG(ERR, "BAR 2 not available\n");
		return -1;
	}

	/* The number of doorbells is max_vhost_queues + 1 */
	virtio_read_dev_config(&vvu_socket->pdev->virtio_pci_device.hw,
			offsetof(struct virtio_vhost_user_config,
				 max_vhost_queues),
			&vvu_socket->max_vhost_queues,
			sizeof(vvu_socket->max_vhost_queues));
	vvu_socket->max_vhost_queues = rte_le_to_cpu_32(vvu_socket->max_vhost_queues);
	if (vvu_socket->max_vhost_queues < RTE_DIM(dev->virtqueue)) {
		/* We could support devices with a smaller max number of
		 * virtqueues than dev->virtqueue[] in the future.  Fail early
		 * for now since the current assumption is that all of
		 * dev->virtqueue[] can be used.
		 */
		VHOST_LOG_CONFIG(ERR,
			"Device supports fewer virtqueues than driver!\n");
		return -1;
	}

	return 0;
}

static int
vvu_virtio_pci_init(struct vvu_socket *vvu_socket)
{
	uint64_t host_features;
	struct virtio_hw *hw = &vvu_socket->pdev->virtio_pci_device.hw;
	int i;

	virtio_set_status(hw, VIRTIO_CONFIG_STATUS_ACK);
	virtio_set_status(hw, VIRTIO_CONFIG_STATUS_DRIVER);

	hw->guest_features = VVU_VIRTIO_FEATURES;
	host_features = VIRTIO_OPS(hw)->get_features(hw);
	hw->guest_features = virtio_negotiate_features(hw, host_features);

	if (!virtio_with_feature(hw, VIRTIO_F_VERSION_1)) {
		VHOST_LOG_CONFIG(ERR, "Missing VIRTIO 1 feature bit\n");
		goto err;
	}

	virtio_set_status(hw, VIRTIO_CONFIG_STATUS_FEATURES_OK);
	if (!(virtio_get_status(hw) & VIRTIO_CONFIG_STATUS_FEATURES_OK)) {
		VHOST_LOG_CONFIG(ERR, "Failed to set FEATURES_OK\n");
		goto err;
	}

	if (vvu_virtio_pci_init_bar(vvu_socket) < 0)
		goto err;

	hw->vqs = rte_zmalloc(NULL, sizeof(struct virtqueue *) * VVU_VQ_MAX, 0);
	if (!hw->vqs)
		goto err;

	for (i = 0; i < VVU_VQ_MAX; i++) {
		if (vvu_virtio_pci_init_vq(vvu_socket, i) < 0) {
			VHOST_LOG_CONFIG(ERR,
				"virtqueue %u init failed\n", i);
			goto err_init_vq;
		}
	}

	if (vvu_virtio_pci_init_rxq(vvu_socket) < 0)
		goto err_init_vq;

	if (vvu_virtio_pci_init_txq(vvu_socket) < 0)
		goto err_init_vq;

	if (vvu_virtio_pci_init_intr(vvu_socket) < 0)
		goto err_init_vq;

	virtio_set_status(hw, VIRTIO_CONFIG_STATUS_DRIVER_OK);

	return 0;

err_init_vq:
	vvu_virtio_pci_free_virtqueues(vvu_socket);

err:
	virtio_reset(hw);
	VHOST_LOG_CONFIG(DEBUG, "%s failed\n", __func__);
	return -1;
}

static int
vvu_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
	      struct rte_pci_device *pci_dev)
{
	struct vvu_pci_device *pdev;

	/* TODO support multi-process applications */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		VHOST_LOG_CONFIG(ERR,
			"virtio-vhost-pci does not support multi-process "
			"applications\n");
		return -1;
	}

	pdev = rte_zmalloc_socket(pci_dev->device.name, sizeof(*pdev),
				  RTE_CACHE_LINE_SIZE,
				  pci_dev->device.numa_node);
	if (!pdev)
		return -1;

	pdev->pci_dev = pci_dev;
	VTPCI_DEV(&pdev->virtio_pci_device.hw) = pci_dev;

	if (vtpci_init(pci_dev, &pdev->virtio_pci_device) != 0) {
		rte_free(pdev);
		return -1;
	}

	/* Reset the device now, the rest is done in vvu_socket_init() */
	virtio_reset(&pdev->virtio_pci_device.hw);

	if (pdev->virtio_pci_device.msix_status == VIRTIO_MSIX_NONE) {
		VHOST_LOG_CONFIG(ERR,
			"MSI-X is required for PCI device at %s\n",
			pci_dev->device.name);
		rte_free(pdev);
		rte_pci_unmap_device(pci_dev);
		return -1;
	}

	TAILQ_INSERT_TAIL(&vvu_pci_device_list, pdev, next);

	VHOST_LOG_CONFIG(INFO,
		"Added virtio-vhost-user device at %s\n",
		pci_dev->device.name);

	return 0;
}

static int
vvu_pci_remove(struct rte_pci_device *pci_dev)
{
	struct vvu_pci_device *pdev;

	TAILQ_FOREACH(pdev, &vvu_pci_device_list, next)
		if (pdev->pci_dev == pci_dev)
			break;
	if (!pdev)
		return -1;

	if (pdev->vvu_socket) {
		VHOST_LOG_CONFIG(ERR,
			"Cannot remove PCI device at %s with vhost still attached\n",
			pci_dev->device.name);
		return -1;
	}

	TAILQ_REMOVE(&vvu_pci_device_list, pdev, next);
	rte_free(pdev);
	rte_pci_unmap_device(pci_dev);
	return 0;
}

static const struct rte_pci_id pci_id_vvu_map[] = {
	{ RTE_PCI_DEVICE(VIRTIO_PCI_VENDORID,
			 VIRTIO_PCI_MODERN_DEVICEID_VHOST_USER) },
	{ .vendor_id = 0, /* sentinel */ },
};

static struct rte_pci_driver vvu_pci_driver = {
	.driver = {
		.name = "virtio_vhost_user",
	},
	.id_table = pci_id_vvu_map,
	.drv_flags = 0,
	.probe = vvu_pci_probe,
	.remove = vvu_pci_remove,
};

RTE_INIT(vvu_pci_init);
static void
vvu_pci_init(void)
{
	if (rte_eal_iopl_init() != 0) {
		VHOST_LOG_CONFIG(ERR,
			"IOPL call failed - cannot use virtio-vhost-user\n");
		return;
	}

	rte_pci_register(&vvu_pci_driver);
	if (rte_vhost_register_transport(VHOST_TRANSPORT_VVU, &virtio_vhost_user_trans_ops) < 0) {
		VHOST_LOG_CONFIG(ERR,
			"Registration of vhost-user transport (%d) failed\n",
			VHOST_TRANSPORT_VVU);
	}
}

static int
vvu_socket_init(struct vhost_user_socket *vsocket, uint64_t flags)
{
	struct vvu_socket *vvu_socket =
		container_of(vsocket, struct vvu_socket, socket);
	struct vvu_pci_device *pdev;

	if (flags & RTE_VHOST_USER_NO_RECONNECT) {
		VHOST_LOG_CONFIG(ERR,
			"error: reconnect cannot be disabled for virtio-vhost-user\n");
		return -1;
	}
	if (flags & RTE_VHOST_USER_CLIENT) {
		VHOST_LOG_CONFIG(ERR,
			"error: virtio-vhost-user does not support client mode\n");
		return -1;
	}

	pdev = vvu_pci_by_name(vsocket->path);
	if (!pdev) {
		VHOST_LOG_CONFIG(ERR,
			"Cannot find virtio-vhost-user PCI device at %s\n",
			vsocket->path);
		return -1;
	}

	if (pdev->vvu_socket) {
		VHOST_LOG_CONFIG(ERR,
			"Device at %s is already in use\n",
			vsocket->path);
		return -1;
	}

	vvu_socket->pdev = pdev;
	pdev->vvu_socket = vvu_socket;

	if (vvu_virtio_pci_init(vvu_socket) < 0) {
		vvu_socket->pdev = NULL;
		pdev->vvu_socket = NULL;
		return -1;
	}

	VHOST_LOG_CONFIG(INFO, "%s at %s\n", __func__, vsocket->path);
	return 0;
}

static int
vvu_socket_cleanup(struct vhost_user_socket *vsocket)
{
	struct vvu_socket *vvu_socket =
		container_of(vsocket, struct vvu_socket, socket);

	if (vvu_socket->conn)
		vhost_destroy_device(vvu_socket->conn->device.vid);

	vvu_virtio_pci_intr_cleanup(vvu_socket);
	virtio_reset(&vvu_socket->pdev->virtio_pci_device.hw);
	vvu_virtio_pci_free_virtqueues(vvu_socket);

	vvu_socket->pdev->vvu_socket = NULL;
	vvu_socket->pdev = NULL;
	return 0;
}

static int
vvu_socket_start(struct vhost_user_socket *vsocket)
{
	struct vvu_socket *vvu_socket =
		container_of(vsocket, struct vvu_socket, socket);

	vvu_connect(vvu_socket);
	return 0;
}

const struct vhost_transport_ops virtio_vhost_user_trans_ops = {
	.socket_size = sizeof(struct vvu_socket),
	.device_size = sizeof(struct vvu_connection),
	.socket_init = vvu_socket_init,
	.socket_cleanup = vvu_socket_cleanup,
	.socket_start = vvu_socket_start,
	.cleanup_device = vvu_cleanup_device,
	.vring_call = vvu_vring_call,
	.send_reply = vvu_send_reply,
	.map_mem_regions = vvu_map_mem_regions,
	.unmap_mem_regions = vvu_unmap_mem_regions,
};
