/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/queue.h>
#include <pthread.h>

#include <rte_log.h>

#include "fd_man.h"
#include "vhost.h"
#include "vhost_user.h"

struct vhost_user vhost_user = {
	.fdset = {
		.fd = { [0 ... MAX_FDS - 1] = {-1, NULL, NULL, NULL, 0} },
		.fd_mutex = PTHREAD_MUTEX_INITIALIZER,
		.fd_pooling_mutex = PTHREAD_MUTEX_INITIALIZER,
		.num = 0
	},
	.vsocket_cnt = 0,
	.mutex = PTHREAD_MUTEX_INITIALIZER,
};


static struct vhost_user_socket *
find_vhost_user_socket(const char *path)
{
	int i;

	if (path == NULL)
		return NULL;

	for (i = 0; i < vhost_user.vsocket_cnt; i++) {
		struct vhost_user_socket *vsocket = vhost_user.vsockets[i];

		if (!strcmp(vsocket->path, path))
			return vsocket;
	}

	return NULL;
}

int
rte_vhost_driver_attach_vdpa_device(const char *path,
		struct rte_vdpa_device *dev)
{
	struct vhost_user_socket *vsocket;

	if (dev == NULL || path == NULL)
		return -1;

	pthread_mutex_lock(&vhost_user.mutex);
	vsocket = find_vhost_user_socket(path);
	if (vsocket)
		vsocket->vdpa_dev = dev;
	pthread_mutex_unlock(&vhost_user.mutex);

	return vsocket ? 0 : -1;
}

int
rte_vhost_driver_detach_vdpa_device(const char *path)
{
	struct vhost_user_socket *vsocket;

	pthread_mutex_lock(&vhost_user.mutex);
	vsocket = find_vhost_user_socket(path);
	if (vsocket)
		vsocket->vdpa_dev = NULL;
	pthread_mutex_unlock(&vhost_user.mutex);

	return vsocket ? 0 : -1;
}

struct rte_vdpa_device *
rte_vhost_driver_get_vdpa_device(const char *path)
{
	struct vhost_user_socket *vsocket;
	struct rte_vdpa_device *dev = NULL;

	pthread_mutex_lock(&vhost_user.mutex);
	vsocket = find_vhost_user_socket(path);
	if (vsocket)
		dev = vsocket->vdpa_dev;
	pthread_mutex_unlock(&vhost_user.mutex);

	return dev;
}

int
rte_vhost_driver_disable_features(const char *path, uint64_t features)
{
	struct vhost_user_socket *vsocket;

	pthread_mutex_lock(&vhost_user.mutex);
	vsocket = find_vhost_user_socket(path);

	/* Note that use_builtin_virtio_net is not affected by this function
	 * since callers may want to selectively disable features of the
	 * built-in vhost net device backend.
	 */

	if (vsocket)
		vsocket->features &= ~features;
	pthread_mutex_unlock(&vhost_user.mutex);

	return vsocket ? 0 : -1;
}

int
rte_vhost_driver_enable_features(const char *path, uint64_t features)
{
	struct vhost_user_socket *vsocket;

	pthread_mutex_lock(&vhost_user.mutex);
	vsocket = find_vhost_user_socket(path);
	if (vsocket) {
		if ((vsocket->supported_features & features) != features) {
			/*
			 * trying to enable features the driver doesn't
			 * support.
			 */
			pthread_mutex_unlock(&vhost_user.mutex);
			return -1;
		}
		vsocket->features |= features;
	}
	pthread_mutex_unlock(&vhost_user.mutex);

	return vsocket ? 0 : -1;
}

int
rte_vhost_driver_set_features(const char *path, uint64_t features)
{
	struct vhost_user_socket *vsocket;

	pthread_mutex_lock(&vhost_user.mutex);
	vsocket = find_vhost_user_socket(path);
	if (vsocket) {
		vsocket->supported_features = features;
		vsocket->features = features;

		/* Anyone setting feature bits is implementing their own vhost
		 * device backend.
		 */
		vsocket->use_builtin_virtio_net = false;
	}
	pthread_mutex_unlock(&vhost_user.mutex);

	return vsocket ? 0 : -1;
}

int
rte_vhost_driver_get_features(const char *path, uint64_t *features)
{
	struct vhost_user_socket *vsocket;
	uint64_t vdpa_features;
	struct rte_vdpa_device *vdpa_dev;
	int ret = 0;

	pthread_mutex_lock(&vhost_user.mutex);
	vsocket = find_vhost_user_socket(path);
	if (!vsocket) {
		VHOST_LOG_CONFIG(ERR, "(%s) socket file is not registered yet.\n", path);
		ret = -1;
		goto unlock_exit;
	}

	vdpa_dev = vsocket->vdpa_dev;
	if (!vdpa_dev) {
		*features = vsocket->features;
		goto unlock_exit;
	}

	if (vdpa_dev->ops->get_features(vdpa_dev, &vdpa_features) < 0) {
		VHOST_LOG_CONFIG(ERR, "(%s) failed to get vdpa features for socket file.\n", path);
		ret = -1;
		goto unlock_exit;
	}

	*features = vsocket->features & vdpa_features;

unlock_exit:
	pthread_mutex_unlock(&vhost_user.mutex);
	return ret;
}

int
rte_vhost_driver_set_protocol_features(const char *path,
		uint64_t protocol_features)
{
	struct vhost_user_socket *vsocket;

	pthread_mutex_lock(&vhost_user.mutex);
	vsocket = find_vhost_user_socket(path);
	if (vsocket)
		vsocket->protocol_features = protocol_features;
	pthread_mutex_unlock(&vhost_user.mutex);
	return vsocket ? 0 : -1;
}

int
rte_vhost_driver_get_protocol_features(const char *path,
		uint64_t *protocol_features)
{
	struct vhost_user_socket *vsocket;
	uint64_t vdpa_protocol_features;
	struct rte_vdpa_device *vdpa_dev;
	int ret = 0;

	pthread_mutex_lock(&vhost_user.mutex);
	vsocket = find_vhost_user_socket(path);
	if (!vsocket) {
		VHOST_LOG_CONFIG(ERR, "(%s) socket file is not registered yet.\n", path);
		ret = -1;
		goto unlock_exit;
	}

	vdpa_dev = vsocket->vdpa_dev;
	if (!vdpa_dev) {
		*protocol_features = vsocket->protocol_features;
		goto unlock_exit;
	}

	if (vdpa_dev->ops->get_protocol_features(vdpa_dev,
				&vdpa_protocol_features) < 0) {
		VHOST_LOG_CONFIG(ERR, "(%s) failed to get vdpa protocol features.\n",
				path);
		ret = -1;
		goto unlock_exit;
	}

	*protocol_features = vsocket->protocol_features
		& vdpa_protocol_features;

unlock_exit:
	pthread_mutex_unlock(&vhost_user.mutex);
	return ret;
}

int
rte_vhost_driver_get_queue_num(const char *path, uint32_t *queue_num)
{
	struct vhost_user_socket *vsocket;
	uint32_t vdpa_queue_num;
	struct rte_vdpa_device *vdpa_dev;
	int ret = 0;

	pthread_mutex_lock(&vhost_user.mutex);
	vsocket = find_vhost_user_socket(path);
	if (!vsocket) {
		VHOST_LOG_CONFIG(ERR, "(%s) socket file is not registered yet.\n", path);
		ret = -1;
		goto unlock_exit;
	}

	vdpa_dev = vsocket->vdpa_dev;
	if (!vdpa_dev) {
		*queue_num = VHOST_MAX_QUEUE_PAIRS;
		goto unlock_exit;
	}

	if (vdpa_dev->ops->get_queue_num(vdpa_dev, &vdpa_queue_num) < 0) {
		VHOST_LOG_CONFIG(ERR, "(%s) failed to get vdpa queue number.\n",
				path);
		ret = -1;
		goto unlock_exit;
	}

	*queue_num = RTE_MIN((uint32_t)VHOST_MAX_QUEUE_PAIRS, vdpa_queue_num);

unlock_exit:
	pthread_mutex_unlock(&vhost_user.mutex);
	return ret;
}

static void
vhost_user_socket_mem_free(struct vhost_user_socket *vsocket)
{
	if (vsocket && vsocket->path) {
		free(vsocket->path);
		vsocket->path = NULL;
	}

	if (vsocket) {
		free(vsocket);
		vsocket = NULL;
	}
}

/*
 * Register a new vhost-user socket; here we could act as server
 * (the default case), or client (when RTE_VHOST_USER_CLIENT) flag
 * is set.
 */
int
rte_vhost_driver_register(const char *path, uint64_t flags)
{
	int ret = -1;
	struct vhost_user_socket *vsocket;
	const struct vhost_transport_ops *trans_ops = &af_unix_trans_ops;

	if (!path)
		return -1;

	pthread_mutex_lock(&vhost_user.mutex);

	if (vhost_user.vsocket_cnt == MAX_VHOST_SOCKET) {
		VHOST_LOG_CONFIG(ERR, "(%s) the number of vhost sockets reaches maximum\n",
				path);
		goto out;
	}

	vsocket = malloc(trans_ops->socket_size);
	if (!vsocket)
		goto out;
	memset(vsocket, 0, trans_ops->socket_size);
	vsocket->trans_ops = trans_ops;
	vsocket->path = strdup(path);
	if (vsocket->path == NULL) {
		VHOST_LOG_CONFIG(ERR, "(%s) failed to copy socket path string\n", path);
		vhost_user_socket_mem_free(vsocket);
		goto out;
	}
	vsocket->vdpa_dev = NULL;
	vsocket->extbuf = flags & RTE_VHOST_USER_EXTBUF_SUPPORT;
	vsocket->linearbuf = flags & RTE_VHOST_USER_LINEARBUF_SUPPORT;
	vsocket->async_copy = flags & RTE_VHOST_USER_ASYNC_COPY;
	vsocket->net_compliant_ol_flags = flags & RTE_VHOST_USER_NET_COMPLIANT_OL_FLAGS;

	if (vsocket->async_copy &&
		(flags & (RTE_VHOST_USER_IOMMU_SUPPORT |
		RTE_VHOST_USER_POSTCOPY_SUPPORT))) {
		VHOST_LOG_CONFIG(ERR, "(%s) async copy with IOMMU or post-copy not supported\n",
				path);
		goto out_free;
	}

	/*
	 * Set the supported features correctly for the builtin vhost-user
	 * net driver.
	 *
	 * Applications know nothing about features the builtin virtio net
	 * driver (virtio_net.c) supports, thus it's not possible for them
	 * to invoke rte_vhost_driver_set_features(). To workaround it, here
	 * we set it unconditionally. If the application want to implement
	 * another vhost-user driver (say SCSI), it should call the
	 * rte_vhost_driver_set_features(), which will overwrite following
	 * two values.
	 */
	vsocket->use_builtin_virtio_net = true;
	vsocket->supported_features = VIRTIO_NET_SUPPORTED_FEATURES;
	vsocket->features           = VIRTIO_NET_SUPPORTED_FEATURES;
	vsocket->protocol_features  = VHOST_USER_PROTOCOL_FEATURES;

	if (vsocket->async_copy) {
		vsocket->supported_features &= ~(1ULL << VHOST_F_LOG_ALL);
		vsocket->features &= ~(1ULL << VHOST_F_LOG_ALL);
		VHOST_LOG_CONFIG(INFO, "(%s) logging feature is disabled in async copy mode\n",
				path);
	}

	/*
	 * We'll not be able to receive a buffer from guest in linear mode
	 * without external buffer if it will not fit in a single mbuf, which is
	 * likely if segmentation offloading enabled.
	 */
	if (vsocket->linearbuf && !vsocket->extbuf) {
		uint64_t seg_offload_features =
				(1ULL << VIRTIO_NET_F_HOST_TSO4) |
				(1ULL << VIRTIO_NET_F_HOST_TSO6) |
				(1ULL << VIRTIO_NET_F_HOST_UFO);

		VHOST_LOG_CONFIG(INFO, "(%s) Linear buffers requested without external buffers,\n",
				path);
		VHOST_LOG_CONFIG(INFO, "(%s) disabling host segmentation offloading support\n",
				path);
		vsocket->supported_features &= ~seg_offload_features;
		vsocket->features &= ~seg_offload_features;
	}

	if (!(flags & RTE_VHOST_USER_IOMMU_SUPPORT)) {
		vsocket->supported_features &= ~(1ULL << VIRTIO_F_IOMMU_PLATFORM);
		vsocket->features &= ~(1ULL << VIRTIO_F_IOMMU_PLATFORM);
	}

	if (!(flags & RTE_VHOST_USER_POSTCOPY_SUPPORT)) {
		vsocket->protocol_features &=
			~(1ULL << VHOST_USER_PROTOCOL_F_PAGEFAULT);
	} else {
#ifndef RTE_LIBRTE_VHOST_POSTCOPY
		VHOST_LOG_CONFIG(ERR, "(%s) Postcopy requested but not compiled\n", path);
		ret = -1;
		goto out_free;
#endif
	}

	if ((flags & RTE_VHOST_USER_CLIENT) != 0) {
		vsocket->reconnect = !(flags & RTE_VHOST_USER_NO_RECONNECT);
		if (vsocket->reconnect && reconn_tid == 0) {
			if (vhost_user_reconnect_init() != 0)
				goto out_free;
		}
	} else {
		vsocket->is_server = true;
	}
	ret = trans_ops->socket_init(vsocket, flags);
	if (ret < 0) {
		goto out_free;
	}

	vhost_user.vsockets[vhost_user.vsocket_cnt++] = vsocket;

	pthread_mutex_unlock(&vhost_user.mutex);
	return ret;

out_free:
	vhost_user_socket_mem_free(vsocket);
out:
	pthread_mutex_unlock(&vhost_user.mutex);

	return ret;
}

/**
 * Unregister the specified vhost socket
 */
int
rte_vhost_driver_unregister(const char *path)
{
	int i;
	int count;

	if (path == NULL)
		return -1;

	pthread_mutex_lock(&vhost_user.mutex);

	for (i = 0; i < vhost_user.vsocket_cnt; i++) {
		struct vhost_user_socket *vsocket = vhost_user.vsockets[i];
		if (strcmp(vsocket->path, path))
			continue;

		vsocket->trans_ops->socket_cleanup(vsocket);

		vhost_user_socket_mem_free(vsocket);
		count = --vhost_user.vsocket_cnt;
		vhost_user.vsockets[i] = vhost_user.vsockets[count];
		vhost_user.vsockets[count] = NULL;
		pthread_mutex_unlock(&vhost_user.mutex);
		return 0;
	}
	pthread_mutex_unlock(&vhost_user.mutex);

	return -1;
}

/*
 * Register ops so that we can add/remove device to data core.
 */
int
rte_vhost_driver_callback_register(const char *path,
	struct rte_vhost_device_ops const * const ops)
{
	struct vhost_user_socket *vsocket;

	pthread_mutex_lock(&vhost_user.mutex);
	vsocket = find_vhost_user_socket(path);
	if (vsocket)
		vsocket->notify_ops = ops;
	pthread_mutex_unlock(&vhost_user.mutex);

	return vsocket ? 0 : -1;
}

struct rte_vhost_device_ops const *
vhost_driver_callback_get(const char *path)
{
	struct vhost_user_socket *vsocket;

	pthread_mutex_lock(&vhost_user.mutex);
	vsocket = find_vhost_user_socket(path);
	pthread_mutex_unlock(&vhost_user.mutex);

	return vsocket ? vsocket->notify_ops : NULL;
}

int
rte_vhost_driver_start(const char *path)
{
	struct vhost_user_socket *vsocket;
	static pthread_t fdset_tid;

	pthread_mutex_lock(&vhost_user.mutex);
	vsocket = find_vhost_user_socket(path);
	pthread_mutex_unlock(&vhost_user.mutex);

	if (!vsocket)
		return -1;

	if (fdset_tid == 0) {
		/**
		 * create a pipe which will be waited by poll and notified to
		 * rebuild the wait list of poll.
		 */
		if (fdset_pipe_init(&vhost_user.fdset) < 0) {
			VHOST_LOG_CONFIG(ERR, "(%s) failed to create pipe for vhost fdset\n", path);
			return -1;
		}

		int ret = rte_ctrl_thread_create(&fdset_tid,
			"vhost-events", NULL, fdset_event_dispatch,
			&vhost_user.fdset);
		if (ret != 0) {
			VHOST_LOG_CONFIG(ERR, "(%s) failed to create fdset handling thread", path);

			fdset_pipe_uninit(&vhost_user.fdset);
			return -1;
		}
	}

	return vsocket->trans_ops->socket_start(vsocket);
}
