/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2018 Intel Corporation
 * Copyright(c) 2017 Red Hat, Inc.
 * Copyright(c) 2019 Arrikto Inc.
 * Copyright(c) 2022 Bytedance Inc.
 */

#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#ifdef RTE_LIBRTE_VHOST_POSTCOPY
#include <linux/userfaultfd.h>
#endif
#include <fcntl.h>

#include <rte_errno.h>
#include <rte_log.h>
#include <rte_vfio.h>

#include "fd_man.h"
#include "vhost.h"
#include "vhost_user.h"

#define MAX_VIRTIO_BACKLOG 128

static struct fdset af_unix_fdset = {
	.fd = { [0 ... MAX_FDS - 1] = {-1, NULL, NULL, NULL, 0} },
	.fd_mutex = PTHREAD_MUTEX_INITIALIZER,
	.fd_pooling_mutex = PTHREAD_MUTEX_INITIALIZER,
	.num = 0
};

TAILQ_HEAD(vhost_user_connection_list, vhost_user_connection);

struct vhost_user_connection {
	struct virtio_net device; /* must be the first field! */
	struct vhost_user_socket *vsocket;
	int connfd;
	int slave_req_fd;
	rte_spinlock_t slave_req_lock;

	int postcopy_ufd;
	int postcopy_listening;

	TAILQ_ENTRY(vhost_user_connection) next;
};

struct af_unix_socket {
	struct vhost_user_socket socket; /* must be the first field! */
	struct vhost_user_connection_list conn_list;
	pthread_mutex_t conn_mutex;
	int socket_fd;
	struct sockaddr_un un;
};

static int vhost_user_start_server(struct vhost_user_socket *vsocket);
static int vhost_user_start_client(struct vhost_user_socket *vsocket);
static int create_unix_socket(struct vhost_user_socket *vsocket);
static void vhost_user_read_cb(int connfd, void *dat, int *remove);
static int read_vhost_message(struct virtio_net *dev, int sockfd, struct vhu_msg_context *ctx);

/*
 * return bytes# of read on success or negative val on failure. Update fdnum
 * with number of fds read.
 */
static int
read_fd_message(char *ifname, int sockfd, char *buf, int buflen, int *fds, int max_fds,
		int *fd_num)
{
	struct iovec iov;
	struct msghdr msgh;
	char control[CMSG_SPACE(max_fds * sizeof(int))];
	struct cmsghdr *cmsg;
	int got_fds = 0;
	int ret;

	*fd_num = 0;

	memset(&msgh, 0, sizeof(msgh));
	iov.iov_base = buf;
	iov.iov_len  = buflen;

	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_control = control;
	msgh.msg_controllen = sizeof(control);

	ret = recvmsg(sockfd, &msgh, 0);
	if (ret <= 0) {
		if (ret)
			VHOST_LOG_CONFIG(ERR, "(%s) recvmsg failed on fd %d (%s)\n",
					ifname, sockfd, strerror(errno));
		return ret;
	}

	if (msgh.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
		VHOST_LOG_CONFIG(ERR, "(%s) truncated msg (fd %d)\n", ifname, sockfd);
		return -1;
	}

	for (cmsg = CMSG_FIRSTHDR(&msgh); cmsg != NULL;
		cmsg = CMSG_NXTHDR(&msgh, cmsg)) {
		if ((cmsg->cmsg_level == SOL_SOCKET) &&
			(cmsg->cmsg_type == SCM_RIGHTS)) {
			got_fds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
			*fd_num = got_fds;
			memcpy(fds, CMSG_DATA(cmsg), got_fds * sizeof(int));
			break;
		}
	}

	/* Clear out unused file descriptors */
	while (got_fds < max_fds)
		fds[got_fds++] = -1;

	return ret;
}
static int
send_fd_message(char *ifname, int sockfd, void *buf, int buflen, int *fds, int fd_num)
{

	struct iovec iov;
	struct msghdr msgh;
	size_t fdsize = fd_num * sizeof(int);
	char control[CMSG_SPACE(fdsize)];
	struct cmsghdr *cmsg;
	int ret;

	memset(&msgh, 0, sizeof(msgh));
	iov.iov_base = buf;
	iov.iov_len = buflen;

	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;

	if (fds && fd_num > 0) {
		msgh.msg_control = control;
		msgh.msg_controllen = sizeof(control);
		cmsg = CMSG_FIRSTHDR(&msgh);
		if (cmsg == NULL) {
			VHOST_LOG_CONFIG(ERR, "(%s) cmsg == NULL\n", ifname);
			errno = EINVAL;
			return -1;
		}
		cmsg->cmsg_len = CMSG_LEN(fdsize);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		memcpy(CMSG_DATA(cmsg), fds, fdsize);
	} else {
		msgh.msg_control = NULL;
		msgh.msg_controllen = 0;
	}

	do {
		ret = sendmsg(sockfd, &msgh, MSG_NOSIGNAL);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0) {
		VHOST_LOG_CONFIG(ERR, "(%s) sendmsg error on fd %d (%s)\n",
				ifname, sockfd, strerror(errno));
		return ret;
	}

	return ret;
}

static int
af_unix_send_reply(struct virtio_net *dev, struct vhu_msg_context *ctx)
{
	struct vhost_user_connection *conn =
		container_of(dev, struct vhost_user_connection, device);

	return send_fd_message(dev->ifname, conn->connfd, &ctx->msg,
			       VHOST_USER_HDR_SIZE + ctx->msg.size, ctx->fds, ctx->fd_num);
}

static int
af_unix_send_slave_req(struct virtio_net *dev, struct vhu_msg_context *ctx)
{
	struct vhost_user_connection *conn =
		container_of(dev, struct vhost_user_connection, device);
	int ret;

	if (ctx->msg.flags & VHOST_USER_NEED_REPLY)
		rte_spinlock_lock(&conn->slave_req_lock);

	ret = send_fd_message(dev->ifname, conn->slave_req_fd, &ctx->msg,
			       VHOST_USER_HDR_SIZE + ctx->msg.size, ctx->fds, ctx->fd_num);

	if (ret < 0 && (ctx->msg.flags & VHOST_USER_NEED_REPLY))
		rte_spinlock_unlock(&conn->slave_req_lock);

	return ret;
}

static int
af_unix_process_slave_message_reply(struct virtio_net *dev,
				    const struct vhu_msg_context *ctx)
{
	struct vhost_user_connection *conn =
		container_of(dev, struct vhost_user_connection, device);
	int ret;
	struct vhu_msg_context ctx_reply;

	if ((ctx->msg.flags & VHOST_USER_NEED_REPLY) == 0)
		return 0;

	ret = read_vhost_message(dev, conn->slave_req_fd, &ctx_reply) < 0;
	if (ret <= 0) {
		if (ret < 0)
			VHOST_LOG_CONFIG(ERR, "(%s) vhost read slave message reply failed\n",
					dev->ifname);
		else
			VHOST_LOG_CONFIG(INFO, "(%s) vhost peer closed\n", dev->ifname);
		ret = -1;
		goto out;
	}

	if (ctx_reply.msg.request.slave != ctx->msg.request.slave) {
		VHOST_LOG_CONFIG(ERR,
			"Received unexpected msg type (%u), expected %u\n",
			ctx_reply.msg.request.slave, ctx->msg.request.slave);
		ret = -1;
		goto out;
	}

	ret = ctx_reply.msg.payload.u64 ? -1 : 0;

out:
	rte_spinlock_unlock(&conn->slave_req_lock);
	return ret;
}

static int
af_unix_set_slave_req_fd(struct virtio_net *dev, struct vhu_msg_context *ctx)
{
	struct vhost_user_connection *conn =
		container_of(dev, struct vhost_user_connection, device);
	int fd = ctx->fds[0];

	if (fd < 0) {
		VHOST_LOG_CONFIG(ERR,
				"Invalid file descriptor for slave channel (%d)\n",
				fd);
		return -1;
	}

	if (conn->slave_req_fd >= 0)
		close(conn->slave_req_fd);

	conn->slave_req_fd = fd;

	return 0;
}

static void
vhost_user_add_connection(int fd, struct vhost_user_socket *vsocket)
{
	struct af_unix_socket *af_vsocket =
		container_of(vsocket, struct af_unix_socket, socket);
	size_t size;
	struct vhost_user_connection *conn;
	int ret;
	struct virtio_net *dev;

	if (vsocket == NULL)
		return;

	dev = vhost_new_device(vsocket->trans_ops);
	if (!dev)
		return;

	conn = container_of(dev, struct vhost_user_connection, device);
	conn->connfd = fd;
	conn->slave_req_fd = -1;
	conn->vsocket = vsocket;
	rte_spinlock_init(&conn->slave_req_lock);
	conn->postcopy_ufd = -1;

	size = strnlen(vsocket->path, PATH_MAX);
	vhost_set_ifname(dev->vid, vsocket->path, size);

	vhost_setup_virtio_net(dev->vid, vsocket->use_builtin_virtio_net,
		vsocket->net_compliant_ol_flags);

	vhost_attach_vdpa_device(dev->vid, vsocket->vdpa_dev);

	if (vsocket->extbuf)
		vhost_enable_extbuf(dev->vid);

	if (vsocket->linearbuf)
		vhost_enable_linearbuf(dev->vid);

	if (vsocket->async_copy) {
		dev = get_device(dev->vid);

		if (dev)
			dev->async_copy = 1;
	}

	VHOST_LOG_CONFIG(INFO, "(%s) new device, handle is %d\n", vsocket->path, dev->vid);

	if (vsocket->notify_ops->new_connection) {
		ret = vsocket->notify_ops->new_connection(dev->vid);
		if (ret < 0) {
			VHOST_LOG_CONFIG(ERR,
				"(%s) failed to add vhost user connection with fd %d\n",
				vsocket->path, fd);
			goto err;
		}
	}

	ret = fdset_add(&af_unix_fdset, fd, vhost_user_read_cb,
			NULL, conn);
	if (ret < 0) {
		VHOST_LOG_CONFIG(ERR, "(%s) failed to add fd %d into vhost server fdset\n",
			vsocket->path, fd);

		if (vsocket->notify_ops->destroy_connection)
			vsocket->notify_ops->destroy_connection(dev->vid);

		goto err;
	}

	pthread_mutex_lock(&af_vsocket->conn_mutex);
	TAILQ_INSERT_TAIL(&af_vsocket->conn_list, conn, next);
	pthread_mutex_unlock(&af_vsocket->conn_mutex);

	fdset_pipe_notify(&af_unix_fdset);
	return;

err:
	close(conn->connfd);
	vhost_destroy_device(dev->vid);
}

/* call back when there is new vhost-user connection from client  */
static void
vhost_user_server_new_connection(int fd, void *dat, int *remove __rte_unused)
{
	struct vhost_user_socket *vsocket = dat;

	fd = accept(fd, NULL, NULL);
	if (fd < 0)
		return;

	VHOST_LOG_CONFIG(INFO, "(%s) new vhost user connection is %d\n",
			vsocket->path, fd);
	vhost_user_add_connection(fd, vsocket);
}

/* return bytes# of read on success or negative val on failure. */
static int
read_vhost_message(struct virtio_net *dev, int sockfd, struct vhu_msg_context *ctx)
{
	int ret;

	ret = read_fd_message(dev->ifname, sockfd, (char *)&ctx->msg,
		VHOST_USER_HDR_SIZE, ctx->fds, VHOST_MEMORY_MAX_NREGIONS, &ctx->fd_num);
	if (ret <= 0) {
		return ret;
	} else if (ret != VHOST_USER_HDR_SIZE) {
		VHOST_LOG_CONFIG(ERR, "(%s) Unexpected header size read\n", dev->ifname);
		close_msg_fds(ctx);
		return -1;
	}

	if (ctx->msg.size) {
		if (ctx->msg.size > sizeof(ctx->msg.payload)) {
			VHOST_LOG_CONFIG(ERR, "(%s) invalid msg size: %d\n",
					dev->ifname, ctx->msg.size);
			return -1;
		}
		ret = read(sockfd, &ctx->msg.payload, ctx->msg.size);
		if (ret <= 0)
			return ret;
		if (ret != (int)ctx->msg.size) {
			VHOST_LOG_CONFIG(ERR, "(%s) read control message failed\n", dev->ifname);
			return -1;
		}
	}

	return ret;
}

static void
vhost_user_read_cb(int connfd, void *dat, int *remove)
{
	struct vhost_user_connection *conn = dat;
	struct vhost_user_socket *vsocket = conn->vsocket;
	struct af_unix_socket *af_vsocket =
		container_of(vsocket, struct af_unix_socket, socket);
	struct vhu_msg_context ctx;
	int ret;

	ret = read_vhost_message(&conn->device, connfd, &ctx);
	if (ret <= 0) {
		if (ret < 0)
			VHOST_LOG_CONFIG(ERR,
				"vhost read message failed\n");
		else
			VHOST_LOG_CONFIG(INFO,
				"vhost peer closed\n");
		goto err;
	}

	ret = vhost_user_msg_handler(conn->device.vid, &ctx);
	if (ret < 0) {
err:
		close(connfd);
		*remove = 1;

		if (vsocket->notify_ops->destroy_connection)
			vsocket->notify_ops->destroy_connection(conn->device.vid);

		if (vsocket->reconnect) {
			create_unix_socket(vsocket);
			vhost_user_start_client(vsocket);
		}

		pthread_mutex_lock(&af_vsocket->conn_mutex);
		TAILQ_REMOVE(&af_vsocket->conn_list, conn, next);
		pthread_mutex_unlock(&af_vsocket->conn_mutex);

		vhost_destroy_device(conn->device.vid);
	}
}

static int
create_unix_socket(struct vhost_user_socket *vsocket)
{
	struct af_unix_socket *af_vsocket =
		container_of(vsocket, struct af_unix_socket, socket);
	int fd;
	struct sockaddr_un *un = &af_vsocket->un;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;
	VHOST_LOG_CONFIG(INFO, "(%s) vhost-user %s: socket created, fd: %d\n",
		vsocket->path, vsocket->is_server ? "server" : "client", fd);

	if (!vsocket->is_server && fcntl(fd, F_SETFL, O_NONBLOCK)) {
		VHOST_LOG_CONFIG(ERR,
			"(%s) vhost-user: can't set nonblocking mode for socket, fd: %d (%s)\n",
			vsocket->path, fd, strerror(errno));
		close(fd);
		return -1;
	}

	memset(un, 0, sizeof(*un));
	un->sun_family = AF_UNIX;
	strncpy(un->sun_path, vsocket->path, sizeof(un->sun_path));
	un->sun_path[sizeof(un->sun_path) - 1] = '\0';

	af_vsocket->socket_fd = fd;
	return 0;
}

static int
vhost_user_start_server(struct vhost_user_socket *vsocket)
{
	struct af_unix_socket *af_vsocket =
		container_of(vsocket, struct af_unix_socket, socket);
	int ret;
	int fd = af_vsocket->socket_fd;
	const char *path = vsocket->path;

	/*
	 * bind () may fail if the socket file with the same name already
	 * exists. But the library obviously should not delete the file
	 * provided by the user, since we can not be sure that it is not
	 * being used by other applications. Moreover, many applications form
	 * socket names based on user input, which is prone to errors.
	 *
	 * The user must ensure that the socket does not exist before
	 * registering the vhost driver in server mode.
	 */
	ret = bind(fd, (struct sockaddr *)&af_vsocket->un, sizeof(af_vsocket->un));
	if (ret < 0) {
		VHOST_LOG_CONFIG(ERR, "(%s) failed to bind: %s; remove it and try again\n",
			path, strerror(errno));
		goto err;
	}
	VHOST_LOG_CONFIG(INFO, "(%s) binding succeeded\n", path);

	ret = listen(fd, MAX_VIRTIO_BACKLOG);
	if (ret < 0)
		goto err;

	ret = fdset_add(&af_unix_fdset, fd, vhost_user_server_new_connection,
		  NULL, vsocket);
	if (ret < 0) {
		VHOST_LOG_CONFIG(ERR,
			"(%s) failed to add listen fd %d to vhost server fdset\n",
			path, fd);
		goto err;
	}

	return 0;

err:
	close(fd);
	return -1;
}

struct vhost_user_reconnect {
	struct sockaddr_un un;
	int fd;
	struct vhost_user_socket *vsocket;

	TAILQ_ENTRY(vhost_user_reconnect) next;
};

TAILQ_HEAD(vhost_user_reconnect_tailq_list, vhost_user_reconnect);
struct vhost_user_reconnect_list {
	struct vhost_user_reconnect_tailq_list head;
	pthread_mutex_t mutex;
};

static struct vhost_user_reconnect_list reconn_list;
static pthread_t reconn_tid;

static int
vhost_user_connect_nonblock(char *path, int fd, struct sockaddr *un, size_t sz)
{
	int ret, flags;

	ret = connect(fd, un, sz);
	if (ret < 0 && errno != EISCONN)
		return -1;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		VHOST_LOG_CONFIG(ERR, "(%s) can't get flags for connfd %d (%s)\n",
				path, fd, strerror(errno));
		return -2;
	}
	if ((flags & O_NONBLOCK) && fcntl(fd, F_SETFL, flags & ~O_NONBLOCK)) {
		VHOST_LOG_CONFIG(ERR, "(%s) can't disable nonblocking on fd %d\n", path, fd);
		return -2;
	}
	return 0;
}

static void *
vhost_user_client_reconnect(void *arg __rte_unused)
{
	int ret;
	struct vhost_user_reconnect *reconn, *next;

	while (1) {
		pthread_mutex_lock(&reconn_list.mutex);

		/*
		 * An equal implementation of TAILQ_FOREACH_SAFE,
		 * which does not exist on all platforms.
		 */
		for (reconn = TAILQ_FIRST(&reconn_list.head);
		     reconn != NULL; reconn = next) {
			next = TAILQ_NEXT(reconn, next);

			ret = vhost_user_connect_nonblock(reconn->vsocket->path, reconn->fd,
						(struct sockaddr *)&reconn->un,
						sizeof(reconn->un));
			if (ret == -2) {
				close(reconn->fd);
				VHOST_LOG_CONFIG(ERR, "(%s) reconnection for fd %d failed\n",
					reconn->vsocket->path, reconn->fd);
				goto remove_fd;
			}
			if (ret == -1)
				continue;

			VHOST_LOG_CONFIG(INFO, "(%s) connected\n", reconn->vsocket->path);
			vhost_user_add_connection(reconn->fd, reconn->vsocket);
remove_fd:
			TAILQ_REMOVE(&reconn_list.head, reconn, next);
			free(reconn);
		}

		pthread_mutex_unlock(&reconn_list.mutex);
		sleep(1);
	}

	return NULL;
}

static int
vhost_user_reconnect_init(void)
{
	int ret;

	ret = pthread_mutex_init(&reconn_list.mutex, NULL);
	if (ret < 0) {
		VHOST_LOG_CONFIG(ERR, "%s: failed to initialize mutex", __func__);
		return ret;
	}
	TAILQ_INIT(&reconn_list.head);

	ret = rte_ctrl_thread_create(&reconn_tid, "vhost_reconn", NULL,
			     vhost_user_client_reconnect, NULL);
	if (ret != 0) {
		VHOST_LOG_CONFIG(ERR, "failed to create reconnect thread");
		if (pthread_mutex_destroy(&reconn_list.mutex))
			VHOST_LOG_CONFIG(ERR, "%s: failed to destroy reconnect mutex", __func__);
	}

	return ret;
}

static int
vhost_user_start_client(struct vhost_user_socket *vsocket)
{
	struct af_unix_socket *af_vsocket =
		container_of(vsocket, struct af_unix_socket, socket);
	int ret;
	int fd = af_vsocket->socket_fd;
	const char *path = vsocket->path;
	struct vhost_user_reconnect *reconn;

	ret = vhost_user_connect_nonblock(vsocket->path, fd, (struct sockaddr *)&af_vsocket->un,
					  sizeof(af_vsocket->un));
	if (ret == 0) {
		vhost_user_add_connection(fd, vsocket);
		return 0;
	}

	VHOST_LOG_CONFIG(WARNING, "(%s) failed to connect: %s\n", path, strerror(errno));

	if (ret == -2 || !vsocket->reconnect) {
		close(fd);
		return -1;
	}

	VHOST_LOG_CONFIG(INFO, "(%s) reconnecting...\n", path);
	reconn = malloc(sizeof(*reconn));
	if (reconn == NULL) {
		VHOST_LOG_CONFIG(ERR, "(%s) failed to allocate memory for reconnect\n", path);
		close(fd);
		return -1;
	}
	reconn->un = af_vsocket->un;
	reconn->fd = fd;
	reconn->vsocket = vsocket;
	pthread_mutex_lock(&reconn_list.mutex);
	TAILQ_INSERT_TAIL(&reconn_list.head, reconn, next);
	pthread_mutex_unlock(&reconn_list.mutex);

	return 0;
}

bool
vhost_user_remove_reconnect(struct vhost_user_socket *vsocket)
{
	int found = false;
	struct vhost_user_reconnect *reconn, *next;

	pthread_mutex_lock(&reconn_list.mutex);

	for (reconn = TAILQ_FIRST(&reconn_list.head);
	     reconn != NULL; reconn = next) {
		next = TAILQ_NEXT(reconn, next);

		if (reconn->vsocket == vsocket) {
			TAILQ_REMOVE(&reconn_list.head, reconn, next);
			close(reconn->fd);
			free(reconn);
			found = true;
			break;
		}
	}
	pthread_mutex_unlock(&reconn_list.mutex);
	return found;
}

static int
af_unix_vring_call(struct virtio_net *dev __rte_unused,
		   struct vhost_virtqueue *vq)
{
	if (vq->callfd >= 0)
		eventfd_write(vq->callfd, (eventfd_t)1);
	return 0;
}

static uint64_t
get_blk_size(int fd)
{
	struct stat stat;
	int ret;

	ret = fstat(fd, &stat);
	return ret == -1 ? (uint64_t)-1 : (uint64_t)stat.st_blksize;
}

static void
async_dma_map(struct virtio_net *dev, bool do_map)
{
	int ret = 0;
	uint32_t i;
	struct guest_page *page;

	if (do_map) {
		for (i = 0; i < dev->nr_guest_pages; i++) {
			page = &dev->guest_pages[i];
			ret = rte_vfio_container_dma_map(RTE_VFIO_DEFAULT_CONTAINER_FD,
							 page->host_user_addr,
							 page->host_iova,
							 page->size);
			if (ret) {
				/*
				 * DMA device may bind with kernel driver, in this case,
				 * we don't need to program IOMMU manually. However, if no
				 * device is bound with vfio/uio in DPDK, and vfio kernel
				 * module is loaded, the API will still be called and return
				 * with ENODEV.
				 *
				 * DPDK vfio only returns ENODEV in very similar situations
				 * (vfio either unsupported, or supported but no devices found).
				 * Either way, no mappings could be performed. We treat it as
				 * normal case in async path. This is a workaround.
				 */
				if (rte_errno == ENODEV)
					return;

				/* DMA mapping errors won't stop VHOST_USER_SET_MEM_TABLE. */
				VHOST_LOG_CONFIG(ERR, "DMA engine map failed\n");
			}
		}

	} else {
		for (i = 0; i < dev->nr_guest_pages; i++) {
			page = &dev->guest_pages[i];
			ret = rte_vfio_container_dma_unmap(RTE_VFIO_DEFAULT_CONTAINER_FD,
							   page->host_user_addr,
							   page->host_iova,
							   page->size);
			if (ret) {
				/* like DMA map, ignore the kernel driver case when unmap. */
				if (rte_errno == EINVAL)
					return;

				VHOST_LOG_CONFIG(ERR, "DMA engine unmap failed\n");
			}
		}
	}
}

static int
vhost_user_mmap_region(struct virtio_net *dev,
		struct rte_vhost_mem_region *region,
		uint64_t mmap_offset)
{
	void *mmap_addr;
	uint64_t mmap_size;
	uint64_t alignment;
	int populate;

	/* Check for memory_size + mmap_offset overflow */
	if (mmap_offset >= -region->size) {
		VHOST_LOG_CONFIG(ERR, "(%s) mmap_offset (%#"PRIx64") and memory_size (%#"PRIx64") overflow\n",
				dev->ifname, mmap_offset, region->size);
		return -1;
	}

	mmap_size = region->size + mmap_offset;

	/* mmap() without flag of MAP_ANONYMOUS, should be called with length
	 * argument aligned with hugepagesz at older longterm version Linux,
	 * like 2.6.32 and 3.2.72, or mmap() will fail with EINVAL.
	 *
	 * To avoid failure, make sure in caller to keep length aligned.
	 */
	alignment = get_blk_size(region->fd);
	if (alignment == (uint64_t)-1) {
		VHOST_LOG_CONFIG(ERR, "(%s) couldn't get hugepage size through fstat\n",
				dev->ifname);
		return -1;
	}
	mmap_size = RTE_ALIGN_CEIL(mmap_size, alignment);
	if (mmap_size == 0) {
		/*
		 * It could happen if initial mmap_size + alignment overflows
		 * the sizeof uint64, which could happen if either mmap_size or
		 * alignment value is wrong.
		 *
		 * mmap() kernel implementation would return an error, but
		 * better catch it before and provide useful info in the logs.
		 */
		VHOST_LOG_CONFIG(ERR, "(%s) mmap size (0x%" PRIx64 ") or alignment (0x%" PRIx64 ") is invalid\n",
				dev->ifname, region->size + mmap_offset, alignment);
		return -1;
	}

	populate = dev->async_copy ? MAP_POPULATE : 0;
	mmap_addr = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE,
			MAP_SHARED | populate, region->fd, 0);

	if (mmap_addr == MAP_FAILED) {
		VHOST_LOG_CONFIG(ERR, "(%s) mmap failed (%s).\n", dev->ifname, strerror(errno));
		return -1;
	}

	region->mmap_addr = mmap_addr;
	region->mmap_size = mmap_size;
	region->host_user_addr = (uint64_t)(uintptr_t)mmap_addr + mmap_offset;

	if (dev->async_copy) {
		if (add_guest_pages(dev, region, alignment) < 0) {
			VHOST_LOG_CONFIG(ERR, "(%s) adding guest pages to region failed.\n",
					dev->ifname);
			return -1;
		}
	}

	VHOST_LOG_CONFIG(INFO, "(%s) guest memory region size: 0x%" PRIx64 "\n",
			dev->ifname, region->size);
	VHOST_LOG_CONFIG(INFO, "(%s)\t guest physical addr: 0x%" PRIx64 "\n",
			dev->ifname, region->guest_phys_addr);
	VHOST_LOG_CONFIG(INFO, "(%s)\t guest virtual  addr: 0x%" PRIx64 "\n",
			dev->ifname, region->guest_user_addr);
	VHOST_LOG_CONFIG(INFO, "(%s)\t host  virtual  addr: 0x%" PRIx64 "\n",
			dev->ifname, region->host_user_addr);
	VHOST_LOG_CONFIG(INFO, "(%s)\t mmap addr : 0x%" PRIx64 "\n",
			dev->ifname, (uint64_t)(uintptr_t)mmap_addr);
	VHOST_LOG_CONFIG(INFO, "(%s)\t mmap size : 0x%" PRIx64 "\n",
			dev->ifname, mmap_size);
	VHOST_LOG_CONFIG(INFO, "(%s)\t mmap align: 0x%" PRIx64 "\n",
			dev->ifname, alignment);
	VHOST_LOG_CONFIG(INFO, "(%s)\t mmap off  : 0x%" PRIx64 "\n",
			dev->ifname, mmap_offset);

	return 0;
}

#ifdef RTE_LIBRTE_VHOST_POSTCOPY
static int
vhost_user_postcopy_region_register(struct virtio_net *dev,
		struct rte_vhost_mem_region *reg)
{
	struct uffdio_register reg_struct;
	struct vhost_user_connection *conn =
		container_of(dev, struct vhost_user_connection, device);

	/*
	 * Let's register all the mmapped area to ensure
	 * alignment on page boundary.
	 */
	reg_struct.range.start = (uint64_t)(uintptr_t)reg->mmap_addr;
	reg_struct.range.len = reg->mmap_size;
	reg_struct.mode = UFFDIO_REGISTER_MODE_MISSING;

	if (ioctl(conn->postcopy_ufd, UFFDIO_REGISTER,
				&reg_struct)) {
		VHOST_LOG_CONFIG(ERR, "(%s) failed to register ufd for region "
				"%" PRIx64 " - %" PRIx64 " (ufd = %d) %s\n",
				dev->ifname,
				(uint64_t)reg_struct.range.start,
				(uint64_t)reg_struct.range.start +
				(uint64_t)reg_struct.range.len - 1,
				conn->postcopy_ufd,
				strerror(errno));
		return -1;
	}

	VHOST_LOG_CONFIG(INFO,
			"(%s)\t userfaultfd registered for range : %" PRIx64 " - %" PRIx64 "\n",
			dev->ifname,
			(uint64_t)reg_struct.range.start,
			(uint64_t)reg_struct.range.start +
			(uint64_t)reg_struct.range.len - 1);

	return 0;
}
#else
static int
vhost_user_postcopy_region_register(struct virtio_net *dev __rte_unused,
		struct rte_vhost_mem_region *reg __rte_unused)
{
	return -1;
}
#endif

static int
vhost_user_postcopy_register(struct virtio_net *dev, int main_fd,
		struct vhu_msg_context *ctx)
{
	struct VhostUserMemory *memory;
	struct rte_vhost_mem_region *reg;
	struct vhu_msg_context ack_ctx;
	uint32_t i;
	struct vhost_user_connection *conn =
		container_of(dev, struct vhost_user_connection, device);

	if (!conn->postcopy_listening)
		return 0;

	/*
	 * We haven't a better way right now than sharing
	 * DPDK's virtual address with Qemu, so that Qemu can
	 * retrieve the region offset when handling userfaults.
	 */
	memory = &ctx->msg.payload.memory;
	for (i = 0; i < memory->nregions; i++) {
		reg = &dev->mem->regions[i];
		memory->regions[i].userspace_addr = reg->host_user_addr;
	}

	/* Send the addresses back to qemu */
	ctx->fd_num = 0;
	/* Send reply */
	ctx->msg.flags &= ~VHOST_USER_VERSION_MASK;
	ctx->msg.flags &= ~VHOST_USER_NEED_REPLY;
	ctx->msg.flags |= VHOST_USER_VERSION;
	ctx->msg.flags |= VHOST_USER_REPLY_MASK;
	af_unix_send_reply(dev, ctx);

	/* Wait for qemu to acknowledge it got the addresses
	 * we've got to wait before we're allowed to generate faults.
	 */
	if (read_vhost_message(dev, main_fd, &ack_ctx) <= 0) {
		VHOST_LOG_CONFIG(ERR, "(%s) failed to read qemu ack on postcopy set-mem-table\n",
				dev->ifname);
		return -1;
	}

	if (validate_msg_fds(dev, &ack_ctx, 0) != 0)
		return -1;

	if (ack_ctx.msg.request.master != VHOST_USER_SET_MEM_TABLE) {
		VHOST_LOG_CONFIG(ERR, "(%s) bad qemu ack on postcopy set-mem-table (%d)\n",
				dev->ifname, ack_ctx.msg.request.master);
		return -1;
	}

	/* Now userfault register and we can use the memory */
	for (i = 0; i < memory->nregions; i++) {
		reg = &dev->mem->regions[i];
		if (vhost_user_postcopy_region_register(dev, reg) < 0)
			return -1;
	}

	return 0;
}

static int
af_unix_map_mem_regions(struct virtio_net *dev, struct vhu_msg_context *ctx)
{
	uint32_t i;
	struct vhost_user_connection *conn =
		container_of(dev, struct vhost_user_connection, device);

	for (i = 0; i < dev->mem->nregions; i++) {
		struct rte_vhost_mem_region *reg = &dev->mem->regions[i];
		uint64_t mmap_size = reg->mmap_size;
		uint64_t mmap_offset = mmap_size - reg->size;

		if (vhost_user_mmap_region(dev, reg, mmap_offset) < 0) {
			VHOST_LOG_CONFIG(ERR, "(%s) failed to mmap region %u\n", dev->ifname, i);
			return -1;
		}
	}

	if (dev->async_copy && rte_vfio_is_enabled("vfio"))
		async_dma_map(dev, true);

	if (vhost_user_postcopy_register(dev, conn->connfd, ctx) < 0)
		return -1;

	return 0;
}

static void
af_unix_unmap_mem_regions(struct virtio_net *dev)
{
	uint32_t i;
	struct rte_vhost_mem_region *reg;

	if (dev->async_copy && rte_vfio_is_enabled("vfio"))
		async_dma_map(dev, false);

	for (i = 0; i < dev->mem->nregions; i++) {
		reg = &dev->mem->regions[i];
		if (reg->host_user_addr) {
			munmap(reg->mmap_addr, reg->mmap_size);
			close(reg->fd);
		}
	}
}

static int
af_unix_socket_init(struct vhost_user_socket *vsocket,
		    uint64_t flags __rte_unused)
{
	struct af_unix_socket *af_vsocket =
		container_of(vsocket, struct af_unix_socket, socket);
	int ret;

	if (vsocket->reconnect && reconn_tid == 0) {
		if (vhost_user_reconnect_init() != 0)
			return -1;
	}

	TAILQ_INIT(&af_vsocket->conn_list);
	ret = pthread_mutex_init(&af_vsocket->conn_mutex, NULL);
	if (ret) {
		VHOST_LOG_CONFIG(ERR, "(%s) failed to init connection mutex\n", vsocket->path);
		return -1;
	}

	return create_unix_socket(vsocket);
}

static int
af_unix_socket_cleanup(struct vhost_user_socket *vsocket)
{
	struct af_unix_socket *af_vsocket =
		container_of(vsocket, struct af_unix_socket, socket);
	struct vhost_user_connection *conn, *next;

	if (vsocket->is_server) {
		/*
		 * If r/wcb is executing, release vhost_user's
		 * mutex lock, and try again since the r/wcb
		 * may use the mutex lock.
		 */
		if (fdset_try_del(&af_unix_fdset, af_vsocket->socket_fd) == -1) {
			return -1;
		}
	} else if (vsocket->reconnect) {
		vhost_user_remove_reconnect(vsocket);
	}

	pthread_mutex_lock(&af_vsocket->conn_mutex);
	for (conn = TAILQ_FIRST(&af_vsocket->conn_list);
			conn != NULL;
			conn = next) {
		next = TAILQ_NEXT(conn, next);

		/*
		 * If r/wcb is executing, release vsocket's
		 * conn_mutex and vhost_user's mutex locks, and
		 * try again since the r/wcb may use the
		 * conn_mutex and mutex locks.
		 */
		if (fdset_try_del(&af_unix_fdset,
					conn->connfd) == -1) {
			pthread_mutex_unlock(&af_vsocket->conn_mutex);
			return -1;
		}

		VHOST_LOG_CONFIG(INFO, "(%s) free connfd %d\n", vsocket->path, conn->connfd);
		close(conn->connfd);
		TAILQ_REMOVE(&af_vsocket->conn_list, conn, next);
		vhost_destroy_device(conn->device.vid);
	}
	pthread_mutex_unlock(&af_vsocket->conn_mutex);

	if (vsocket->is_server) {
		close(af_vsocket->socket_fd);
		unlink(vsocket->path);
	}

	pthread_mutex_destroy(&af_vsocket->conn_mutex);
	return 0;
}

static int
af_unix_socket_start(struct vhost_user_socket *vsocket)
{
	static pthread_t fdset_tid;

	if (fdset_tid == 0) {
		/**
		 * create a pipe which will be waited by poll and notified to
		 * rebuild the wait list of poll.
		 */
		if (fdset_pipe_init(&af_unix_fdset) < 0) {
			VHOST_LOG_CONFIG(ERR,
				"(%s) failed to create pipe for vhost fdset\n", vsocket->path);
			return -1;
		}

		int ret = rte_ctrl_thread_create(&fdset_tid,
			"vhost-events", NULL, fdset_event_dispatch,
			&af_unix_fdset);
		if (ret != 0) {
			VHOST_LOG_CONFIG(ERR,
				"(%s) failed to create fdset handling thread", vsocket->path);

			fdset_pipe_uninit(&af_unix_fdset);
			return -1;
		}
	}
	if (vsocket->is_server)
		return vhost_user_start_server(vsocket);
	else
		return vhost_user_start_client(vsocket);
}

static void
af_unix_cleanup_device(struct virtio_net *dev, int destroy __rte_unused)
{
	struct vhost_user_connection *conn =
		container_of(dev, struct vhost_user_connection, device);

	if (dev->log_addr) {
		munmap((void *)(uintptr_t)dev->log_addr, dev->log_size);
		dev->log_addr = 0;
	}

	if (conn->slave_req_fd >= 0) {
		close(conn->slave_req_fd);
		conn->slave_req_fd = -1;
	}

	if (conn->postcopy_ufd >= 0) {
		close(conn->postcopy_ufd);
		conn->postcopy_ufd = -1;
	}

	conn->postcopy_listening = 0;
}

static int
af_unix_set_log_base(struct virtio_net *dev, const struct vhu_msg_context *ctx)
{
	int fd = ctx->fds[0];
	uint64_t size, off;
	void *addr;

	size = ctx->msg.payload.log.mmap_size;
	off  = ctx->msg.payload.log.mmap_offset;

	/*
	 * mmap from 0 to workaround a hugepage mmap bug: mmap will
	 * fail when offset is not page size aligned.
	 */
	addr = mmap(0, size + off, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	if (addr == MAP_FAILED) {
		VHOST_LOG_CONFIG(ERR, "mmap log base failed!\n");
		return -1;
	}

	/*
	 * Free previously mapped log memory on occasionally
	 * multiple VHOST_USER_SET_LOG_BASE.
	 */
	if (dev->log_addr)
		munmap((void *)(uintptr_t)dev->log_addr, dev->log_size);

	dev->log_addr = (uint64_t)(uintptr_t)addr;
	dev->log_base = dev->log_addr + off;
	dev->log_size = size;

	return 0;
}

static int
af_unix_set_postcopy_advise(struct virtio_net *dev, struct vhu_msg_context *ctx)
{
	struct vhost_user_connection *conn =
		container_of(dev, struct vhost_user_connection, device);

#ifdef RTE_LIBRTE_VHOST_POSTCOPY
	struct uffdio_api api_struct;

	if (validate_msg_fds(dev, ctx, 0) != 0)
		return RTE_VHOST_MSG_RESULT_ERR;

	conn->postcopy_ufd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);

	if (conn->postcopy_ufd == -1) {
		VHOST_LOG_CONFIG(ERR, "(%s) userfaultfd not available: %s\n",
			dev->ifname, strerror(errno));
		return RTE_VHOST_MSG_RESULT_ERR;
	}
	api_struct.api = UFFD_API;
	api_struct.features = 0;
	if (ioctl(conn->postcopy_ufd, UFFDIO_API, &api_struct)) {
		VHOST_LOG_CONFIG(ERR, "(%s) UFFDIO_API ioctl failure: %s\n",
			dev->ifname, strerror(errno));
		close(conn->postcopy_ufd);
		conn->postcopy_ufd = -1;
		return RTE_VHOST_MSG_RESULT_ERR;
	}
	ctx->fds[0] = conn->postcopy_ufd;
	ctx->fd_num = 1;

	return RTE_VHOST_MSG_RESULT_REPLY;
#else
	conn->postcopy_ufd = -1;
	ctx->fd_num = 0;

	return RTE_VHOST_MSG_RESULT_ERR;
#endif
}

static int
af_unix_set_postcopy_listen(struct virtio_net *dev, struct vhu_msg_context *ctx)
{
	struct vhost_user_connection *conn =
		container_of(dev, struct vhost_user_connection, device);

	if (validate_msg_fds(dev, ctx, 0) != 0)
		return RTE_VHOST_MSG_RESULT_ERR;

	if (dev->mem && dev->mem->nregions) {
		VHOST_LOG_CONFIG(ERR, "(%s) regions already registered at postcopy-listen\n",
				dev->ifname);
		return RTE_VHOST_MSG_RESULT_ERR;
	}
	conn->postcopy_listening = 1;

	return RTE_VHOST_MSG_RESULT_OK;
}

static int
af_unix_set_postcopy_end(struct virtio_net *dev, struct vhu_msg_context *ctx)
{
	struct vhost_user_connection *conn =
		container_of(dev, struct vhost_user_connection, device);

	if (validate_msg_fds(dev, ctx, 0) != 0)
		return RTE_VHOST_MSG_RESULT_ERR;

	conn->postcopy_listening = 0;
	if (conn->postcopy_ufd >= 0) {
		close(conn->postcopy_ufd);
		conn->postcopy_ufd = -1;
	}

	ctx->msg.payload.u64 = 0;
	ctx->msg.size = sizeof(ctx->msg.payload.u64);
	ctx->fd_num = 0;

	return RTE_VHOST_MSG_RESULT_REPLY;
}

const struct vhost_transport_ops af_unix_trans_ops = {
	.socket_size = sizeof(struct af_unix_socket),
	.device_size = sizeof(struct vhost_user_connection),
	.socket_start = af_unix_socket_start,
	.cleanup_device = af_unix_cleanup_device,
	.socket_init = af_unix_socket_init,
	.socket_cleanup = af_unix_socket_cleanup,
	.vring_call = af_unix_vring_call,
	.send_reply = af_unix_send_reply,
	.send_slave_req = af_unix_send_slave_req,
	.process_slave_message_reply = af_unix_process_slave_message_reply,
	.set_slave_req_fd = af_unix_set_slave_req_fd,
	.map_mem_regions = af_unix_map_mem_regions,
	.unmap_mem_regions = af_unix_unmap_mem_regions,
	.set_log_base = af_unix_set_log_base,
	.set_postcopy_advise = af_unix_set_postcopy_advise,
	.set_postcopy_listen = af_unix_set_postcopy_listen,
	.set_postcopy_end = af_unix_set_postcopy_end,
};
