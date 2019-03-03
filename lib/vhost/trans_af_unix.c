/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2018 Intel Corporation
 * Copyright(c) 2017 Red Hat, Inc.
 * Copyright(c) 2019 Arrikto Inc.
 * Copyright(c) 2022 Bytedance Inc.
 */

#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>

#include <rte_log.h>

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
int
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

	ret = vhost_user_msg_handler(conn->device.vid, connfd, &ctx);
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

	if (conn->slave_req_fd >= 0) {
		close(conn->slave_req_fd);
		conn->slave_req_fd = -1;
	}
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
};
