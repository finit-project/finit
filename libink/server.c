/* libink — listening socket, accept, peer-credential capture
 *
 * Copyright (c) 2026  Joachim Wiberg <troglobit@gmail.com>
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "internal.h"

static void close_save_errno(int fd)
{
	int saved = errno;
	close(fd);
	errno = saved;
}

int link_server_new(link_server_t **out, const char *path)
{
	struct sockaddr_un sun = { .sun_family = AF_UNIX };
	link_server_t *srv;
	size_t plen;
	int fd;

	if (!out || !path || !*path) {
		errno = EINVAL;
		return -1;
	}

	plen = strlen(path);
	if (plen >= sizeof(sun.sun_path) || plen >= LINK_PATH_MAX) {
		errno = ENAMETOOLONG;
		return -1;
	}

	srv = calloc(1, sizeof(*srv));
	if (!srv)
		return -1;
	TAILQ_INIT(&srv->objects);

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0)
		goto err_free;

	memcpy(sun.sun_path, path, plen + 1);

	(void)unlink(path);

	/* fchmod() on a Unix-domain socket fd is a silent no-op on Linux:
	 * the file mode is fixed at bind() time as (0777 & ~umask).  Set
	 * umask around the bind() so the socket appears with mode 0666
	 * atomically, no race window.  World-accessible by design;
	 * per-method authorization happens later in dispatch via
	 * SO_PEERCRED. */
	{
		mode_t oldmask = umask(0111);
		int    rc      = bind(fd, (struct sockaddr *)&sun, sizeof(sun));
		int    saved   = errno;

		umask(oldmask);
		if (rc < 0) {
			errno = saved;
			goto err_close;
		}
	}

	if (listen(fd, 16) < 0)
		goto err_unlink;

	srv->fd = fd;
	memcpy(srv->path, path, plen + 1);
	*out = srv;
	return 0;

err_unlink:
	(void)unlink(path);
err_close:
	close_save_errno(fd);
err_free:
	free(srv);
	return -1;
}

void link_server_free(link_server_t *srv)
{
	struct link_object *o;

	if (!srv)
		return;

	o = TAILQ_FIRST(&srv->objects);
	while (o) {
		struct link_object       *next_o = TAILQ_NEXT(o, link);
		struct link_vtable_entry *e      = TAILQ_FIRST(&o->vtables);

		while (e) {
			struct link_vtable_entry *next_e = TAILQ_NEXT(e, link);

			free(e);
			e = next_e;
		}
		free(o);
		o = next_o;
	}

	if (srv->fd >= 0)
		close(srv->fd);
	if (srv->path[0])
		(void)unlink(srv->path);
	free(srv);
}

int link_server_get_fd(const link_server_t *srv)
{
	if (!srv)
		return -1;

	return srv->fd;
}

int link_server_accept(link_server_t *srv, link_connection_t **out)
{
	struct ucred cred = { 0 };
	socklen_t credlen = sizeof(cred);
	link_connection_t *conn;
	int cfd;

	if (!srv || !out) {
		errno = EINVAL;
		return -1;
	}

	cfd = accept4(srv->fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (cfd < 0)
		return -1;

	conn = calloc(1, sizeof(*conn));
	if (!conn) {
		close_save_errno(cfd);
		return -1;
	}

	conn->fd     = cfd;
	conn->auth   = LINK_AUTH_NUL;
	conn->server = srv;

	if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cred, &credlen) == 0)
		conn->peer_uid = cred.uid;
	else
		conn->peer_uid = (uid_t)-1;

	__auth_generate_guid(conn->guid);

	*out = conn;
	return 0;
}

link_connection_t *link_server_attach(link_server_t *srv, int fd, uid_t peer_uid)
{
	link_connection_t *conn;
	int flags;

	/* On entry we always own `fd` -- close it on every failure path
	 * so callers don't have to track whether we touched fcntl state. */
	if (!srv || fd < 0) {
		if (fd >= 0)
			close_save_errno(fd);
		errno = EINVAL;
		return NULL;
	}

	/* Match server_accept's fd setup: CLOEXEC first (so a fork-and-
	 * exec between the two calls cannot leak the fd), then NONBLOCK
	 * so process_binary's read loop can drain without hanging. */
	flags = fcntl(fd, F_GETFD, 0);
	if (flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0)
		goto err_close;
	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
		goto err_close;

	conn = calloc(1, sizeof(*conn));
	if (!conn)
		goto err_close;

	conn->fd       = fd;
	conn->auth     = LINK_AUTH_DONE;	/* caller already handshook */
	conn->server   = srv;
	conn->peer_uid = peer_uid;
	__auth_generate_guid(conn->guid);

	return conn;

err_close:
	close_save_errno(fd);
	return NULL;
}
