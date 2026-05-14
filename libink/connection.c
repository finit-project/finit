/* libink — per-connection lifecycle and dispatch entry point
 *
 * Copyright (c) 2026  Joachim Wiberg <troglobit@gmail.com>
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ink-internal.h"

int ink_connection_get_fd(const ink_connection_t *conn)
{
	return conn ? conn->fd : -1;
}

uid_t ink_connection_get_uid(const ink_connection_t *conn)
{
	return conn ? conn->peer_uid : (uid_t)-1;
}

void ink_connection_close(ink_connection_t *conn)
{
	if (!conn)
		return;

	if (conn->fd >= 0)
		close(conn->fd);
	free(conn);
}

/* Process buffered binary D-Bus messages, dispatching each complete
 * message and shifting consumed bytes out of rxbuf.  Returns -1 if
 * we should drop the connection (peer closed, protocol error,
 * downstream send failure). */
static int process_binary(ink_connection_t *conn)
{
	while (conn->rxlen > 0) {
		struct ink_msg msg;
		ssize_t        consumed;

		consumed = ink__msg_parse(conn->rxbuf, conn->rxlen, &msg);
		if (consumed == 0)
			break;	/* incomplete; wait for more bytes */
		if (consumed < 0)
			return -1;

		if (ink__dispatch_message(conn, &msg) < 0)
			return -1;

		memmove(conn->rxbuf, conn->rxbuf + consumed,
			conn->rxlen - (size_t)consumed);
		conn->rxlen -= (size_t)consumed;
	}
	return 0;
}

int ink_connection_process(ink_connection_t *conn)
{
	if (!conn) {
		errno = EINVAL;
		return -1;
	}

	if (conn->auth == INK_AUTH_FAILED)
		return -1;

	if (conn->auth != INK_AUTH_DONE)
		return ink__auth_process(conn);

	/* Authenticated: read into rxbuf and dispatch any complete messages. */
	for (;;) {
		ssize_t n;
		size_t  room = sizeof(conn->rxbuf) - conn->rxlen;

		if (room == 0) {
			/* Pathological message size; drop the peer. */
			errno = E2BIG;
			return -1;
		}

		n = read(conn->fd, conn->rxbuf + conn->rxlen, room);
		if (n == 0)
			return -1;	/* peer closed */
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			return -1;
		}
		conn->rxlen += (size_t)n;
		if (process_binary(conn) < 0)
			return -1;
		/* Loop again — there may be more readable bytes. */
	}

	return process_binary(conn);
}
