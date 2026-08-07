/* libink — per-connection lifecycle and dispatch entry point
 *
 * Copyright (c) 2026  Joachim Wiberg <troglobit@gmail.com>
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "internal.h"

int link_connection_get_fd(const link_connection_t *conn)
{
	return conn ? conn->fd : -1;
}

uid_t link_connection_get_uid(const link_connection_t *conn)
{
	return conn ? conn->peer_uid : (uid_t)-1;
}

/* Issue a method call and remember the serial so the reply can be
 * handed back to `cb` when the read loop picks it up.  Nothing here
 * waits: this is the counterpart of link_client_call() for a
 * connection already owned by the event loop. */
int link_connection_call(link_connection_t *conn, const char *destination,
			 const char *path, const char *interface, const char *member,
			 link_reply_cb_t cb, void *userdata,
			 const char *signature, ...)
{
	uint8_t  body[LINK_CALL_BODY_MAX];
	uint8_t  hdr[LINK_CALL_HDR_MAX];
	ssize_t  blen = 0;
	ssize_t  hlen;
	uint32_t serial;
	int      i;

	if (!conn || conn->fd < 0 || !path || !member) {
		errno = EINVAL;
		return -1;
	}

	for (i = 0; i < LINK_PENDING_CAP; i++) {
		if (!conn->pending[i].used)
			break;
	}
	if (i == LINK_PENDING_CAP) {
		errno = EBUSY;
		return -1;
	}

	if (signature && *signature) {
		va_list ap;

		va_start(ap, signature);
		blen = __marshal_va(body, sizeof(body), signature, ap);
		va_end(ap);
		if (blen < 0) {
			errno = EMSGSIZE;
			return -1;
		}
	}

	serial = ++conn->next_serial;
	hlen = __msg_build_method_call(hdr, sizeof(hdr), serial, path, interface,
				       member, destination, signature, (uint32_t)blen);
	if (hlen < 0) {
		errno = EMSGSIZE;
		return -1;
	}

	if (__io_write_all(conn->fd, hdr, (size_t)hlen) < 0)
		return -1;
	if (blen > 0 && __io_write_all(conn->fd, body, (size_t)blen) < 0)
		return -1;


	conn->pending[i].used     = 1;
	conn->pending[i].serial   = serial;
	conn->pending[i].cb       = cb;
	conn->pending[i].userdata = userdata;

	return 0;
}

void link_connection_close(link_connection_t *conn)
{
	size_t i;

	if (!conn)
		return;


	/* Anything waiting on this connection has to be told, or a parked
	 * call sits forever and its caller never hears back. */
	__dispatch_forget_conn(conn);

	for (i = 0; i < conn->matches_count; i++)
		__match_free(conn->matches[i]);

	if (conn->fd >= 0)
		close(conn->fd);
	free(conn);
}

/* Process buffered binary D-Bus messages, dispatching each complete
 * message and shifting consumed bytes out of rxbuf.  Returns -1 if
 * we should drop the connection (peer closed, protocol error,
 * downstream send failure). */
static int process_binary(link_connection_t *conn)
{
	while (conn->rxlen > 0) {
		struct link_msg msg;
		ssize_t        consumed;

		consumed = __msg_parse(conn->rxbuf, conn->rxlen, &msg);
		if (consumed == 0)
			break;	/* incomplete; wait for more bytes */
		if (consumed < 0)
			return -1;

		if (__dispatch_message(conn, &msg, (size_t)consumed) < 0)
			return -1;

		memmove(conn->rxbuf, conn->rxbuf + consumed,
			conn->rxlen - (size_t)consumed);
		conn->rxlen -= (size_t)consumed;
	}
	return 0;
}

int link_connection_process(link_connection_t *conn)
{
	if (!conn) {
		errno = EINVAL;
		return -1;
	}

	if (conn->auth == LINK_AUTH_FAILED)
		return -1;

	if (conn->auth != LINK_AUTH_DONE) {
		if (__auth_process(conn) < 0)
			return -1;

		/* Still in SASL phase — wait for more bytes. */
		if (conn->auth != LINK_AUTH_DONE)
			return 0;

		/* Fall through: BEGIN may have arrived in the same read
		 * as the first binary message.  auth_process moved those
		 * bytes into rxbuf; they must be dispatched now, because
		 * no further wake-up is guaranteed (the kernel has
		 * already delivered everything that was readable). */
		if (process_binary(conn) < 0)
			return -1;
	}

	/* Read additional bytes and dispatch any complete messages.
	 * process_binary is called inside the loop after every
	 * successful read; no second call after EAGAIN because the
	 * buffer hasn't changed. */
	for (;;) {
		ssize_t n;
		size_t  room = sizeof(conn->rxbuf) - conn->rxlen;

		if (room == 0) {
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
				return 0;
			return -1;
		}
		conn->rxlen += (size_t)n;
		if (process_binary(conn) < 0)
			return -1;
	}
}
