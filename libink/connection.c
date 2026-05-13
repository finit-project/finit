/* libink — per-connection lifecycle and dispatch entry point
 *
 * Copyright (c) 2026  Joachim Wiberg <troglobit@gmail.com>
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <stdlib.h>
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

int ink_connection_process(ink_connection_t *conn)
{
	if (!conn) {
		errno = EINVAL;
		return -1;
	}

	if (conn->auth == INK_AUTH_FAILED)
		return -1;

	return ink__auth_process(conn);
}
