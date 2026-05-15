/* libink — shared I/O helpers.
 *
 * Server send paths (libink/dispatch.c, libink/auth.c) and the
 * client (libink/client.c) all need EINTR-resilient write_all /
 * read_full.  On any other error they return -1 with an unknown
 * number of bytes already transferred.
 *
 * Copyright (c) 2026  Joachim Wiberg <troglobit@gmail.com>
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <unistd.h>

#include "internal.h"

int __io_write_all(int fd, const void *buf, size_t len)
{
	const char *p = buf;

	while (len > 0) {
		ssize_t n = write(fd, p, len);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		p   += n;
		len -= (size_t)n;
	}
	return 0;
}

int __io_read_full(int fd, void *buf, size_t len)
{
	char *p = buf;

	while (len > 0) {
		ssize_t n = read(fd, p, len);

		if (n == 0)
			return -1;
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		p   += n;
		len -= (size_t)n;
	}
	return 0;
}
