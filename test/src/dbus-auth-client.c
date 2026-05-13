/* Minimal D-Bus AUTH EXTERNAL client used by the libink smoke test.
 *
 * Usage: dbus-auth-client <socket-path> <claimed-uid>
 *
 *   exit 0 — server reply began with "OK "
 *   exit 1 — server reply began with "REJECTED " (the expected denial)
 *   exit 2 — any other reply, short read, or transport error
 *
 * Copyright (c) 2026  Joachim Wiberg <troglobit@gmail.com>
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static const char hex[] = "0123456789abcdef";

static int write_all(int fd, const void *buf, size_t len)
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

/* Read until '\n' or buffer-full.  Returns line length excluding any
 * trailing CR/LF, -1 on transport error / EOF / overflow. */
static ssize_t read_line(int fd, char *buf, size_t bufsz)
{
	size_t off = 0;

	while (off + 1 < bufsz) {
		ssize_t n = read(fd, buf + off, 1);

		if (n == 0)
			return -1;
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (buf[off] == '\n') {
			buf[off] = '\0';
			if (off > 0 && buf[off - 1] == '\r')
				buf[--off] = '\0';
			return (ssize_t)off;
		}
		off++;
	}
	return -1;
}

int main(int argc, char *argv[])
{
	struct sockaddr_un sun = { .sun_family = AF_UNIX };
	char hexuid[32];
	char line[64];
	char reply[256];
	const char *path, *claimed;
	size_t i, claimed_len, plen;
	int fd, rc;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <socket-path> <claimed-uid>\n", argv[0]);
		return 2;
	}
	path    = argv[1];
	claimed = argv[2];

	plen = strlen(path);
	if (plen >= sizeof(sun.sun_path)) {
		fprintf(stderr, "%s: path too long\n", argv[0]);
		return 2;
	}

	claimed_len = strlen(claimed);
	if (claimed_len * 2 >= sizeof(hexuid)) {
		fprintf(stderr, "%s: uid too long\n", argv[0]);
		return 2;
	}
	for (i = 0; i < claimed_len; i++) {
		unsigned c = (unsigned char)claimed[i];

		hexuid[i * 2]     = hex[c >> 4];
		hexuid[i * 2 + 1] = hex[c & 0xf];
	}
	hexuid[claimed_len * 2] = '\0';

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return 2;
	}

	memcpy(sun.sun_path, path, plen + 1);
	if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		perror("connect");
		close(fd);
		return 2;
	}

	if (write_all(fd, "\0", 1) < 0) {
		perror("write");
		close(fd);
		return 2;
	}

	rc = snprintf(line, sizeof(line), "AUTH EXTERNAL %s\r\n", hexuid);
	if (rc < 0 || (size_t)rc >= sizeof(line)) {
		fprintf(stderr, "%s: auth line too long\n", argv[0]);
		close(fd);
		return 2;
	}
	if (write_all(fd, line, (size_t)rc) < 0) {
		perror("write");
		close(fd);
		return 2;
	}

	if (read_line(fd, reply, sizeof(reply)) < 0) {
		fprintf(stderr, "%s: short read or oversized reply\n", argv[0]);
		close(fd);
		return 2;
	}

	printf("%s\n", reply);
	close(fd);

	if (strncmp(reply, "OK ", 3) == 0)
		return 0;
	if (strncmp(reply, "REJECTED ", 9) == 0)
		return 1;
	return 2;
}
