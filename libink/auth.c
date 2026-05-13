/* libink — D-Bus AUTH EXTERNAL handshake
 *
 * Implements the line-based SASL-style exchange described in the
 * D-Bus specification, section "Authentication Protocol".  Only the
 * AUTH EXTERNAL mechanism is offered; everything else is rejected.
 *
 * The exchange:
 *
 *   client  --> [nul byte]
 *   client  --> "AUTH EXTERNAL <hex-uid>\r\n"
 *   server  <-- "OK <hex-guid>\r\n"
 *   client  --> "NEGOTIATE_UNIX_FD\r\n"           [optional]
 *   server  <-- "ERROR <reason>\r\n"              (no fd-passing yet)
 *   client  --> "BEGIN\r\n"
 *
 * Copyright (c) 2026  Joachim Wiberg <troglobit@gmail.com>
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

#include "ink-internal.h"

static const char rejected_ext[] = "REJECTED EXTERNAL\r\n";

static int write_all(int fd, const char *buf, size_t len)
{
	while (len > 0) {
		ssize_t n = write(fd, buf, len);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		buf += n;
		len -= (size_t)n;
	}
	return 0;
}

static int reply(int fd, const char *line)
{
	return write_all(fd, line, strlen(line));
}

static int reject(ink_connection_t *conn)
{
	return write_all(conn->fd, rejected_ext, sizeof(rejected_ext) - 1);
}

void ink__auth_generate_guid(char out[33])
{
	static const char hex[] = "0123456789abcdef";
	uint8_t raw[16];
	size_t i;

	if (getrandom(raw, sizeof(raw), 0) != (ssize_t)sizeof(raw)) {
		/* Extraordinarily unlikely; GUID is informational, not a
		 * security primitive — fall back to something deterministic
		 * rather than uninitialized memory. */
		for (i = 0; i < sizeof(raw); i++)
			raw[i] = (uint8_t)(i ^ 0xa5);
	}

	for (i = 0; i < sizeof(raw); i++) {
		out[i * 2]     = hex[raw[i] >> 4];
		out[i * 2 + 1] = hex[raw[i] & 0xf];
	}
	out[32] = '\0';
}

static int hexval(int c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

/* Parse "AUTH EXTERNAL <hex>" payload into a uid.  The argument is
 * an even-length hex string whose decoded form is a decimal uid in
 * ASCII.  Returns 0 on success, -1 on malformed input. */
static int parse_external_uid(const char *arg, size_t arglen, uid_t *out)
{
	char decoded[24];
	char *ep = NULL;
	unsigned long v;
	size_t i, dlen;

	if (arglen == 0 || (arglen & 1) || arglen / 2 >= sizeof(decoded))
		return -1;

	dlen = arglen / 2;
	for (i = 0; i < dlen; i++) {
		int hi = hexval((unsigned char)arg[i * 2]);
		int lo = hexval((unsigned char)arg[i * 2 + 1]);

		if (hi < 0 || lo < 0)
			return -1;
		decoded[i] = (char)((hi << 4) | lo);
	}
	decoded[dlen] = '\0';

	errno = 0;
	v = strtoul(decoded, &ep, 10);
	if (errno || !ep || *ep != '\0' || v > (unsigned long)((uid_t)-1))
		return -1;

	*out = (uid_t)v;
	return 0;
}

static int handle_line(ink_connection_t *conn, const char *line, size_t len)
{
	if (len >= 14 && memcmp(line, "AUTH EXTERNAL ", 14) == 0) {
		uid_t claimed;
		char ok[64];

		if (parse_external_uid(line + 14, len - 14, &claimed) < 0)
			return reject(conn);
		if (conn->peer_uid == (uid_t)-1 || claimed != conn->peer_uid)
			return reject(conn);

		snprintf(ok, sizeof(ok), "OK %s\r\n", conn->guid);
		return reply(conn->fd, ok);
	}

	if (len == 4 && memcmp(line, "AUTH", 4) == 0)
		return reject(conn);

	if (len == 17 && memcmp(line, "NEGOTIATE_UNIX_FD", 17) == 0)
		return reply(conn->fd, "ERROR fd-passing not supported\r\n");

	if (len == 5 && memcmp(line, "BEGIN", 5) == 0) {
		conn->auth = INK_AUTH_DONE;
		return 0;
	}

	if (len == 6 && memcmp(line, "CANCEL", 6) == 0)
		return reject(conn);

	if (len >= 5 && memcmp(line, "ERROR", 5) == 0)
		return reject(conn);

	return reply(conn->fd, "ERROR Unknown command\r\n");
}

/* Pull one CR+LF-terminated line out of conn->linebuf.  Returns the
 * line length (without the CR+LF), or 0 if no complete line is
 * present yet.  Consumes the line on success. */
static size_t take_line(ink_connection_t *conn, char *out, size_t outsz)
{
	size_t i;

	for (i = 0; i + 1 < conn->linelen; i++) {
		if (conn->linebuf[i] == '\r' && conn->linebuf[i + 1] == '\n') {
			size_t linelen = i;
			size_t consumed = i + 2;

			if (linelen >= outsz)
				linelen = outsz - 1;

			memcpy(out, conn->linebuf, linelen);
			out[linelen] = '\0';

			memmove(conn->linebuf, conn->linebuf + consumed,
				conn->linelen - consumed);
			conn->linelen -= consumed;
			return linelen;
		}
	}
	return 0;
}

int ink__auth_process(ink_connection_t *conn)
{
	uint8_t buf[256];
	ssize_t n;
	size_t off = 0;

	n = read(conn->fd, buf, sizeof(buf));
	if (n == 0)
		return -1;	/* peer closed */
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			return 0;
		return -1;
	}

	if (conn->auth == INK_AUTH_NUL) {
		if (buf[0] != 0x00) {
			conn->auth = INK_AUTH_FAILED;
			return -1;
		}
		off = 1;
		conn->auth = INK_AUTH_LINE;
	}

	if (conn->auth == INK_AUTH_DONE) {
		/* Post-BEGIN bytes are discarded until the marshaller lands. */
		return 0;
	}

	if (conn->auth == INK_AUTH_LINE) {
		size_t take = (size_t)n - off;
		char line[INK_AUTH_LINEBUF_SIZE];
		size_t linelen;

		if (conn->linelen + take > sizeof(conn->linebuf)) {
			conn->auth = INK_AUTH_FAILED;
			return -1;
		}
		memcpy(conn->linebuf + conn->linelen, buf + off, take);
		conn->linelen += take;

		while ((linelen = take_line(conn, line, sizeof(line))) > 0) {
			if (handle_line(conn, line, linelen) < 0)
				return -1;
			if (conn->auth != INK_AUTH_LINE)
				break;
		}
	}

	return 0;
}
