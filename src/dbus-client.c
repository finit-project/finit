/* Minimal D-Bus client for initctl.
 *
 * Copyright (c) 2026  Joachim Wiberg <troglobit@gmail.com>
 * SPDX-License-Identifier: MIT
 */

#include "config.h"

#ifdef HAVE_DBUS

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "dbus-client.h"

#define ALIGN_UP(x, n) (((x) + (n) - 1) & ~((size_t)((n) - 1)))

struct dbusc {
	int      fd;
	uint32_t next_serial;
};

static const char hex[] = "0123456789abcdef";

/* ---- transport helpers ---- */

static int write_all(int fd, const void *buf, size_t len)
{
	const char *p = buf;

	while (len > 0) {
		ssize_t n = write(fd, p, len);

		if (n < 0) {
			if (errno == EINTR) continue;
			return -1;
		}
		p   += n;
		len -= (size_t)n;
	}
	return 0;
}

static int read_full(int fd, void *buf, size_t len)
{
	char *p = buf;

	while (len > 0) {
		ssize_t n = read(fd, p, len);

		if (n == 0) return -1;
		if (n < 0) {
			if (errno == EINTR) continue;
			return -1;
		}
		p   += n;
		len -= (size_t)n;
	}
	return 0;
}

static ssize_t read_line(int fd, char *buf, size_t bufsz)
{
	size_t off = 0;

	while (off + 1 < bufsz) {
		ssize_t n = read(fd, buf + off, 1);

		if (n == 0) return -1;
		if (n < 0) {
			if (errno == EINTR) continue;
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

/* ---- SASL handshake ---- */

static int do_auth(int fd)
{
	char uidstr[16];
	char hexuid[32];
	char line[64];
	char reply[256];
	size_t i, n;
	int    rc;

	if (write_all(fd, "\0", 1) < 0)
		return -1;

	/* geteuid() matches what the kernel reports via SO_PEERCRED on
	 * the receiving side; getuid() would diverge if initctl is ever
	 * shipped setuid (it isn't today, but precision is cheap). */
	n = (size_t)snprintf(uidstr, sizeof(uidstr), "%u",
			     (unsigned)geteuid());
	if (n * 2 >= sizeof(hexuid))
		return -1;
	for (i = 0; i < n; i++) {
		unsigned c = (unsigned char)uidstr[i];

		hexuid[i * 2]     = hex[c >> 4];
		hexuid[i * 2 + 1] = hex[c & 0xf];
	}
	hexuid[n * 2] = '\0';

	rc = snprintf(line, sizeof(line), "AUTH EXTERNAL %s\r\n", hexuid);
	if (rc < 0 || (size_t)rc >= sizeof(line))
		return -1;
	if (write_all(fd, line, (size_t)rc) < 0)
		return -1;
	if (read_line(fd, reply, sizeof(reply)) < 0)
		return -1;
	if (strncmp(reply, "OK ", 3) != 0)
		return -1;
	if (write_all(fd, "BEGIN\r\n", 7) < 0)
		return -1;
	return 0;
}

/* ---- public ---- */

dbusc_t *dbusc_open(const char *path)
{
	struct sockaddr_un sun = { .sun_family = AF_UNIX };
	dbusc_t *c;
	int      fd;

	if (!path || strlen(path) >= sizeof(sun.sun_path))
		return NULL;
	memcpy(sun.sun_path, path, strlen(path) + 1);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return NULL;
	if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		close(fd);
		return NULL;
	}
	if (do_auth(fd) < 0) {
		close(fd);
		return NULL;
	}

	c = calloc(1, sizeof(*c));
	if (!c) {
		close(fd);
		return NULL;
	}
	c->fd          = fd;
	c->next_serial = 1;
	return c;
}

void dbusc_close(dbusc_t *c)
{
	if (!c)
		return;
	if (c->fd >= 0)
		close(c->fd);
	free(c);
}

/* ---- message build / parse ---- */

struct buf {
	uint8_t *p;
	size_t   cap;
	size_t   off;
	int      err;
};

static int b_reserve(struct buf *b, size_t align, size_t bytes)
{
	size_t pad = ALIGN_UP(b->off, align) - b->off;

	if (b->err || b->off + pad + bytes > b->cap) {
		b->err = 1;
		return -1;
	}
	while (pad--) b->p[b->off++] = 0;
	return 0;
}

static void b_put_u32(struct buf *b, uint32_t v)
{
	if (b_reserve(b, 4, 4) < 0) return;
	b->p[b->off++] = (uint8_t)(v       & 0xff);
	b->p[b->off++] = (uint8_t)((v >>  8) & 0xff);
	b->p[b->off++] = (uint8_t)((v >> 16) & 0xff);
	b->p[b->off++] = (uint8_t)((v >> 24) & 0xff);
}

static void b_put_byte(struct buf *b, uint8_t v)
{
	if (b_reserve(b, 1, 1) < 0) return;
	b->p[b->off++] = v;
}

static void b_put_string(struct buf *b, const char *s)
{
	size_t len = strlen(s);

	if (b_reserve(b, 4, 4 + len + 1) < 0) return;
	b_put_u32(b, (uint32_t)len);
	memcpy(b->p + b->off, s, len);
	b->off += len;
	b->p[b->off++] = 0;
}

static void b_put_sig(struct buf *b, const char *s)
{
	size_t len = strlen(s);

	if (b_reserve(b, 1, 1 + len + 1) < 0) return;
	b->p[b->off++] = (uint8_t)len;
	memcpy(b->p + b->off, s, len);
	b->off += len;
	b->p[b->off++] = 0;
}

static int send_method_call(struct dbusc *c,
			    const char *obj_path,
			    const char *iface,
			    const char *member,
			    const char *arg_sig,
			    const char *arg_str,
			    uint32_t    arg_u32)
{
	uint8_t hdr[2048];
	uint8_t body[1024];
	struct buf b  = { .p = hdr,  .cap = sizeof(hdr) };
	struct buf bb = { .p = body, .cap = sizeof(body) };
	uint32_t body_len = 0;
	size_t   fields_start, fields_end, padded_end;
	uint32_t serial = c->next_serial++;

	if (arg_sig && *arg_sig) {
		if (!strcmp(arg_sig, "s"))
			b_put_string(&bb, arg_str ? arg_str : "");
		else if (!strcmp(arg_sig, "u"))
			b_put_u32(&bb, arg_u32);
		else
			return -1;
		if (bb.err) return -1;
		body_len = (uint32_t)bb.off;
	}

	memset(hdr, 0, 16);
	hdr[0] = 'l';
	hdr[1] = 1;         /* METHOD_CALL */
	hdr[3] = 1;         /* protocol */
	hdr[4] = (uint8_t)( body_len        & 0xff);
	hdr[5] = (uint8_t)((body_len >>  8) & 0xff);
	hdr[6] = (uint8_t)((body_len >> 16) & 0xff);
	hdr[7] = (uint8_t)((body_len >> 24) & 0xff);
	hdr[8]  = (uint8_t)( serial        & 0xff);
	hdr[9]  = (uint8_t)((serial >>  8) & 0xff);
	hdr[10] = (uint8_t)((serial >> 16) & 0xff);
	hdr[11] = (uint8_t)((serial >> 24) & 0xff);
	b.off = 16;
	fields_start = b.off;

	/* PATH (code 1, type 'o') */
	b_reserve(&b, 8, 0);
	b_put_byte(&b, 1);
	b_put_sig (&b, "o");
	b_put_string(&b, obj_path);

	if (iface) {
		b_reserve(&b, 8, 0);
		b_put_byte(&b, 2);
		b_put_sig (&b, "s");
		b_put_string(&b, iface);
	}

	b_reserve(&b, 8, 0);
	b_put_byte(&b, 3);
	b_put_sig (&b, "s");
	b_put_string(&b, member);

	if (arg_sig && *arg_sig) {
		b_reserve(&b, 8, 0);
		b_put_byte(&b, 8);
		b_put_sig (&b, "g");
		b_put_sig (&b, arg_sig);
	}

	fields_end = b.off;
	{
		uint32_t flen = (uint32_t)(fields_end - fields_start);
		hdr[12] = (uint8_t)( flen        & 0xff);
		hdr[13] = (uint8_t)((flen >>  8) & 0xff);
		hdr[14] = (uint8_t)((flen >> 16) & 0xff);
		hdr[15] = (uint8_t)((flen >> 24) & 0xff);
	}

	padded_end = ALIGN_UP(fields_end, 8);
	while (b.off < padded_end) hdr[b.off++] = 0;
	if (b.err) return -1;

	if (write_all(c->fd, hdr, b.off) < 0) return -1;
	if (body_len > 0 && write_all(c->fd, body, body_len) < 0) return -1;
	return 0;
}

/* Read one method-return or error reply.  Captures the ERROR_NAME
 * header field on type=3 messages; everything else is consumed and
 * discarded. */
static int read_reply(int fd, uint8_t *out_type,
		      char *err_buf, size_t err_buf_sz)
{
	uint8_t  hdr_fixed[16];
	uint8_t  hdr_fields[2048];
	uint8_t  body_dump[1024];
	uint32_t body_len, fields_len;
	size_t   body_off;
	size_t   pos;

	if (err_buf && err_buf_sz)
		err_buf[0] = '\0';

	if (read_full(fd, hdr_fixed, 16) < 0)
		return -1;
	if (hdr_fixed[0] != 'l')
		return -1;
	*out_type = hdr_fixed[1];
	body_len = (uint32_t)hdr_fixed[4]
		 | ((uint32_t)hdr_fixed[5] << 8)
		 | ((uint32_t)hdr_fixed[6] << 16)
		 | ((uint32_t)hdr_fixed[7] << 24);
	fields_len = (uint32_t)hdr_fixed[12]
		   | ((uint32_t)hdr_fixed[13] << 8)
		   | ((uint32_t)hdr_fixed[14] << 16)
		   | ((uint32_t)hdr_fixed[15] << 24);

	if (fields_len > sizeof(hdr_fields))
		return -1;
	if (read_full(fd, hdr_fields, fields_len) < 0)
		return -1;

	body_off = (size_t)ALIGN_UP(16 + fields_len, 8);
	if (body_off > 16 + fields_len) {
		uint8_t pad[8];

		if (read_full(fd, pad, body_off - 16 - fields_len) < 0)
			return -1;
	}

	pos = 0;
	while (pos < fields_len) {
		uint8_t  code;
		size_t   vsig_len;
		const char *vsig;

		pos = ALIGN_UP(pos, 8);
		if (pos >= fields_len) break;
		code     = hdr_fields[pos++];
		vsig_len = hdr_fields[pos++];
		if (pos + vsig_len + 1 > fields_len) return -1;
		vsig = (const char *)(hdr_fields + pos);
		pos += vsig_len + 1;

		if (vsig[0] == 's' || vsig[0] == 'o') {
			uint32_t slen;

			pos = ALIGN_UP(pos, 4);
			if (pos + 4 > fields_len) return -1;
			slen = (uint32_t)hdr_fields[pos]
			     | ((uint32_t)hdr_fields[pos + 1] << 8)
			     | ((uint32_t)hdr_fields[pos + 2] << 16)
			     | ((uint32_t)hdr_fields[pos + 3] << 24);
			pos += 4;
			if (pos + slen + 1 > fields_len) return -1;
			if (code == 4 && err_buf && slen < err_buf_sz) {
				memcpy(err_buf, hdr_fields + pos, slen);
				err_buf[slen] = '\0';
			}
			pos += slen + 1;
		} else if (vsig[0] == 'g') {
			uint32_t slen = hdr_fields[pos++];

			if (pos + slen + 1 > fields_len) return -1;
			pos += slen + 1;
		} else if (vsig[0] == 'u') {
			pos = ALIGN_UP(pos, 4);
			pos += 4;
		} else {
			return -1;
		}
	}

	/* Drain the body in chunks of body_dump[]. */
	while (body_len > 0) {
		size_t take = body_len > sizeof(body_dump)
			    ? sizeof(body_dump) : body_len;

		if (read_full(fd, body_dump, take) < 0)
			return -1;
		body_len -= (uint32_t)take;
	}
	return 0;
}

int dbusc_call(dbusc_t *c,
	       const char *obj_path,
	       const char *iface,
	       const char *method,
	       const char *arg_sig,
	       const char *arg_str,
	       uint32_t    arg_u32,
	       char       *err_buf,
	       size_t      err_buf_sz)
{
	uint8_t type = 0;

	if (!c || c->fd < 0 || !obj_path || !iface || !method)
		return -1;

	if (send_method_call(c, obj_path, iface, method,
			     arg_sig, arg_str, arg_u32) < 0)
		return -1;
	if (read_reply(c->fd, &type, err_buf, err_buf_sz) < 0)
		return -1;

	if (type == 2)	/* METHOD_RETURN */
		return 0;
	if (type == 3)	/* ERROR */
		return 1;
	return -1;
}

#endif /* HAVE_DBUS */
