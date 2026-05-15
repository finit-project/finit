/* libink — synchronous client-side D-Bus calls.
 *
 * Pairs with server.c / connection.c on the receiving end.  The
 * intent is for short-lived CLI tools (initctl) and tests to use
 * libink as their D-Bus client rather than reimplementing the
 * wire format.
 *
 * Copyright (c) 2026  Joachim Wiberg <troglobit@gmail.com>
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "internal.h"

struct link_client {
	int      fd;
	uint32_t next_serial;
	/* Re-use the server-side rx buffer size for incoming replies.
	 * Replies to our methods are bounded by the same per-message
	 * sanity cap as everything else. */
	uint8_t  rxbuf[LINK_RX_BUF_SIZE];
	size_t   rxlen;
};

link_client_t *link_client_open(const char *path)
{
	struct sockaddr_un sun = { .sun_family = AF_UNIX };
	link_client_t *c;
	int            fd;

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
	if (__auth_client(fd, geteuid()) < 0) {
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

void link_client_close(link_client_t *c)
{
	if (!c)
		return;
	if (c->fd >= 0)
		close(c->fd);
	free(c);
}

/* read_full / send_all live in libink/io.c. */
#define read_full(fd, buf, len)  __io_read_full ((fd), (buf), (len))
#define send_all(fd, buf, len)   __io_write_all((fd), (buf), (len))

#define ALIGN_UP(x, n) (((x) + (n) - 1) & ~((size_t)((n) - 1)))

/* Read one complete D-Bus message: the 16-byte fixed header tells
 * us fields_len + body_len, so we then issue exactly one more read
 * for the remainder.  Both lengths are bounded against rxbuf before
 * arithmetic so a malformed wire u32 can't wrap into a near-4-GiB
 * read. */
static int read_one(link_client_t *c, struct link_msg *msg)
{
	uint32_t body_len, fields_len, body_off, total;
	ssize_t  consumed;

	memset(msg, 0, sizeof(*msg));

	if (read_full(c->fd, c->rxbuf, 16) < 0)
		return -1;
	if (c->rxbuf[0] != 'l')
		return -1;

	body_len   = (uint32_t)c->rxbuf[4]
		   | ((uint32_t)c->rxbuf[5] << 8)
		   | ((uint32_t)c->rxbuf[6] << 16)
		   | ((uint32_t)c->rxbuf[7] << 24);
	fields_len = (uint32_t)c->rxbuf[12]
		   | ((uint32_t)c->rxbuf[13] << 8)
		   | ((uint32_t)c->rxbuf[14] << 16)
		   | ((uint32_t)c->rxbuf[15] << 24);

	/* Bound the wire-supplied lengths before any arithmetic on
	 * them.  Without this, fields_len = 0xFFFFFFF0 would wrap
	 * 16u + fields_len to near zero, bypass the total < rxbuf
	 * check, and trigger an out-of-bounds read. */
	if (fields_len > sizeof(c->rxbuf) || body_len > sizeof(c->rxbuf))
		return -1;

	body_off = (uint32_t)ALIGN_UP(16u + fields_len, 8u);
	total    = body_off + body_len;
	if (total > sizeof(c->rxbuf) || total < 16)
		return -1;

	if (read_full(c->fd, c->rxbuf + 16, total - 16) < 0)
		return -1;
	c->rxlen = total;

	consumed = __msg_parse(c->rxbuf, c->rxlen, msg);
	if (consumed <= 0)
		return -1;
	return 0;
}

int link_client_call(link_client_t *c,
		     const char *obj_path,
		     const char *interface,
		     const char *member,
		     const char *signature,
		     const uint8_t *body, size_t body_len,
		     char *err_buf, size_t err_buf_sz)
{
	/* Generous: Manager1 headers fit in ~150 B, but the buffer is
	 * shared with whatever future callers throw at us, and an
	 * overflow only manifests as a silent LINK_CALL_FAIL via
	 * __msg_build_method_call returning -1.  1 KiB on stack
	 * is cheap insurance. */
	uint8_t  hdr[1024];
	ssize_t  hlen;
	uint32_t serial;
	struct link_msg reply;

	if (!c || c->fd < 0 || !obj_path || !member)
		return LINK_CALL_FAIL;
	if (err_buf && err_buf_sz)
		err_buf[0] = '\0';

	serial = c->next_serial++;
	hlen = __msg_build_method_call(hdr, sizeof(hdr), serial,
					   obj_path, interface, member,
					   signature, (uint32_t)body_len);
	if (hlen < 0)
		return LINK_CALL_FAIL;

	if (send_all(c->fd, hdr, (size_t)hlen) < 0)
		return LINK_CALL_FAIL;
	if (body_len > 0 && send_all(c->fd, body, body_len) < 0)
		return LINK_CALL_FAIL;

	if (read_one(c, &reply) < 0)
		return LINK_CALL_FAIL;

	if (reply.type == LINK_MSG_METHOD_RETURN)
		return LINK_CALL_OK;
	if (reply.type == LINK_MSG_ERROR) {
		if (err_buf && err_buf_sz && reply.error_name) {
			size_t n = strlen(reply.error_name);

			if (n >= err_buf_sz)
				n = err_buf_sz - 1;
			memcpy(err_buf, reply.error_name, n);
			err_buf[n] = '\0';
		}
		return LINK_CALL_ERROR;
	}
	return LINK_CALL_FAIL;
}
