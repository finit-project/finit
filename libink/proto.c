/* libink — D-Bus wire protocol: message header parsing and building.
 *
 * Implements the binary message header format described in the
 * D-Bus specification, sections "Message Format" and "Header Fields".
 * Bodies are deliberately not parsed here — that's the marshaller's
 * job (marshal.c).
 *
 * Native byte order is assumed to be little-endian; messages with the
 * 'B' endianness flag are rejected for now (every conforming client
 * on the platforms Finit targets sends 'l').
 *
 * Copyright (c) 2026  Joachim Wiberg <troglobit@gmail.com>
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>

#include "proto.h"

#define HDR_FIXED_SIZE 16
#define MAX_MSG_SIZE   (128 * 1024)	/* sanity limit for PID 1 */
#define ALIGN_UP(x, n) (((x) + (n) - 1) & ~((size_t)((n) - 1)))

static inline uint32_t rd_u32(const uint8_t *p)
{
	return (uint32_t)p[0]
	     | ((uint32_t)p[1] << 8)
	     | ((uint32_t)p[2] << 16)
	     | ((uint32_t)p[3] << 24);
}

static inline void wr_u32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v       & 0xff);
	p[1] = (uint8_t)((v >> 8)  & 0xff);
	p[2] = (uint8_t)((v >> 16) & 0xff);
	p[3] = (uint8_t)((v >> 24) & 0xff);
}

/* Parse a (length-prefixed, nul-terminated) DBus STRING or PATH from
 * the header field array.  Returns a pointer into buf or NULL on
 * malformed input.  *consumed receives the bytes used including the
 * nul. */
static const char *parse_string(const uint8_t *buf, size_t avail, size_t *consumed)
{
	uint32_t len;

	if (avail < 4)
		return NULL;
	len = rd_u32(buf);
	if (len >= avail - 4)	/* need room for len bytes + nul */
		return NULL;
	if (buf[4 + len] != 0)
		return NULL;
	*consumed = 4 + len + 1;
	return (const char *)(buf + 4);
}

/* Parse a SIGNATURE (1-byte length, nul-terminated). */
static const char *parse_signature(const uint8_t *buf, size_t avail, size_t *consumed)
{
	uint32_t len;

	if (avail < 1)
		return NULL;
	len = buf[0];
	if (len + 2 > avail)
		return NULL;
	if (buf[1 + len] != 0)
		return NULL;
	*consumed = 1 + len + 1;
	return (const char *)(buf + 1);
}

ssize_t __msg_parse(const uint8_t *buf, size_t len, struct link_msg *out)
{
	uint32_t fields_len, total_hdr, body_off, total;
	const uint8_t *fp, *fend;

	memset(out, 0, sizeof(*out));

	if (len < HDR_FIXED_SIZE)
		return 0;

	if (buf[0] != 'l') {
		errno = EPROTO;
		return -1;
	}
	if (buf[3] != LINK_PROTOCOL_VERSION) {
		errno = EPROTONOSUPPORT;
		return -1;
	}
	out->endian   = buf[0];
	out->type     = buf[1];
	out->flags    = buf[2];
	out->body_len = rd_u32(buf + 4);
	out->serial   = rd_u32(buf + 8);
	fields_len    = rd_u32(buf + 12);

	if (fields_len > MAX_MSG_SIZE || out->body_len > MAX_MSG_SIZE) {
		errno = E2BIG;
		return -1;
	}

	total_hdr = HDR_FIXED_SIZE + fields_len;
	body_off  = (uint32_t)ALIGN_UP(total_hdr, 8);
	total     = body_off + out->body_len;

	if (len < total)
		return 0;	/* need more bytes */

	/* Walk the array of (byte field-code, variant). */
	fp   = buf + HDR_FIXED_SIZE;
	fend = fp + fields_len;
	while (fp < fend) {
		uint8_t code;
		const char *vsig;
		size_t used;

		fp = buf + ALIGN_UP((size_t)(fp - buf), 8);
		if (fp >= fend)
			break;

		code = *fp++;
		vsig = parse_signature(fp, (size_t)(fend - fp), &used);
		if (!vsig) {
			errno = EPROTO;
			return -1;
		}
		fp += used;

		if (vsig[0] == 's' || vsig[0] == 'o') {
			fp = buf + ALIGN_UP((size_t)(fp - buf), 4);
			if (fp >= fend) { errno = EPROTO; return -1; }
			const char *s = parse_string(fp, (size_t)(fend - fp), &used);
			if (!s) { errno = EPROTO; return -1; }
			switch (code) {
			case LINK_HDR_PATH:        out->path        = s; break;
			case LINK_HDR_INTERFACE:   out->interface   = s; break;
			case LINK_HDR_MEMBER:      out->member      = s; break;
			case LINK_HDR_ERROR_NAME:  out->error_name  = s; break;
			case LINK_HDR_DESTINATION: out->destination = s; break;
			case LINK_HDR_SENDER:      out->sender      = s; break;
			}
			fp += used;
		} else if (vsig[0] == 'g') {
			const char *s = parse_signature(fp, (size_t)(fend - fp), &used);
			if (!s) { errno = EPROTO; return -1; }
			if (code == LINK_HDR_SIGNATURE)
				out->signature = s;
			fp += used;
		} else if (vsig[0] == 'u') {
			fp = buf + ALIGN_UP((size_t)(fp - buf), 4);
			if (fp + 4 > fend) { errno = EPROTO; return -1; }
			uint32_t v = rd_u32(fp);
			if (code == LINK_HDR_REPLY_SERIAL)
				out->reply_serial = v;
			fp += 4;
		} else {
			/* Unknown field type — skip whole message. */
			errno = EPROTO;
			return -1;
		}
	}

	out->body       = buf + body_off;
	out->body_avail = out->body_len;
	return (ssize_t)total;
}

/* ---------- builders ---------- */

/* Append a (byte field-code, variant) entry to a header-fields array,
 * with the entry pre-aligned to 8 bytes. */
static int put_field_string(uint8_t *buf, size_t cap, size_t *off,
			    uint8_t code, char vsig_char,
			    const char *value)
{
	size_t o   = *off;
	size_t pad = ALIGN_UP(o, 8) - o;
	size_t len = strlen(value);

	/* Padding for struct alignment */
	while (pad-- > 0) {
		if (o >= cap) return -1;
		buf[o++] = 0;
	}

	/* code, variant signature (1B len + 1B char + 1B nul) */
	if (o + 4 > cap) return -1;
	buf[o++] = code;
	buf[o++] = 1;
	buf[o++] = (uint8_t)vsig_char;
	buf[o++] = 0;

	if (vsig_char == 's' || vsig_char == 'o') {
		/* 4-byte align for u32 length */
		while (o & 3) {
			if (o >= cap) return -1;
			buf[o++] = 0;
		}
		if (o + 4 + len + 1 > cap) return -1;
		wr_u32(buf + o, (uint32_t)len);
		o += 4;
		memcpy(buf + o, value, len);
		o += len;
		buf[o++] = 0;
	} else if (vsig_char == 'g') {
		if (o + 1 + len + 1 > cap) return -1;
		buf[o++] = (uint8_t)len;
		memcpy(buf + o, value, len);
		o += len;
		buf[o++] = 0;
	} else {
		return -1;
	}

	*off = o;
	return 0;
}

static int put_field_u32(uint8_t *buf, size_t cap, size_t *off,
			 uint8_t code, uint32_t value)
{
	size_t o   = *off;
	size_t pad = ALIGN_UP(o, 8) - o;

	while (pad-- > 0) {
		if (o >= cap) return -1;
		buf[o++] = 0;
	}
	if (o + 8 > cap) return -1;
	buf[o++] = code;
	buf[o++] = 1;
	buf[o++] = 'u';
	buf[o++] = 0;
	while (o & 3) {
		if (o >= cap) return -1;
		buf[o++] = 0;
	}
	if (o + 4 > cap) return -1;
	wr_u32(buf + o, value);
	o += 4;
	*off = o;
	return 0;
}

static ssize_t finalize_header(uint8_t *buf, size_t cap,
			       uint8_t type, uint8_t flags,
			       uint32_t body_len, uint32_t serial,
			       size_t fields_end)
{
	size_t hdr_end = fields_end;
	size_t pad     = ALIGN_UP(hdr_end, 8) - hdr_end;

	buf[0] = 'l';
	buf[1] = type;
	buf[2] = flags;
	buf[3] = LINK_PROTOCOL_VERSION;
	wr_u32(buf + 4,  body_len);
	wr_u32(buf + 8,  serial);
	wr_u32(buf + 12, (uint32_t)(hdr_end - HDR_FIXED_SIZE));

	while (pad-- > 0) {
		if (hdr_end >= cap) return -1;
		buf[hdr_end++] = 0;
	}
	return (ssize_t)hdr_end;
}

ssize_t __msg_build_return(uint8_t *buf, size_t cap,
			      uint32_t serial, uint32_t reply_serial,
			      const char *destination,
			      const char *signature, uint32_t body_len)
{
	size_t off = HDR_FIXED_SIZE;

	if (cap < HDR_FIXED_SIZE)
		return -1;

	if (put_field_u32(buf, cap, &off, LINK_HDR_REPLY_SERIAL, reply_serial) < 0)
		return -1;
	if (destination &&
	    put_field_string(buf, cap, &off, LINK_HDR_DESTINATION, 's', destination) < 0)
		return -1;
	if (signature && *signature &&
	    put_field_string(buf, cap, &off, LINK_HDR_SIGNATURE, 'g', signature) < 0)
		return -1;

	return finalize_header(buf, cap, LINK_MSG_METHOD_RETURN,
			       LINK_FLAG_NO_REPLY_EXPECTED,
			       body_len, serial, off);
}

ssize_t __msg_build_error(uint8_t *buf, size_t cap,
			     uint32_t serial, uint32_t reply_serial,
			     const char *destination,
			     const char *error_name,
			     const char *signature, uint32_t body_len)
{
	size_t off = HDR_FIXED_SIZE;

	if (cap < HDR_FIXED_SIZE || !error_name)
		return -1;

	if (put_field_u32(buf, cap, &off, LINK_HDR_REPLY_SERIAL, reply_serial) < 0)
		return -1;
	if (put_field_string(buf, cap, &off, LINK_HDR_ERROR_NAME, 's', error_name) < 0)
		return -1;
	if (destination &&
	    put_field_string(buf, cap, &off, LINK_HDR_DESTINATION, 's', destination) < 0)
		return -1;
	if (signature && *signature &&
	    put_field_string(buf, cap, &off, LINK_HDR_SIGNATURE, 'g', signature) < 0)
		return -1;

	return finalize_header(buf, cap, LINK_MSG_ERROR,
			       LINK_FLAG_NO_REPLY_EXPECTED,
			       body_len, serial, off);
}

ssize_t __msg_build_signal(uint8_t *buf, size_t cap,
			      uint32_t serial,
			      const char *path,
			      const char *interface,
			      const char *member,
			      const char *signature, uint32_t body_len)
{
	size_t off = HDR_FIXED_SIZE;

	if (cap < HDR_FIXED_SIZE || !path || !interface || !member)
		return -1;

	if (put_field_string(buf, cap, &off, LINK_HDR_PATH,      'o', path)      < 0)
		return -1;
	if (put_field_string(buf, cap, &off, LINK_HDR_INTERFACE, 's', interface) < 0)
		return -1;
	if (put_field_string(buf, cap, &off, LINK_HDR_MEMBER,    's', member)    < 0)
		return -1;
	if (signature && *signature &&
	    put_field_string(buf, cap, &off, LINK_HDR_SIGNATURE, 'g', signature) < 0)
		return -1;

	return finalize_header(buf, cap, LINK_MSG_SIGNAL,
			       LINK_FLAG_NO_REPLY_EXPECTED,
			       body_len, serial, off);
}

ssize_t __msg_build_method_call(uint8_t *buf, size_t cap,
				    uint32_t serial,
				    const char *path,
				    const char *interface,
				    const char *member,
				    const char *signature,
				    uint32_t body_len)
{
	size_t off = HDR_FIXED_SIZE;

	if (cap < HDR_FIXED_SIZE || !path || !member)
		return -1;

	if (put_field_string(buf, cap, &off, LINK_HDR_PATH, 'o', path) < 0)
		return -1;
	if (interface &&
	    put_field_string(buf, cap, &off, LINK_HDR_INTERFACE, 's', interface) < 0)
		return -1;
	if (put_field_string(buf, cap, &off, LINK_HDR_MEMBER, 's', member) < 0)
		return -1;
	if (signature && *signature &&
	    put_field_string(buf, cap, &off, LINK_HDR_SIGNATURE, 'g', signature) < 0)
		return -1;

	return finalize_header(buf, cap, LINK_MSG_METHOD_CALL,
			       /* flags=0: we expect a reply */
			       0,
			       body_len, serial, off);
}

size_t __msg_header_size(const struct link_msg *m)
{
	(void)m;
	/* Generous upper bound used by callers to size send buffers. */
	return 512;
}
