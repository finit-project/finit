/* libink — D-Bus wire protocol: message header parsing and building.
 *
 * Copyright (c) 2026  Joachim Wiberg <troglobit@gmail.com>
 * SPDX-License-Identifier: MIT
 */
#ifndef LIBINK_PROTO_H_
#define LIBINK_PROTO_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "link.h"		/* LINK_MSG_* type codes */

/* Message flags. */
#define LINK_FLAG_NO_REPLY_EXPECTED  0x01
#define LINK_FLAG_NO_AUTO_START      0x02
#define LINK_FLAG_ALLOW_INTERACTIVE_AUTHORIZATION 0x04

/* Header field codes. */
#define LINK_HDR_PATH         1
#define LINK_HDR_INTERFACE    2
#define LINK_HDR_MEMBER       3
#define LINK_HDR_ERROR_NAME   4
#define LINK_HDR_REPLY_SERIAL 5
#define LINK_HDR_DESTINATION  6
#define LINK_HDR_SENDER       7
#define LINK_HDR_SIGNATURE    8
#define LINK_HDR_UNIX_FDS     9

#define LINK_PROTOCOL_VERSION 1

/* Parsed view of an incoming message.  Pointers reference bytes
 * inside the receiver's own rx buffer; treat as borrowed and short-
 * lived (until the next read of the same connection). */
struct link_msg {
	uint8_t      type;
	uint8_t      flags;
	uint8_t      endian;	/* 'l' or 'B' */
	uint32_t     body_len;
	uint32_t     serial;
	uint32_t     reply_serial;

	const char  *path;	/* object path, or NULL */
	const char  *interface;	/* may be NULL on method calls */
	const char  *member;
	const char  *error_name;
	const char  *destination;
	const char  *sender;
	const char  *signature;	/* may be NULL if body is empty */

	/* Pointer into the rx buffer and length, after header padding. */
	const uint8_t *body;
	uint32_t       body_avail;
};

/* Parse a complete D-Bus message from `buf` of size `len`.  On
 * success returns the total number of bytes consumed (header +
 * padding + body) and fills *out.  Returns 0 if more bytes are
 * needed, -1 on malformed input. */
ssize_t __msg_parse(const uint8_t *buf, size_t len, struct link_msg *out);

/* Compute the on-wire size of a future message header given the
 * fields we'd populate.  Used to size send buffers. */
size_t __msg_header_size(const struct link_msg *m);

/* Build a method-return header into `buf` (capacity `cap`).
 * `reply_serial`/`destination` come from the call being replied to.
 * `signature` is the body signature ("" if no args).  `body_len`
 * is the length of the body that will follow the header padding.
 * Returns the number of bytes written, or -1 on overflow. */
ssize_t __msg_build_return(uint8_t *buf, size_t cap,
			      uint32_t serial, uint32_t reply_serial,
			      const char *destination,
			      const char *signature, uint32_t body_len);

/* Build an error reply header. */
ssize_t __msg_build_error(uint8_t *buf, size_t cap,
			     uint32_t serial, uint32_t reply_serial,
			     const char *destination,
			     const char *error_name,
			     const char *signature, uint32_t body_len);

/* Build a signal header (no reply expected, no destination). */
ssize_t __msg_build_signal(uint8_t *buf, size_t cap,
			      uint32_t serial,
			      const char *path,
			      const char *interface,
			      const char *member,
			      const char *signature, uint32_t body_len);

/* Build a method-call header (client side). */
ssize_t __msg_build_method_call(uint8_t *buf, size_t cap,
				    uint32_t serial,
				    const char *path,
				    const char *interface,
				    const char *member,
				    const char *signature,
				    uint32_t body_len);

#endif /* LIBINK_PROTO_H_ */
