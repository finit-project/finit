/* libink internal types — not for external consumers.
 *
 * Copyright (c) 2026  Joachim Wiberg <troglobit@gmail.com>
 * SPDX-License-Identifier: MIT
 */
#ifndef LIBINK_INK_INTERNAL_H_
#define LIBINK_INK_INTERNAL_H_

#include <stdint.h>
#include <sys/queue.h>

#include "ink.h"
#include "marshal.h"
#include "proto.h"

typedef enum {
	INK_AUTH_NUL = 0,
	INK_AUTH_LINE,
	INK_AUTH_DONE,
	INK_AUTH_FAILED,
} ink_auth_state_t;

#define INK_PATH_MAX          108
#define INK_AUTH_LINEBUF_SIZE 256
#define INK_RX_BUF_SIZE       (64 * 1024)
#define INK_TX_BUF_SIZE       (16 * 1024)
#define INK_UNIQUE_NAME_LEN   16

/* Per-vtable record attached to an object's interface list. */
struct ink_vtable_entry {
	const ink_vtable_t *vt;
	void               *userdata;
	TAILQ_ENTRY(ink_vtable_entry) link;
};

TAILQ_HEAD(ink_vtable_list, ink_vtable_entry);

/* An object exposed at one path. */
struct ink_object {
	char                       path[INK_PATH_MAX];
	struct ink_vtable_list     vtables;
	TAILQ_ENTRY(ink_object)    link;
};

TAILQ_HEAD(ink_object_list, ink_object);

struct ink_server {
	int                       fd;
	char                      path[INK_PATH_MAX];
	struct ink_object_list    objects;
	uint32_t                  next_unique_id;	/* for ":1.N" names */
};

/* The reply being assembled inside a method handler.
 *
 * The reply body lives in conn->txbuf, not on this struct, so a
 * stack-allocated ink_call (in dispatch) stays small.  Sharing the
 * connection's txbuf is safe: the event loop is single-threaded and
 * a connection only ever has one in-flight method call at a time. */
struct ink_call {
	ink_connection_t *conn;
	struct ink_msg    incoming;
	struct ink_reader read_cursor;
	struct ink_writer reply_writer;	/* writes into conn->txbuf */
	int               reply_consumed;
	int               error_sent;
};

struct ink_connection {
	int                 fd;
	uid_t               peer_uid;

	char                guid[33];
	char                unique_name[INK_UNIQUE_NAME_LEN]; /* ":1.N" */

	ink_auth_state_t    auth;
	char                linebuf[INK_AUTH_LINEBUF_SIZE];
	size_t              linelen;

	uint8_t             rxbuf[INK_RX_BUF_SIZE];
	size_t              rxlen;

	/* Scratch for outgoing reply bodies.  Shared by the dispatch
	 * path (writes through call.reply_writer) and built-in handlers
	 * (send_string_reply).  Lifetime ends with each send_method_*
	 * call. */
	uint8_t             txbuf[INK_TX_BUF_SIZE];

	uint32_t            next_serial;

	struct ink_server  *server;	/* back-pointer for dispatch */
};

/* auth.c */
int  ink__auth_process(ink_connection_t *conn);
void ink__auth_generate_guid(char out[33]);

/* dispatch.c */
int  ink__dispatch_message(ink_connection_t *conn, const struct ink_msg *m);
int  ink__send_error(ink_connection_t *conn, const struct ink_msg *req,
		     const char *error_name, const char *text);
int  ink__send_method_return(ink_connection_t *conn, const struct ink_msg *req,
			     const char *out_sig,
			     const uint8_t *body, size_t body_len);

/* builtin.c */
int  ink__handle_builtin(ink_connection_t *conn, const struct ink_msg *m);

#endif /* LIBINK_INK_INTERNAL_H_ */
