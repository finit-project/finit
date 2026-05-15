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
	LINK_AUTH_NUL = 0,
	LINK_AUTH_LINE,
	LINK_AUTH_DONE,
	LINK_AUTH_FAILED,
} link_auth_state_t;

#define LINK_PATH_MAX          108
#define LINK_AUTH_LINEBUF_SIZE 256
#define LINK_RX_BUF_SIZE       (64 * 1024)
#define LINK_TX_BUF_SIZE       (16 * 1024)
#define LINK_UNIQUE_NAME_LEN   16
#define LINK_MATCH_RULE_MAX    256	/* per-peer match rule cap */
#define LINK_MATCH_PEER_CAP    16	/* max active match rules per peer */

/* Per-vtable record attached to an object's interface list. */
struct link_vtable_entry {
	const link_vtable_t *vt;
	void               *userdata;
	TAILQ_ENTRY(link_vtable_entry) link;
};

TAILQ_HEAD(link_vtable_list, link_vtable_entry);

/* An object exposed at one path. */
struct link_object {
	char                       path[LINK_PATH_MAX];
	struct link_vtable_list     vtables;
	TAILQ_ENTRY(link_object)    link;
};

TAILQ_HEAD(link_object_list, link_object);

struct link_server {
	int                       fd;
	char                      path[LINK_PATH_MAX];
	struct link_object_list    objects;
	uint32_t                  next_unique_id;	/* for ":1.N" names */
};

/* The reply being assembled inside a method handler.
 *
 * The reply body lives in conn->txbuf, not on this struct, so a
 * stack-allocated link_call (in dispatch) stays small.  Sharing the
 * connection's txbuf is safe: the event loop is single-threaded and
 * a connection only ever has one in-flight method call at a time. */
struct link_call {
	link_connection_t *conn;
	struct link_msg    incoming;
	struct link_reader read_cursor;
	struct link_writer reply_writer;	/* writes into conn->txbuf */
	int               reply_consumed;
	int               error_sent;
};

/* A parsed AddMatch rule.  Fields are NULL when the rule omits the
 * key, meaning "match anything"; non-NULL means "must equal". */
struct link_match {
	char *raw;		/* original string, for RemoveMatch */
	char *type;		/* "signal", or NULL */
	char *interface;
	char *member;
	char *path;
};

struct link_connection {
	int                 fd;
	uid_t               peer_uid;

	char                guid[33];
	char                unique_name[LINK_UNIQUE_NAME_LEN]; /* ":1.N" */

	link_auth_state_t    auth;
	char                linebuf[LINK_AUTH_LINEBUF_SIZE];
	size_t              linelen;

	/* Match rules registered via org.freedesktop.DBus.AddMatch.
	 * Bounded for PID 1 hygiene; a peer that exceeds the cap gets
	 * a LimitsExceeded error reply. */
	struct link_match   *matches[LINK_MATCH_PEER_CAP];
	size_t              matches_count;

	uint8_t             rxbuf[LINK_RX_BUF_SIZE];
	size_t              rxlen;

	/* Scratch for outgoing reply bodies.  Shared by the dispatch
	 * path (writes through call.reply_writer) and built-in handlers
	 * (send_string_reply).  Lifetime ends with each send_method_*
	 * call. */
	uint8_t             txbuf[LINK_TX_BUF_SIZE];

	uint32_t            next_serial;

	struct link_server  *server;	/* back-pointer for dispatch */
};

/* auth.c */
int  link__auth_process(link_connection_t *conn);
void link__auth_generate_guid(char out[33]);

/* dispatch.c */
int  link__dispatch_message(link_connection_t *conn, const struct link_msg *m);
int  link__send_error(link_connection_t *conn, const struct link_msg *req,
		     const char *error_name, const char *text);
int  link__send_method_return(link_connection_t *conn, const struct link_msg *req,
			     const char *out_sig,
			     const uint8_t *body, size_t body_len);

/* builtin.c */
int  link__handle_builtin(link_connection_t *conn, const struct link_msg *m);

/* match.c */
struct link_match *link__match_parse  (const char *rule);
void              link__match_free   (struct link_match *m);
int               link__match_matches(const struct link_match *m,
				     const char *path, const char *iface,
				     const char *member);
int               link__match_add    (link_connection_t *conn, const char *rule);
int               link__match_remove (link_connection_t *conn, const char *rule);

#endif /* LIBINK_INK_INTERNAL_H_ */
