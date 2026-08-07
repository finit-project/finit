/* libink internal types — not for external consumers.
 *
 * Copyright (c) 2026  Joachim Wiberg <troglobit@gmail.com>
 * SPDX-License-Identifier: MIT
 */
#ifndef LIBINK_INTERNAL_H_
#define LIBINK_INTERNAL_H_

#include <stdint.h>
#include <sys/queue.h>

#include "link.h"
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
#define LINK_UNIQUE_NAME_LEN   LINK_SENDER_MAX
#define LINK_MATCH_RULE_MAX    256	/* per-peer match rule cap */
#define LINK_MATCH_PEER_CAP    16	/* max active match rules per peer */
#define LINK_PENDING_CAP        4	/* outbound calls awaiting a reply */
/* Staging for an outgoing method call.  Generous on purpose: headers
 * for the calls libink makes run to ~150 B, and both the synchronous
 * and the connection-side path build into these, so one answer rather
 * than a number per call site. */
#define LINK_CALL_HDR_MAX    1024
#define LINK_CALL_BODY_MAX   1024
#define LINK_PARKED_CAP         4	/* inbound calls awaiting a uid */
/* A call parked for authorization is a privileged one: an object path
 * and at most a service name.  Finit's per-service paths alone run to
 * 512 bytes, so leave room for the header around one.  Anything that
 * does not fit is denied rather than held. */
#define LINK_PARKED_MSG_MAX  1024

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

/* An inbound method call held while we find out who sent it.  The
 * message is copied because rxbuf is reused as soon as we return to
 * the read loop.  `tok` is the handle the resolver answers with, and
 * zero when the slot is free. */
struct link_parked {
	link_authz_t        tok;
	link_connection_t  *conn;
	size_t              len;
	uint8_t             buf[LINK_PARKED_MSG_MAX];
};

struct link_server {
	int                       fd;
	char                      path[LINK_PATH_MAX];
	struct link_object_list    objects;
	uint32_t                  next_unique_id;	/* for ":1.N" names */

	/* Set by link_server_set_uid_resolver(); see link.h. */
	link_uid_resolver_t       uid_resolver;
	void                     *uid_userdata;

	/* Set by link_server_set_authorizer(); see link.h. */
	link_authorizer_t         authorizer;
	void                     *authz_userdata;
	struct link_parked        parked[LINK_PARKED_CAP];
	link_authz_t              next_tok;
};

/* The reply being assembled inside a method handler.
 *
 * The reply body lives in conn->txbuf, not on this struct, so a
 * stack-allocated link_call (in dispatch) stays small.  Sharing the
 * connection's txbuf is safe because a reply is marshalled and sent
 * without yielding.  Note that parking means several calls can be in
 * flight on one connection: what is held is the request, and
 * link_uid_resolved() resumes from a copy, so txbuf is still only
 * ever used by one reply at a time.  An async handler that returned
 * before writing its reply would break that. */
struct link_call {
	link_connection_t *conn;
	struct link_msg    incoming;
	struct link_reader read_cursor;
	struct link_writer reply_writer;	/* writes into conn->txbuf */
	int               reply_consumed;
	int               error_sent;
	uid_t             uid;		/* caller, resolved for a broker peer */
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
	 * a LimitsExceeded error reply.  A broker never registers any,
	 * it matches for its own clients, so `broker` bypasses them. */
	struct link_match   *matches[LINK_MATCH_PEER_CAP];
	size_t              matches_count;
	int                 broker;

	uint8_t             rxbuf[LINK_RX_BUF_SIZE];
	size_t              rxlen;

	/* Scratch for outgoing reply bodies.  Shared by the dispatch
	 * path (writes through call.reply_writer) and built-in handlers
	 * (send_string_reply).  Lifetime ends with each send_method_*
	 * call. */
	uint8_t             txbuf[LINK_TX_BUF_SIZE];

	uint32_t            next_serial;

	/* Outbound calls we made on this connection, awaiting replies.
	 * Only a broker connection uses these today, to ask the bus
	 * driver who a sender is. */
	struct {
		int              used;
		uint32_t         serial;
		link_reply_cb_t  cb;
		void            *userdata;
	} pending[LINK_PENDING_CAP];

	struct link_server  *server;	/* back-pointer for dispatch */
};

/* io.c — shared EINTR-resilient I/O loops. */
int  __io_write_all(int fd, const void *buf, size_t len);
int  __io_read_full(int fd, void *buf,       size_t len);

/* auth.c */
int  __auth_process(link_connection_t *conn);
void __auth_generate_guid(char out[33]);
int  __auth_client(int fd, uid_t uid);

/* dispatch.c */
int  __dispatch_message(link_connection_t *conn, const struct link_msg *m, size_t framelen);
void __dispatch_forget_conn(link_connection_t *conn);
int  __send_error(link_connection_t *conn, const struct link_msg *req,
		     const char *error_name, const char *text);
int  __send_method_return(link_connection_t *conn, const struct link_msg *req,
			     const char *out_sig,
			     const uint8_t *body, size_t body_len);

/* builtin.c */
int  __handle_builtin(link_connection_t *conn, const struct link_msg *m);

/* match.c */
struct link_match *__match_parse  (const char *rule);
void              __match_free   (struct link_match *m);
int               __match_matches(const struct link_match *m,
				     const char *path, const char *iface,
				     const char *member);
int               __match_add    (link_connection_t *conn, const char *rule);
int               __match_remove (link_connection_t *conn, const char *rule);

#endif /* LIBINK_INTERNAL_H_ */
