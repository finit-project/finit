/* libink — object tree, vtable registration, and method dispatch.
 *
 * Copyright (c) 2026  Joachim Wiberg <troglobit@gmail.com>
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "internal.h"

/* ----------  object/vtable registration  ---------- */

static struct link_object *find_object(link_server_t *srv, const char *path)
{
	struct link_object *o;

	TAILQ_FOREACH(o, &srv->objects, link)
		if (strcmp(o->path, path) == 0)
			return o;
	return NULL;
}

int link_server_remove_object(link_server_t *srv, const char *path)
{
	struct link_object       *o;
	struct link_vtable_entry *e;

	if (!srv || !path) {
		errno = EINVAL;
		return -1;
	}

	o = find_object(srv, path);
	if (!o) {
		errno = ENOENT;
		return -1;
	}

	while ((e = TAILQ_FIRST(&o->vtables))) {
		TAILQ_REMOVE(&o->vtables, e, link);
		free(e);
	}
	TAILQ_REMOVE(&srv->objects, o, link);
	free(o);
	return 0;
}

int link_server_add_object(link_server_t *srv, const char *path,
			  const link_vtable_t *vt, void *userdata)
{
	struct link_object        *o;
	struct link_vtable_entry  *e;
	size_t                    plen;

	if (!srv || !path || !*path || !vt || !vt->interface) {
		errno = EINVAL;
		return -1;
	}
	plen = strlen(path);
	if (plen >= LINK_PATH_MAX) {
		errno = ENAMETOOLONG;
		return -1;
	}

	o = find_object(srv, path);
	if (!o) {
		o = calloc(1, sizeof(*o));
		if (!o)
			return -1;
		memcpy(o->path, path, plen + 1);
		TAILQ_INIT(&o->vtables);
		TAILQ_INSERT_TAIL(&srv->objects, o, link);
	}

	e = calloc(1, sizeof(*e));
	if (!e)
		return -1;
	e->vt       = vt;
	e->userdata = userdata;
	TAILQ_INSERT_TAIL(&o->vtables, e, link);
	return 0;
}

/* ----------  lookup ---------- */

static const link_method_t *find_method(const link_vtable_t *vt, const char *name)
{
	const link_method_t *m;

	if (!vt->methods)
		return NULL;
	for (m = vt->methods; m->name; m++)
		if (strcmp(m->name, name) == 0)
			return m;
	return NULL;
}

/* If incoming.interface is NULL, search every interface on the
 * object for a member with this name.  Returns the matching method
 * and writes back its vtable_entry in *out_e. */
static const link_method_t *resolve(struct link_object *o,
				   const char *iface, const char *member,
				   struct link_vtable_entry **out_e)
{
	struct link_vtable_entry *e;
	const link_method_t      *m;

	if (iface) {
		TAILQ_FOREACH(e, &o->vtables, link) {
			if (strcmp(e->vt->interface, iface) != 0)
				continue;
			m = find_method(e->vt, member);
			if (m) {
				*out_e = e;
				return m;
			}
			return NULL;
		}
		return NULL;
	}

	TAILQ_FOREACH(e, &o->vtables, link) {
		m = find_method(e->vt, member);
		if (m) {
			*out_e = e;
			return m;
		}
	}
	return NULL;
}

/* ----------  send helpers  ---------- */

/*
 * Peer fds are non-blocking, so send_all may fail mid-frame (e.g.
 * EAGAIN from a peer that stopped draining its socket).  Any failure
 * poisons the peer's stream: never retry on the same connection,
 * drop the peer.
 */
#define send_all(fd, buf, len)  __io_write_all((fd), (buf), (len))

int __send_method_return(link_connection_t *conn, const struct link_msg *req,
			    const char *out_sig,
			    const uint8_t *body, size_t body_len)
{
	uint8_t hdr[512];
	ssize_t hlen;
	uint32_t serial = ++conn->next_serial;

	hlen = __msg_build_return(hdr, sizeof(hdr), serial,
				     req->serial,
				     req->sender,
				     out_sig, (uint32_t)body_len);
	if (hlen < 0) {
		errno = EMSGSIZE;
		return -1;
	}

	if (send_all(conn->fd, hdr, (size_t)hlen) < 0)
		return -1;
	if (body_len > 0 && send_all(conn->fd, body, body_len) < 0)
		return -1;
	return 0;
}

int link_connection_emit_signal(link_connection_t *conn,
			       const char *path,
			       const char *interface,
			       const char *member,
			       const char *signature,
			       const uint8_t *body, size_t body_len)
{
	uint8_t  hdr[512];
	ssize_t  hlen;
	uint32_t serial;
	size_t   i;
	int      matched = 0;

	if (!conn || !path || !interface || !member) {
		errno = EINVAL;
		return -1;
	}
	if (conn->auth != LINK_AUTH_DONE)
		return 0;	/* peer hasn't finished the SASL phase */

	/* A broker routes to whoever subscribed with it, so it wants
	 * every signal and never sends us AddMatch of its own. */
	matched = conn->broker;

	for (i = 0; !matched && i < conn->matches_count; i++) {
		if (__match_matches(conn->matches[i], path,
				       interface, member))
			matched = 1;
	}
	if (!matched)
		return 0;	/* peer didn't subscribe — nothing to do */

	serial = ++conn->next_serial;
	hlen = __msg_build_signal(hdr, sizeof(hdr), serial,
				     path, interface, member,
				     signature, (uint32_t)body_len);
	if (hlen < 0) {
		errno = EMSGSIZE;
		return -1;
	}

	if (send_all(conn->fd, hdr, (size_t)hlen) < 0)
		return -1;
	if (body_len > 0 && send_all(conn->fd, body, body_len) < 0)
		return -1;
	return 0;
}

int __send_error(link_connection_t *conn, const struct link_msg *req,
		    const char *error_name, const char *text)
{
	uint8_t  hdr[512];
	uint8_t  body[256];
	ssize_t  hlen;
	size_t   blen = 0;
	uint32_t serial = ++conn->next_serial;
	const char *sig = NULL;

	if (text && *text) {
		struct link_writer w;
		ssize_t n;

		__w_init(&w, body, sizeof(body));
		__w_string(&w, text);
		n = __w_finish(&w);
		if (n < 0) {
			errno = EMSGSIZE;
			return -1;
		}
		blen = (size_t)n;
		sig  = "s";
	}

	hlen = __msg_build_error(hdr, sizeof(hdr), serial,
				    req->serial, req->sender,
				    error_name, sig, (uint32_t)blen);
	if (hlen < 0) {
		errno = EMSGSIZE;
		return -1;
	}

	if (send_all(conn->fd, hdr, (size_t)hlen) < 0)
		return -1;
	if (blen > 0 && send_all(conn->fd, body, blen) < 0)
		return -1;
	return 0;
}

/* ----------  link_call public surface  ---------- */

const char *link_call_path     (const link_call_t *c) { return c ? c->incoming.path      : NULL; }
const char *link_call_interface(const link_call_t *c) { return c ? c->incoming.interface : NULL; }
const char *link_call_member   (const link_call_t *c) { return c ? c->incoming.member    : NULL; }
uid_t       link_call_uid      (const link_call_t *c) { return c ? c->uid               : LINK_UID_UNKNOWN; }

link_writer_t *link_call_reply(link_call_t *call)
{
	if (!call || call->reply_consumed || call->error_sent)
		return NULL;
	call->reply_consumed = 1;
	__w_init(&call->reply_writer,
		    call->conn->txbuf, sizeof(call->conn->txbuf));
	return &call->reply_writer;
}

int link_call_reply_error(link_call_t *call, const char *name, const char *message)
{
	if (!call || call->error_sent) {
		errno = EINVAL;
		return -1;
	}
	call->error_sent = 1;
	return __send_error(call->conn, &call->incoming, name, message);
}

/* ----------  public reader wrappers  ---------- */

int link_call_read_byte  (link_call_t *c, uint8_t *o)        { return __r_byte  (&c->read_cursor, o); }
int link_call_read_bool  (link_call_t *c, int *o)            { return __r_bool  (&c->read_cursor, o); }
int link_call_read_u32   (link_call_t *c, uint32_t *o)       { return __r_u32   (&c->read_cursor, o); }
int link_call_read_string(link_call_t *c, const char **o)    { return __r_string(&c->read_cursor, o); }
int link_call_read_path  (link_call_t *c, const char **o)    { return __r_path  (&c->read_cursor, o); }

/* ----------  public writer wrappers  ---------- */

void    link_writer_init  (link_writer_t *w, uint8_t *buf, size_t cap) { __w_init(w, buf, cap); }
ssize_t link_writer_finish(link_writer_t *w)                           { return __w_finish(w); }

void link_w_byte    (link_writer_t *w, uint8_t v)        { __w_byte(w, v); }
void link_w_bool    (link_writer_t *w, int v)            { __w_bool(w, v); }
void link_w_u32     (link_writer_t *w, uint32_t v)       { __w_u32(w, v);  }
void link_w_string  (link_writer_t *w, const char *s)    { __w_string(w, s); }
void link_w_path    (link_writer_t *w, const char *s)    { __w_path(w, s);   }
void link_w_variant_string(link_writer_t *w, const char *s) { __w_variant_string(w, s); }
void link_w_array_begin (link_writer_t *w, char ec)      { __w_array_begin(w, ec); }
void link_w_array_end   (link_writer_t *w)               { __w_array_end(w);       }
void link_w_struct_begin(link_writer_t *w)               { __w_struct_begin(w); }
void link_w_struct_end  (link_writer_t *w)               { __w_struct_end(w);   }

/* ----------  public reader wrappers  ---------- */

void link_reader_init(link_reader_t *r, const uint8_t *body, size_t len) { __r_init(r, body, len); }
int  link_r_byte  (link_reader_t *r, uint8_t  *o)     { return __r_byte  (r, o); }
int  link_r_bool  (link_reader_t *r, int      *o)     { return __r_bool  (r, o); }
int  link_r_u32   (link_reader_t *r, uint32_t *o)     { return __r_u32   (r, o); }
int  link_r_string(link_reader_t *r, const char **o)  { return __r_string(r, o); }
int  link_r_path  (link_reader_t *r, const char **o)  { return __r_path  (r, o); }
int  link_r_variant_begin (link_reader_t *r, char *type)     { return __r_variant_begin(r, type); }
int  link_r_skip_basic    (link_reader_t *r, char type)      { return __r_skip_basic(r, type); }
int  link_r_variant_string(link_reader_t *r, const char **o) { return __r_variant_string(r, o); }
int  link_r_align (link_reader_t *r, size_t n)        { return __r_align (r, n); }
int  link_r_array_begin(link_reader_t *r, size_t *e)  { return __r_array_begin(r, e); }
int  link_r_done  (const link_reader_t *r)            { return __r_done  (r);    }
size_t link_r_pos (const link_reader_t *r)            { return r->off;           }

/* ----------  dispatch entry point  ---------- */

/* ----------  replies to our own outbound calls  ---------- */

/* Hand a reply to whoever issued the matching link_connection_call().
 * Unmatched replies are dropped: a broker is free to send us things we
 * never asked for, and that is not a reason to drop the connection. */
static void deliver_reply(link_connection_t *conn, const struct link_msg *m)
{
	link_reply_cb_t  cb;
	link_reply_t     r;
	void            *userdata;
	int              i;

	for (i = 0; i < LINK_PENDING_CAP; i++) {
		if (conn->pending[i].used && conn->pending[i].serial == m->reply_serial)
			break;
	}
	if (i == LINK_PENDING_CAP) {
		return;
	}

	cb       = conn->pending[i].cb;
	userdata = conn->pending[i].userdata;
	conn->pending[i].used = 0;

	if (!cb)
		return;

	__msg_to_reply(&r, m);
	cb(conn, &r, userdata);
}

/* ----------  calls parked while their caller is identified  ---------- */

/* Every park gets a token that is never issued twice, so a resolver
 * answering late, twice, or after its connection went away resumes
 * nothing rather than whatever call has since taken the slot. */
static struct link_parked *park(link_connection_t *conn, const uint8_t *frame,
				size_t len, link_authz_t *tok)
{
	link_server_t *srv = conn->server;
	int i;

	if (!frame || !len || len > LINK_PARKED_MSG_MAX)
		return NULL;

	for (i = 0; i < LINK_PARKED_CAP; i++) {
		if (!srv->parked[i].tok)
			break;
	}
	if (i == LINK_PARKED_CAP)
		return NULL;

	srv->parked[i].tok  = ++srv->next_tok;
	srv->parked[i].conn = conn;
	srv->parked[i].len  = len;
	memcpy(srv->parked[i].buf, frame, len);
	*tok = srv->parked[i].tok;

	return &srv->parked[i];
}

static void unpark(struct link_parked *p)
{
	p->tok  = 0;
	p->conn = NULL;
}

void __dispatch_forget_conn(link_connection_t *conn)
{
	link_server_t *srv = conn->server;
	int i;

	/* Drop parked calls first.  A pending callback below may try to
	 * resolve one, and resuming a dispatch on a connection that is
	 * being torn down is no use to anyone; an invalidated slot makes
	 * that resolve a no-op instead. */
	if (srv) {
		for (i = 0; i < LINK_PARKED_CAP; i++) {
			if (srv->parked[i].conn == conn)
				unpark(&srv->parked[i]);
		}
	}

	for (i = 0; i < LINK_PENDING_CAP; i++) {
		if (conn->pending[i].used && conn->pending[i].cb)
			conn->pending[i].cb(conn, NULL, conn->pending[i].userdata);
		conn->pending[i].used = 0;
	}
}

static int dispatch_call(link_connection_t *conn, const struct link_msg *m,
			 const uint8_t *frame, size_t framelen,
			 const uid_t *known_uid);

void link_uid_resolved(link_server_t *server, link_authz_t tok, uid_t uid)
{
	uint8_t             buf[LINK_PARKED_MSG_MAX];
	struct link_parked *p = NULL;
	link_connection_t  *conn;
	struct link_msg     msg;
	size_t              len;
	int                 i;

	if (!server || !tok)
		return;

	for (i = 0; i < LINK_PARKED_CAP; i++) {
		if (server->parked[i].tok == tok) {
			p = &server->parked[i];
			break;
		}
	}
	if (!p)
		return;		/* stale handle, already answered */

	/* Copy the message out and free the slot before dispatching:
	 * the handler may park a call of its own. */
	conn = p->conn;
	len  = p->len;
	memcpy(buf, p->buf, len);
	unpark(p);

	if (!conn || __msg_parse(buf, len, &msg) <= 0)
		return;

	(void)dispatch_call(conn, &msg, NULL, 0, &uid);
}

int __dispatch_message(link_connection_t *conn, const struct link_msg *m, size_t framelen)
{
	if (m->type == LINK_MSG_METHOD_RETURN || m->type == LINK_MSG_ERROR) {
		deliver_reply(conn, m);
		return 0;
	}

	if (m->type != LINK_MSG_METHOD_CALL) {
		/* Signals from a client to PID 1 are nonsense; drop. */
		return 0;
	}

	return dispatch_call(conn, m, conn->rxbuf, framelen, NULL);
}

/* Who may invoke a privileged method.  Without an authorizer, only
 * root, which is what libink can decide on its own. */
static int caller_may(link_server_t *srv, uid_t uid)
{
	if (uid == LINK_UID_UNKNOWN)
		return 0;
	if (srv && srv->authorizer)
		return srv->authorizer(uid, srv->authz_userdata);

	return uid == 0;
}

/* Ask who is calling on a broker connection, where the message is the
 * only evidence.  Returns 0 with *uid set, 1 when the call was parked
 * and will be dispatched again once the resolver answers, -1 when the
 * caller cannot be identified, and -2 when we have no room to ask. */
#define CALLER_UID_BUSY (-2)

static int resolve_caller(link_connection_t *conn, const struct link_msg *m,
			  const uint8_t *frame, size_t framelen, uid_t *uid)
{
	link_server_t      *srv = conn->server;
	struct link_parked *p;
	link_authz_t        tok;
	int                 rc;

	if (!srv || !srv->uid_resolver || !m->sender)
		return -1;

	/* Enforce the rule link.h states, rather than trusting every
	 * resolver to remember it: a truncated sender key would let two
	 * callers share one identity. */
	if (strlen(m->sender) >= LINK_SENDER_MAX) {
		return -1;
	}

	/* Park first so the resolver has somewhere to answer, then let
	 * it release the slot immediately if it already knew. */
	p = park(conn, frame, framelen, &tok);
	if (!p)
		return CALLER_UID_BUSY;

	rc = srv->uid_resolver(conn, m->sender, tok, uid, srv->uid_userdata);
	if (rc != 1)
		unpark(p);

	return rc;
}

static int dispatch_call(link_connection_t *conn, const struct link_msg *m,
			 const uint8_t *frame, size_t framelen,
			 const uid_t *known_uid)
{
	struct link_object       *o;
	struct link_vtable_entry *e = NULL;
	const link_method_t      *meth;
	struct link_call          call;
	ssize_t                  blen;
	uid_t                    call_uid;
	int                      rc;

	/* What a handler sees via link_call_uid().  Unresolved on a broker
	 * connection until a privileged method forces the question. */
	call_uid = known_uid ? *known_uid : conn->peer_uid;

	if (!m->path || !m->member) {
		return __send_error(conn, m,
			"org.freedesktop.DBus.Error.InvalidArgs",
			"Method call without path or member");
	}


	/* Built-in DBus interfaces (Hello, Ping, Introspect, Properties)
	 * are handled here before object-tree lookup, which means they
	 * also run before the LINK_METHOD_PRIVILEGED authz gate further
	 * down.  The current set is read-only; do NOT introduce a
	 * state-changing built-in without first adding equivalent
	 * authorisation inside __handle_builtin. */
	rc = __handle_builtin(conn, m);
	if (rc >= 0)
		return rc;	/* 0 = handled OK, 1 = built-in but failed; <0 = not a built-in */

	o = find_object(conn->server, m->path);
	if (!o) {
		return __send_error(conn, m,
			"org.freedesktop.DBus.Error.UnknownObject",
			"No such object");
	}

	meth = resolve(o, m->interface, m->member, &e);
	if (!meth) {
		return __send_error(conn, m,
			"org.freedesktop.DBus.Error.UnknownMethod",
			"No such method on this object");
	}

	/* Validate signature: client must match the declared in_sig. */
	{
		const char *got = m->signature ? m->signature : "";
		const char *want = meth->in_sig ? meth->in_sig : "";

		if (strcmp(got, want) != 0) {
			return __send_error(conn, m,
				"org.freedesktop.DBus.Error.InvalidArgs",
				"Argument signature mismatch");
		}
	}

	/* Per-method authorization.  PRIVILEGED methods require uid 0.
	 * On an ordinary connection the peer's uid was captured via
	 * SO_PEERCRED at accept time and verified against the AUTH
	 * EXTERNAL claim, so conn->peer_uid is the answer.  A broker
	 * connection carries every caller at once, so who is asking has
	 * to be established per message, which may park the call. */
	if (meth->flags & LINK_METHOD_PRIVILEGED) {
		if (conn->broker && !known_uid) {
			rc = resolve_caller(conn, m, frame, framelen, &call_uid);
			if (rc == 1)
				return 0;	/* parked, resumed later */

			if (rc == CALLER_UID_BUSY) {
				/* Not a permission problem: root may well
				 * be asking, we just have no slot to find
				 * out in.  Say so, it is retryable. */
				return __send_error(conn, m,
					"org.freedesktop.DBus.Error.LimitsExceeded",
					"Too many calls awaiting authorization");
			}
			if (rc < 0)
				call_uid = (uid_t)-1;
		}

		if (!caller_may(conn->server, call_uid)) {
			return __send_error(conn, m,
				"org.freedesktop.DBus.Error.AccessDenied",
				"Caller is not privileged for this method");
		}
	}

	memset(&call, 0, sizeof(call));
	call.conn     = conn;
	call.uid      = call_uid;
	call.incoming = *m;
	__r_init(&call.read_cursor, m->body, m->body_avail);

	rc = meth->handler(&call, e->userdata);
	if (rc < 0 && !call.reply_consumed && !call.error_sent) {
		/* Handler returned an error without sending one. */
		__send_error(conn, m,
				"org.freedesktop.DBus.Error.Failed",
				"Handler failed");
		return 0;
	}

	if (!call.reply_consumed && !call.error_sent) {
		/* Handler returned 0 but never produced a reply; treat as
		 * empty reply with out_sig "". */
		__send_method_return(conn, m, NULL, NULL, 0);
		return 0;
	}

	if (call.reply_consumed && !call.error_sent) {
		blen = __w_finish(&call.reply_writer);
		if (blen < 0)
			return __send_error(conn, m,
				"org.freedesktop.DBus.Error.Failed",
				"Reply marshalling overflow");
		return __send_method_return(conn, m, meth->out_sig,
					       conn->txbuf, (size_t)blen);
	}

	return 0;
}
