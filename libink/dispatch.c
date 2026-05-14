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

#include "ink-internal.h"

/* ----------  object/vtable registration  ---------- */

static struct ink_object *find_object(ink_server_t *srv, const char *path)
{
	struct ink_object *o;

	TAILQ_FOREACH(o, &srv->objects, link)
		if (strcmp(o->path, path) == 0)
			return o;
	return NULL;
}

int ink_server_add_object(ink_server_t *srv, const char *path,
			  const ink_vtable_t *vt, void *userdata)
{
	struct ink_object        *o;
	struct ink_vtable_entry  *e;
	size_t                    plen;

	if (!srv || !path || !*path || !vt || !vt->interface) {
		errno = EINVAL;
		return -1;
	}
	plen = strlen(path);
	if (plen >= INK_PATH_MAX) {
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

static const ink_method_t *find_method(const ink_vtable_t *vt, const char *name)
{
	const ink_method_t *m;

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
static const ink_method_t *resolve(struct ink_object *o,
				   const char *iface, const char *member,
				   struct ink_vtable_entry **out_e)
{
	struct ink_vtable_entry *e;
	const ink_method_t      *m;

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

static int send_all(int fd, const uint8_t *buf, size_t len)
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

int ink__send_method_return(ink_connection_t *conn, const struct ink_msg *req,
			    const char *out_sig,
			    const uint8_t *body, size_t body_len)
{
	uint8_t hdr[512];
	ssize_t hlen;
	uint32_t serial = ++conn->next_serial;

	hlen = ink__msg_build_return(hdr, sizeof(hdr), serial,
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

int ink__send_error(ink_connection_t *conn, const struct ink_msg *req,
		    const char *error_name, const char *text)
{
	uint8_t  hdr[512];
	uint8_t  body[256];
	ssize_t  hlen;
	size_t   blen = 0;
	uint32_t serial = ++conn->next_serial;
	const char *sig = NULL;

	if (text && *text) {
		struct ink_writer w;
		ssize_t n;

		ink__w_init(&w, body, sizeof(body));
		ink__w_string(&w, text);
		n = ink__w_finish(&w);
		if (n < 0) {
			errno = EMSGSIZE;
			return -1;
		}
		blen = (size_t)n;
		sig  = "s";
	}

	hlen = ink__msg_build_error(hdr, sizeof(hdr), serial,
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

/* ----------  ink_call public surface  ---------- */

const char *ink_call_path     (const ink_call_t *c) { return c ? c->incoming.path      : NULL; }
const char *ink_call_interface(const ink_call_t *c) { return c ? c->incoming.interface : NULL; }
const char *ink_call_member   (const ink_call_t *c) { return c ? c->incoming.member    : NULL; }
uid_t       ink_call_uid      (const ink_call_t *c) { return c ? c->conn->peer_uid     : (uid_t)-1; }

ink_writer_t *ink_call_reply(ink_call_t *call)
{
	if (!call || call->reply_consumed || call->error_sent)
		return NULL;
	call->reply_consumed = 1;
	ink__w_init(&call->reply_writer,
		    call->conn->txbuf, sizeof(call->conn->txbuf));
	return &call->reply_writer;
}

int ink_call_reply_error(ink_call_t *call, const char *name, const char *message)
{
	if (!call || call->error_sent) {
		errno = EINVAL;
		return -1;
	}
	call->error_sent = 1;
	return ink__send_error(call->conn, &call->incoming, name, message);
}

/* ----------  public reader wrappers  ---------- */

int ink_call_read_byte  (ink_call_t *c, uint8_t *o)        { return ink__r_byte  (&c->read_cursor, o); }
int ink_call_read_bool  (ink_call_t *c, int *o)            { return ink__r_bool  (&c->read_cursor, o); }
int ink_call_read_u32   (ink_call_t *c, uint32_t *o)       { return ink__r_u32   (&c->read_cursor, o); }
int ink_call_read_string(ink_call_t *c, const char **o)    { return ink__r_string(&c->read_cursor, o); }
int ink_call_read_path  (ink_call_t *c, const char **o)    { return ink__r_path  (&c->read_cursor, o); }

/* ----------  public writer wrappers  ---------- */

void ink_w_byte    (ink_writer_t *w, uint8_t v)        { ink__w_byte(w, v); }
void ink_w_bool    (ink_writer_t *w, int v)            { ink__w_bool(w, v); }
void ink_w_u32     (ink_writer_t *w, uint32_t v)       { ink__w_u32(w, v);  }
void ink_w_string  (ink_writer_t *w, const char *s)    { ink__w_string(w, s); }
void ink_w_path    (ink_writer_t *w, const char *s)    { ink__w_path(w, s);   }
void ink_w_array_begin (ink_writer_t *w, char ec)      { ink__w_array_begin(w, ec); }
void ink_w_array_end   (ink_writer_t *w)               { ink__w_array_end(w);       }
void ink_w_struct_begin(ink_writer_t *w)               { ink__w_struct_begin(w); }
void ink_w_struct_end  (ink_writer_t *w)               { ink__w_struct_end(w);   }

/* ----------  dispatch entry point  ---------- */

int ink__dispatch_message(ink_connection_t *conn, const struct ink_msg *m)
{
	struct ink_object       *o;
	struct ink_vtable_entry *e = NULL;
	const ink_method_t      *meth;
	struct ink_call          call;
	ssize_t                  blen;
	int                      rc;

	if (m->type != INK_MSG_METHOD_CALL) {
		/* Signals and replies from a client to PID 1 are nonsense;
		 * silently drop. */
		return 0;
	}

	if (!m->path || !m->member) {
		return ink__send_error(conn, m,
			"org.freedesktop.DBus.Error.InvalidArgs",
			"Method call without path or member");
	}

	/* Built-in DBus interfaces (Hello, Ping, Introspect, Properties)
	 * are handled here before object-tree lookup. */
	rc = ink__handle_builtin(conn, m);
	if (rc >= 0)
		return rc;	/* 0 = handled OK, 1 = built-in but failed; <0 = not a built-in */

	o = find_object(conn->server, m->path);
	if (!o) {
		return ink__send_error(conn, m,
			"org.freedesktop.DBus.Error.UnknownObject",
			"No such object");
	}

	meth = resolve(o, m->interface, m->member, &e);
	if (!meth) {
		return ink__send_error(conn, m,
			"org.freedesktop.DBus.Error.UnknownMethod",
			"No such method on this object");
	}

	/* Validate signature: client must match the declared in_sig. */
	{
		const char *got = m->signature ? m->signature : "";
		const char *want = meth->in_sig ? meth->in_sig : "";

		if (strcmp(got, want) != 0)
			return ink__send_error(conn, m,
				"org.freedesktop.DBus.Error.InvalidArgs",
				"Argument signature mismatch");
	}

	memset(&call, 0, sizeof(call));
	call.conn     = conn;
	call.incoming = *m;
	ink__r_init(&call.read_cursor, m->body, m->body_avail);

	rc = meth->handler(&call, e->userdata);
	if (rc < 0 && !call.reply_consumed && !call.error_sent) {
		/* Handler returned an error without sending one. */
		ink__send_error(conn, m,
				"org.freedesktop.DBus.Error.Failed",
				"Handler failed");
		return 0;
	}

	if (!call.reply_consumed && !call.error_sent) {
		/* Handler returned 0 but never produced a reply; treat as
		 * empty reply with out_sig "". */
		ink__send_method_return(conn, m, NULL, NULL, 0);
		return 0;
	}

	if (call.reply_consumed && !call.error_sent) {
		blen = ink__w_finish(&call.reply_writer);
		if (blen < 0)
			return ink__send_error(conn, m,
				"org.freedesktop.DBus.Error.Failed",
				"Reply marshalling overflow");
		return ink__send_method_return(conn, m, meth->out_sig,
					       conn->txbuf, (size_t)blen);
	}

	return 0;
}
