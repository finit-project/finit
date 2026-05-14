/* libink — built-in implementations of the well-known
 * org.freedesktop.DBus.* interfaces (Hello, Peer, Introspectable).
 *
 * These run before object-tree lookup in the dispatcher; returning
 * 0 means "handled, reply sent"; <0 means "not a built-in, fall
 * through to user-registered handlers".
 *
 * Copyright (c) 2026  Joachim Wiberg <troglobit@gmail.com>
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "ink-internal.h"

/* ---------- helpers ---------- */

static int member_is(const struct ink_msg *m, const char *iface, const char *member)
{
	if (!m->member || strcmp(m->member, member) != 0)
		return 0;
	if (m->interface && strcmp(m->interface, iface) != 0)
		return 0;
	return 1;
}

static int send_string_reply(ink_connection_t *conn, const struct ink_msg *req,
			     const char *s)
{
	struct ink_writer w;
	ssize_t           blen;

	ink__w_init(&w, conn->txbuf, sizeof(conn->txbuf));
	ink__w_string(&w, s);
	blen = ink__w_finish(&w);
	if (blen < 0) {
		errno = EMSGSIZE;
		return -1;
	}
	return ink__send_method_return(conn, req, "s", conn->txbuf, (size_t)blen);
}

/* ---------- Hello ---------- */

static int handle_hello(ink_connection_t *conn, const struct ink_msg *m)
{
	if (!conn->unique_name[0]) {
		uint32_t n = ++conn->server->next_unique_id;

		snprintf(conn->unique_name, sizeof(conn->unique_name),
			 ":1.%u", n);
	}
	return send_string_reply(conn, m, conn->unique_name);
}

/* ---------- Ping / GetMachineId ---------- */

static int handle_ping(ink_connection_t *conn, const struct ink_msg *m)
{
	return ink__send_method_return(conn, m, NULL, NULL, 0);
}

static int handle_get_machine_id(ink_connection_t *conn, const struct ink_msg *m)
{
	/* D-Bus mandates a 32-char hex machine-id.  Use the per-server
	 * GUID-style identifier we already generate for each connection,
	 * promoted to a per-server constant on first call.  Good enough
	 * for the brokerless case where clients use this only as a
	 * sanity hint. */
	static char machine_id[33];

	if (!machine_id[0])
		ink__auth_generate_guid(machine_id);
	return send_string_reply(conn, m, machine_id);
}

/* ---------- Introspect ---------- */

struct xbuf {
	char  *buf;
	size_t cap;
	size_t off;
	int    err;
};

static void xprintf(struct xbuf *x, const char *fmt, ...)
{
	va_list ap;
	int     n;

	if (x->err)
		return;
	va_start(ap, fmt);
	n = vsnprintf(x->buf + x->off, x->cap - x->off, fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t)n >= x->cap - x->off) {
		x->err = 1;
		return;
	}
	x->off += (size_t)n;
}

/* Emit a single <method> stanza for one method definition. */
static void emit_method(struct xbuf *x, const ink_method_t *m)
{
	const char *p;

	xprintf(x, "    <method name=\"%s\">\n", m->name);
	for (p = m->in_sig ? m->in_sig : ""; *p; p++)
		xprintf(x, "      <arg type=\"%c\" direction=\"in\"/>\n", *p);
	for (p = m->out_sig ? m->out_sig : ""; *p; p++)
		xprintf(x, "      <arg type=\"%c\" direction=\"out\"/>\n", *p);
	xprintf(x, "    </method>\n");
}

/* Introspection limitation: emit_method prints one <arg> per
 * character of the signature, which is wrong for compound types
 * (an "a(ss)" arg appears as four args).  Good enough for the
 * "s", "u", "as" signatures we expose today; replace with a
 * signature parser when the first compound argument lands. */

static const char STANDARD_INTERFACES_XML[] =
	"  <interface name=\"org.freedesktop.DBus.Introspectable\">\n"
	"    <method name=\"Introspect\">\n"
	"      <arg name=\"data\" type=\"s\" direction=\"out\"/>\n"
	"    </method>\n"
	"  </interface>\n"
	"  <interface name=\"org.freedesktop.DBus.Peer\">\n"
	"    <method name=\"Ping\"/>\n"
	"    <method name=\"GetMachineId\">\n"
	"      <arg name=\"machine_uuid\" type=\"s\" direction=\"out\"/>\n"
	"    </method>\n"
	"  </interface>\n";

/* Is `child` a path under `parent`?  If so, write the first segment
 * of the relative remainder into out (max outsz) and return 1. */
static int child_segment(const char *parent, const char *child,
			 char *out, size_t outsz)
{
	size_t plen = strlen(parent);
	const char *rest, *slash;
	size_t seglen;

	if (strncmp(parent, child, plen) != 0)
		return 0;
	/* Special case for "/" */
	if (plen == 1 && parent[0] == '/')
		rest = child + 1;
	else if (child[plen] != '/')
		return 0;
	else
		rest = child + plen + 1;
	if (!*rest)
		return 0;

	slash  = strchr(rest, '/');
	seglen = slash ? (size_t)(slash - rest) : strlen(rest);
	if (seglen + 1 > outsz)
		return 0;
	memcpy(out, rest, seglen);
	out[seglen] = '\0';
	return 1;
}

static int handle_introspect(ink_connection_t *conn, const struct ink_msg *m)
{
	static char  xml[8192];	/* static keeps the stack small in PID 1 */
	struct xbuf  x = { .buf = xml, .cap = sizeof(xml) };
	struct ink_object *o;
	const char  *path = m->path;

	xprintf(&x,
		"<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n"
		"  \"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
		"<node>\n");

	xprintf(&x, "%s", STANDARD_INTERFACES_XML);

	o = NULL;
	{
		struct ink_object *p;

		TAILQ_FOREACH(p, &conn->server->objects, link) {
			if (strcmp(p->path, path) == 0) {
				o = p;
				break;
			}
		}
	}

	if (o) {
		struct ink_vtable_entry *e;
		const ink_method_t *meth;

		TAILQ_FOREACH(e, &o->vtables, link) {
			xprintf(&x, "  <interface name=\"%s\">\n",
				e->vt->interface);
			if (e->vt->methods)
				for (meth = e->vt->methods; meth->name; meth++)
					emit_method(&x, meth);
			xprintf(&x, "  </interface>\n");
		}
	}

	{
		struct ink_object *p;
		char prev_seg[INK_PATH_MAX] = { 0 };
		char seg     [INK_PATH_MAX];

		TAILQ_FOREACH(p, &conn->server->objects, link) {
			if (!child_segment(path, p->path, seg, sizeof(seg)))
				continue;
			if (strcmp(prev_seg, seg) == 0)
				continue;
			xprintf(&x, "  <node name=\"%s\"/>\n", seg);
			memcpy(prev_seg, seg, sizeof(prev_seg));
		}
	}

	xprintf(&x, "</node>\n");

	if (x.err)
		return ink__send_error(conn, m,
			"org.freedesktop.DBus.Error.Failed",
			"Introspection XML overflow");

	return send_string_reply(conn, m, xml);
}

/* ---------- entry point ---------- */

int ink__handle_builtin(ink_connection_t *conn, const struct ink_msg *m)
{
	if (member_is(m, "org.freedesktop.DBus", "Hello") &&
	    m->path && strcmp(m->path, "/org/freedesktop/DBus") == 0)
		return handle_hello(conn, m);

	if (member_is(m, "org.freedesktop.DBus.Peer", "Ping"))
		return handle_ping(conn, m);

	if (member_is(m, "org.freedesktop.DBus.Peer", "GetMachineId"))
		return handle_get_machine_id(conn, m);

	if (member_is(m, "org.freedesktop.DBus.Introspectable", "Introspect"))
		return handle_introspect(conn, m);

	return -1;	/* not a built-in */
}
