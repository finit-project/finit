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

#include "internal.h"

/* ---------- helpers ---------- */

static int member_is(const struct link_msg *m, const char *iface, const char *member)
{
	if (!m->member || strcmp(m->member, member) != 0)
		return 0;
	if (m->interface && strcmp(m->interface, iface) != 0)
		return 0;
	return 1;
}

static int send_string_reply(link_connection_t *conn, const struct link_msg *req,
			     const char *s)
{
	struct link_writer w;
	ssize_t           blen;

	__w_init(&w, conn->txbuf, sizeof(conn->txbuf));
	__w_string(&w, s);
	blen = __w_finish(&w);
	if (blen < 0) {
		errno = EMSGSIZE;
		return -1;
	}
	return __send_method_return(conn, req, "s", conn->txbuf, (size_t)blen);
}

/* ---------- Hello ---------- */

static int handle_hello(link_connection_t *conn, const struct link_msg *m)
{
	if (!conn->unique_name[0]) {
		uint32_t n = ++conn->server->next_unique_id;

		snprintf(conn->unique_name, sizeof(conn->unique_name),
			 ":1.%u", n);
	}
	return send_string_reply(conn, m, conn->unique_name);
}

/* ---------- Ping / GetMachineId ---------- */

static int handle_ping(link_connection_t *conn, const struct link_msg *m)
{
	return __send_method_return(conn, m, NULL, NULL, 0);
}

static int handle_get_machine_id(link_connection_t *conn, const struct link_msg *m)
{
	/* D-Bus mandates a 32-char hex machine-id.  Use the per-server
	 * GUID-style identifier we already generate for each connection,
	 * promoted to a per-server constant on first call.  Good enough
	 * for the brokerless case where clients use this only as a
	 * sanity hint. */
	static char machine_id[33];

	if (!machine_id[0])
		__auth_generate_guid(machine_id);
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

/*
 * Advance past one single complete type in a D-Bus signature:
 * a basic type code, 'a' + element type, or a bracketed group.
 * Signatures come from our own vtables, so trust them; an
 * unterminated group just stops at NUL.
 */
static const char *sig_next(const char *p)
{
	while (*p == 'a')	/* array prefixes, then element type */
		p++;
	if (*p == '(' || *p == '{') {
		char close = *p == '(' ? ')' : '}';

		for (p++; *p && *p != close; p = sig_next(p))
			;
	}
	return *p ? p + 1 : p;	/* NUL: unterminated group, stop here */
}

static void emit_args(struct xbuf *x, const char *sig, const char *dir)
{
	const char *p, *e;

	for (p = sig; p && *p; p = e) {
		e = sig_next(p);
		xprintf(x, "      <arg type=\"%.*s\" direction=\"%s\"/>\n",
			(int)(e - p), p, dir);
	}
}

/* Emit a single <method> stanza for one method definition. */
static void emit_method(struct xbuf *x, const link_method_t *m)
{
	xprintf(x, "    <method name=\"%s\">\n", m->name);
	emit_args(x, m->in_sig, "in");
	emit_args(x, m->out_sig, "out");
	xprintf(x, "    </method>\n");
}

static void emit_property(struct xbuf *x, const link_property_t *p)
{
	/* Setters are not implemented, so every property advertises
	 * access="read" today.  When Properties.Set lands, switch on
	 * a writable flag. */
	xprintf(x, "    <property name=\"%s\" type=\"%s\" access=\"read\"/>\n",
		p->name, p->sig ? p->sig : "s");
}

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
	"  </interface>\n"
	"  <interface name=\"org.freedesktop.DBus.Properties\">\n"
	"    <method name=\"Get\">\n"
	"      <arg name=\"interface\" type=\"s\" direction=\"in\"/>\n"
	"      <arg name=\"property\"  type=\"s\" direction=\"in\"/>\n"
	"      <arg name=\"value\"     type=\"v\" direction=\"out\"/>\n"
	"    </method>\n"
	"    <method name=\"GetAll\">\n"
	"      <arg name=\"interface\" type=\"s\" direction=\"in\"/>\n"
	"      <arg name=\"props\"     type=\"a{sv}\" direction=\"out\"/>\n"
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

static int handle_introspect(link_connection_t *conn, const struct link_msg *m)
{
	static char  xml[8192];	/* static keeps the stack small in PID 1 */
	struct xbuf  x = { .buf = xml, .cap = sizeof(xml) };
	struct link_object *o;
	const char  *path = m->path;

	xprintf(&x,
		"<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n"
		"  \"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
		"<node>\n");

	xprintf(&x, "%s", STANDARD_INTERFACES_XML);

	o = NULL;
	{
		struct link_object *p;

		TAILQ_FOREACH(p, &conn->server->objects, link) {
			if (strcmp(p->path, path) == 0) {
				o = p;
				break;
			}
		}
	}

	if (o) {
		struct link_vtable_entry *e;
		const link_method_t *meth;

		TAILQ_FOREACH(e, &o->vtables, link) {
			const link_property_t *prop;

			xprintf(&x, "  <interface name=\"%s\">\n",
				e->vt->interface);
			if (e->vt->methods)
				for (meth = e->vt->methods; meth->name; meth++)
					emit_method(&x, meth);
			if (e->vt->properties)
				for (prop = e->vt->properties; prop->name; prop++)
					emit_property(&x, prop);
			xprintf(&x, "  </interface>\n");
		}
	}

	{
		struct link_object *p;
		char prev_seg[LINK_PATH_MAX] = { 0 };
		char seg     [LINK_PATH_MAX];

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
		return __send_error(conn, m,
			"org.freedesktop.DBus.Error.Failed",
			"Introspection XML overflow");

	return send_string_reply(conn, m, xml);
}

/* ---------- Properties.Get / GetAll ---------- */

/* Find the (object, vtable-entry) pair matching `path` and `interface`.
 * Returns NULL if the path is unknown or the interface isn't exposed
 * on it. */
static struct link_vtable_entry *
find_vtable(link_connection_t *conn, const char *path, const char *interface)
{
	struct link_object *o;

	if (!path || !interface)
		return NULL;
	TAILQ_FOREACH(o, &conn->server->objects, link) {
		struct link_vtable_entry *e;

		if (strcmp(o->path, path) != 0)
			continue;
		TAILQ_FOREACH(e, &o->vtables, link) {
			if (strcmp(e->vt->interface, interface) == 0)
				return e;
		}
	}
	return NULL;
}

static int handle_properties_get(link_connection_t *conn, const struct link_msg *m)
{
	const char *iface, *prop_name;
	struct link_reader r;
	struct link_writer w;
	struct link_vtable_entry *e;
	const link_property_t   *p;
	ssize_t blen;

	if (!m->signature || strcmp(m->signature, "ss") != 0)
		return __send_error(conn, m,
			"org.freedesktop.DBus.Error.InvalidArgs",
			"Properties.Get takes (interface, property)");

	__r_init(&r, m->body, m->body_avail);
	if (__r_string(&r, &iface) < 0 || __r_string(&r, &prop_name) < 0)
		return __send_error(conn, m,
			"org.freedesktop.DBus.Error.InvalidArgs",
			"Malformed argument");

	e = find_vtable(conn, m->path, iface);
	if (!e || !e->vt->properties)
		return __send_error(conn, m,
			"org.freedesktop.DBus.Error.UnknownInterface",
			"No such interface on this object");

	for (p = e->vt->properties; p->name; p++) {
		if (strcmp(p->name, prop_name) != 0)
			continue;
		if (!p->getter)
			break;
		__w_init(&w, conn->txbuf, sizeof(conn->txbuf));
		__w_sig(&w, p->sig ? p->sig : "s");
		if (p->getter(&w, e->userdata) != 0 || (blen = __w_finish(&w)) < 0)
			return __send_error(conn, m,
				"org.freedesktop.DBus.Error.Failed",
				"Property getter failed");
		return __send_method_return(conn, m, "v",
					   conn->txbuf, (size_t)blen);
	}

	return __send_error(conn, m,
		"org.freedesktop.DBus.Error.UnknownProperty",
		"No such property on this interface");
}

static int handle_properties_get_all(link_connection_t *conn, const struct link_msg *m)
{
	const char *iface;
	struct link_reader r;
	struct link_writer w;
	struct link_vtable_entry *e;
	const link_property_t   *p;
	ssize_t blen;

	if (!m->signature || strcmp(m->signature, "s") != 0)
		return __send_error(conn, m,
			"org.freedesktop.DBus.Error.InvalidArgs",
			"Properties.GetAll takes one string");

	__r_init(&r, m->body, m->body_avail);
	if (__r_string(&r, &iface) < 0)
		return __send_error(conn, m,
			"org.freedesktop.DBus.Error.InvalidArgs",
			"Malformed argument");

	e = find_vtable(conn, m->path, iface);
	if (!e)
		return __send_error(conn, m,
			"org.freedesktop.DBus.Error.UnknownInterface",
			"No such interface on this object");

	__w_init(&w, conn->txbuf, sizeof(conn->txbuf));
	__w_array_begin(&w, '{');
	if (e->vt->properties) {
		for (p = e->vt->properties; p->name; p++) {
			if (!p->getter)
				continue;
			__w_struct_begin(&w);
			__w_string(&w, p->name);
			__w_sig(&w, p->sig ? p->sig : "s");
			if (p->getter(&w, e->userdata) != 0)
				return __send_error(conn, m,
					"org.freedesktop.DBus.Error.Failed",
					"Property getter failed");
			__w_struct_end(&w);
		}
	}
	__w_array_end(&w);

	blen = __w_finish(&w);
	if (blen < 0)
		return __send_error(conn, m,
			"org.freedesktop.DBus.Error.Failed",
			"Reply too large");

	return __send_method_return(conn, m, "a{sv}",
				   conn->txbuf, (size_t)blen);
}

/* ---------- AddMatch / RemoveMatch ---------- */

static int handle_add_match(link_connection_t *conn, const struct link_msg *m)
{
	const char *rule;
	struct link_reader r;

	if (!m->signature || strcmp(m->signature, "s") != 0)
		return __send_error(conn, m,
			"org.freedesktop.DBus.Error.InvalidArgs",
			"AddMatch takes a single string");

	__r_init(&r, m->body, m->body_avail);
	if (__r_string(&r, &rule) < 0)
		return __send_error(conn, m,
			"org.freedesktop.DBus.Error.InvalidArgs",
			"Malformed argument");

	if (__match_add(conn, rule) < 0) {
		if (errno == ENOSPC)
			return __send_error(conn, m,
				"org.freedesktop.DBus.Error.LimitsExceeded",
				"Too many active match rules");
		return __send_error(conn, m,
			"org.freedesktop.DBus.Error.MatchRuleInvalid",
			"Unrecognised key or malformed rule");
	}
	return __send_method_return(conn, m, NULL, NULL, 0);
}

static int handle_remove_match(link_connection_t *conn, const struct link_msg *m)
{
	const char *rule;
	struct link_reader r;

	if (!m->signature || strcmp(m->signature, "s") != 0)
		return __send_error(conn, m,
			"org.freedesktop.DBus.Error.InvalidArgs",
			"RemoveMatch takes a single string");

	__r_init(&r, m->body, m->body_avail);
	if (__r_string(&r, &rule) < 0)
		return __send_error(conn, m,
			"org.freedesktop.DBus.Error.InvalidArgs",
			"Malformed argument");

	if (__match_remove(conn, rule) < 0)
		return __send_error(conn, m,
			"org.freedesktop.DBus.Error.MatchRuleNotFound",
			"No such match rule on this connection");

	return __send_method_return(conn, m, NULL, NULL, 0);
}

/* ---------- entry point ---------- */

int __handle_builtin(link_connection_t *conn, const struct link_msg *m)
{
	/* Hello and AddMatch/RemoveMatch are per-connection state, and on
	 * a broker link the connection is shared by every caller: one
	 * sender could exhaust the match cap or drop another's rule.
	 * Naming and subscription belong to the broker for its own
	 * clients, so we do not answer these there. */
	if (conn->broker && m->member &&
	    (!strcmp(m->member, "Hello") ||
	     !strcmp(m->member, "AddMatch") ||
	     !strcmp(m->member, "RemoveMatch"))) {
		__dbg("%s is the broker's to answer, not ours", m->member);
		return __send_error(conn, m,
			"org.freedesktop.DBus.Error.AccessDenied",
			"Handled by the message bus, not by this peer");
	}

	if (member_is(m, "org.freedesktop.DBus", "Hello") &&
	    m->path && strcmp(m->path, "/org/freedesktop/DBus") == 0)
		return handle_hello(conn, m);

	if (member_is(m, "org.freedesktop.DBus", "AddMatch") &&
	    m->path && strcmp(m->path, "/org/freedesktop/DBus") == 0)
		return handle_add_match(conn, m);

	if (member_is(m, "org.freedesktop.DBus", "RemoveMatch") &&
	    m->path && strcmp(m->path, "/org/freedesktop/DBus") == 0)
		return handle_remove_match(conn, m);

	if (member_is(m, "org.freedesktop.DBus.Peer", "Ping"))
		return handle_ping(conn, m);

	if (member_is(m, "org.freedesktop.DBus.Peer", "GetMachineId"))
		return handle_get_machine_id(conn, m);

	if (member_is(m, "org.freedesktop.DBus.Introspectable", "Introspect"))
		return handle_introspect(conn, m);

	if (member_is(m, "org.freedesktop.DBus.Properties", "Get"))
		return handle_properties_get(conn, m);

	if (member_is(m, "org.freedesktop.DBus.Properties", "GetAll"))
		return handle_properties_get_all(conn, m);

	return -1;	/* not a built-in */
}
