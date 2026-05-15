/* Finit-side glue between the event loop and libink.
 *
 * Owns the libink server, accepts new peers, drives each peer's
 * state machine, and registers the Finit-specific D-Bus object
 * tree (org.finit.Manager1 et al).  Nothing in libink/ depends on
 * finit-internal types: the boundary lives in this file, by design.
 *
 * Copyright (c) 2026  Joachim Wiberg <troglobit@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "config.h"

#ifdef HAVE_DBUS

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <uev/uev.h>

#include "ink.h"

#include "finit.h"
#include "conf.h"
#include "log.h"
#include "private.h"
#include "service.h"
#include "sig.h"
#include "sm.h"
#include "svc.h"

#define DBUS_MAX_PEERS 64

struct peer {
	uev_t              watcher;
	ink_connection_t  *conn;
	TAILQ_ENTRY(peer)  link;
};

static TAILQ_HEAD(, peer) peers = TAILQ_HEAD_INITIALIZER(peers);
static ink_server_t      *server;
static uev_t              accept_watcher;
static size_t             peer_count;

static void peer_drop(struct peer *p)
{
	uev_io_stop(&p->watcher);
	ink_connection_close(p->conn);
	TAILQ_REMOVE(&peers, p, link);
	peer_count--;
	free(p);
}

static void peer_cb(uev_t *w, void *arg, int events)
{
	struct peer *p = arg;

	(void)w;

	if (UEV_ERROR == events) {
		peer_drop(p);
		return;
	}

	if (ink_connection_process(p->conn) < 0)
		peer_drop(p);
}

static void accept_cb(uev_t *w, void *arg, int events)
{
	(void)arg;

	if (UEV_ERROR == events) {
		err(1, "D-Bus accept watcher error");
		return;
	}

	for (;;) {
		ink_connection_t *conn = NULL;
		struct peer *p;

		if (ink_server_accept(server, &conn) < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK)
				err(1, "Failed accepting D-Bus client");
			break;
		}

		if (peer_count >= DBUS_MAX_PEERS) {
			logit(LOG_WARNING, "D-Bus peer cap reached (%zu), dropping",
			      peer_count);
			ink_connection_close(conn);
			continue;
		}

		p = calloc(1, sizeof(*p));
		if (!p) {
			ink_connection_close(conn);
			err(1, "Out of memory accepting D-Bus client");
			break;
		}

		p->conn = conn;
		TAILQ_INSERT_TAIL(&peers, p, link);
		peer_count++;

		if (uev_io_init(w->ctx, &p->watcher, peer_cb, p,
				ink_connection_get_fd(conn), UEV_READ)) {
			err(1, "Failed registering D-Bus peer watcher");
			peer_drop(p);
		}
	}
}

/* ---------- org.finit.Manager1 ---------- */

static int manager_list_services(ink_call_t *call, void *userdata)
{
	ink_writer_t *w;
	svc_t        *iter = NULL;
	svc_t        *svc;

	(void)userdata;

	w = ink_call_reply(call);
	if (!w)
		return -1;

	ink_w_array_begin(w, 's');
	for (svc = svc_iterator(&iter, 1); svc; svc = svc_iterator(&iter, 0)) {
		char ident[MAX_IDENT_LEN];

		svc_ident(svc, ident, sizeof(ident));
		ink_w_string(w, ident);
	}
	ink_w_array_end(w);
	return 0;
}

/* Service-control helpers used by Start/Stop/Restart/Reload.  These
 * mirror the static helpers in api.c — kept private here so api.c
 * stays untouched in this increment. */

static int dbus_apply_stop(svc_t *svc, void *user_data)
{
	(void)user_data;
	if (!svc)
		return 1;
	service_timeout_cancel(svc);
	svc_stop(svc);
	service_step(svc);
	if (!IS_RESERVED_RUNLEVEL(runlevel))
		service_step_all(SVC_TYPE_ANY);
	return 0;
}

static int dbus_apply_start(svc_t *svc, void *user_data)
{
	(void)user_data;
	if (!svc)
		return 1;
	service_timeout_cancel(svc);
	svc_start(svc);
	service_step(svc);
	if (!IS_RESERVED_RUNLEVEL(runlevel))
		service_step_all(SVC_TYPE_ANY);
	return 0;
}

static int dbus_apply_restart(svc_t *svc, void *user_data)
{
	if (!svc)
		return 1;
	if (!svc_is_running(svc))
		return dbus_apply_start(svc, user_data);
	service_timeout_cancel(svc);
	service_stop(svc);
	service_step(svc);
	return 0;
}

struct dispatch_ctx {
	int (*action)(svc_t *, void *);
	int   matched;
};

static int dispatch_found(svc_t *svc, void *udata)
{
	struct dispatch_ctx *ctx = udata;

	ctx->matched++;
	return ctx->action(svc, NULL);
}

static int dispatch_missing(char *job, char *id, void *udata)
{
	(void)job; (void)id; (void)udata;
	return 0;	/* don't penalise the return; we'll check ->matched */
}

/* Apply `action` to every service matched by `ident`.  Returns 0 if
 * at least one service matched and the action succeeded on all;
 * -1 if no service matched the identity (caller sends NoSuchService). */
static int dispatch_action(const char *ident,
			   int (*action)(svc_t *, void *))
{
	char buf[MAX_IDENT_LEN];
	struct dispatch_ctx ctx = { .action = action };
	int rc;

	if (!ident || !*ident || strlen(ident) >= sizeof(buf))
		return -1;
	memcpy(buf, ident, strlen(ident) + 1);
	rc = svc_parse_jobstr(buf, sizeof(buf), &ctx,
			      dispatch_found, dispatch_missing);
	if (ctx.matched == 0)
		return -1;
	return rc;
}

static int manager_take_string_method(ink_call_t *call,
				      int (*action)(svc_t *, void *))
{
	const char *ident;

	if (ink_call_read_string(call, &ident) < 0)
		return ink_call_reply_error(call,
			"org.freedesktop.DBus.Error.InvalidArgs",
			"expected (s)");
	if (dispatch_action(ident, action) != 0)
		return ink_call_reply_error(call,
			"org.finit.Error.NoSuchService", ident);

	(void)ink_call_reply(call);	/* empty reply */
	return 0;
}

static int manager_start  (ink_call_t *call, void *u) { (void)u; return manager_take_string_method(call, dbus_apply_start);   }
static int manager_stop   (ink_call_t *call, void *u) { (void)u; return manager_take_string_method(call, dbus_apply_stop);    }
static int manager_restart(ink_call_t *call, void *u) { (void)u; return manager_take_string_method(call, dbus_apply_restart); }

static int manager_reload(ink_call_t *call, void *userdata)
{
	(void)userdata;
	/*
	 * Same semantics as api.c: harmless no-op during bootstrap
	 * and shutdown, the client still sees success.
	 */
	if (IS_RESERVED_RUNLEVEL(runlevel))
		warnx("Ignoring reload in runlevel S and 6/0.");
	else
		sm_reload();
	(void)ink_call_reply(call);
	return 0;
}

static int manager_set_runlevel(ink_call_t *call, void *userdata)
{
	uint32_t lvl;

	(void)userdata;
	if (ink_call_read_u32(call, &lvl) < 0)
		return ink_call_reply_error(call,
			"org.freedesktop.DBus.Error.InvalidArgs",
			"expected (u)");
	if (lvl > 9 || lvl == INIT_LEVEL)
		return ink_call_reply_error(call,
			"org.freedesktop.DBus.Error.InvalidArgs",
			"runlevel must be 0-9 (excluding internal levels)");

	if (lvl == 0) halt = SHUT_OFF;
	if (lvl == 6) halt = SHUT_REBOOT;
	sm_runlevel((int)lvl);

	(void)ink_call_reply(call);
	return 0;
}

static int dbus_shutdown(ink_call_t *call, shutop_t target, int level)
{
	if (IS_RESERVED_RUNLEVEL(runlevel))
		return ink_call_reply_error(call,
			"org.finit.Error.WrongRunlevel",
			"Already in shutdown");
	halt = target;
	sm_runlevel(level);
	(void)ink_call_reply(call);
	return 0;
}

static int manager_reboot  (ink_call_t *c, void *u) { (void)u; return dbus_shutdown(c, SHUT_REBOOT, 6); }
static int manager_poweroff(ink_call_t *c, void *u) { (void)u; return dbus_shutdown(c, SHUT_OFF,    0); }
static int manager_halt    (ink_call_t *c, void *u) { (void)u; return dbus_shutdown(c, SHUT_HALT,   0); }

static const ink_method_t manager_methods[] = {
	{ .name = "ListServices", .in_sig = "",  .out_sig = "as",
	  .handler = manager_list_services },
	{ .name = "Start",        .in_sig = "s", .out_sig = "",
	  .flags = INK_METHOD_PRIVILEGED, .handler = manager_start },
	{ .name = "Stop",         .in_sig = "s", .out_sig = "",
	  .flags = INK_METHOD_PRIVILEGED, .handler = manager_stop },
	{ .name = "Restart",      .in_sig = "s", .out_sig = "",
	  .flags = INK_METHOD_PRIVILEGED, .handler = manager_restart },
	{ .name = "Reload",       .in_sig = "",  .out_sig = "",
	  .flags = INK_METHOD_PRIVILEGED, .handler = manager_reload },
	{ .name = "SetRunlevel",  .in_sig = "u", .out_sig = "",
	  .flags = INK_METHOD_PRIVILEGED, .handler = manager_set_runlevel },
	{ .name = "Reboot",       .in_sig = "",  .out_sig = "",
	  .flags = INK_METHOD_PRIVILEGED, .handler = manager_reboot },
	{ .name = "Poweroff",     .in_sig = "",  .out_sig = "",
	  .flags = INK_METHOD_PRIVILEGED, .handler = manager_poweroff },
	{ .name = "Halt",         .in_sig = "",  .out_sig = "",
	  .flags = INK_METHOD_PRIVILEGED, .handler = manager_halt },
	{ NULL, NULL, NULL, 0, NULL }
};

static const ink_vtable_t manager_vtable = {
	.interface = "org.finit.Manager1",
	.methods   = manager_methods,
};

/* ---------- init / exit ---------- */

int dbus_init(uev_ctx_t *ctx)
{
	dbg("Setting up D-Bus listening socket at %s ...", FINIT_BUS_SOCKET);

	if (ink_server_new(&server, FINIT_BUS_SOCKET) < 0) {
		err(1, "Failed binding D-Bus socket %s", FINIT_BUS_SOCKET);
		return 1;
	}

	if (ink_server_add_object(server, "/org/finit/manager",
				  &manager_vtable, NULL) < 0) {
		err(1, "Failed registering Manager1 object");
		ink_server_free(server);
		server = NULL;
		return 1;
	}

	if (uev_io_init(ctx, &accept_watcher, accept_cb, NULL,
			ink_server_get_fd(server), UEV_READ)) {
		err(1, "Failed registering D-Bus accept watcher");
		ink_server_free(server);
		server = NULL;
		return 1;
	}

	return 0;
}

int dbus_exit(void)
{
	struct peer *p;

	uev_io_stop(&accept_watcher);

	while ((p = TAILQ_FIRST(&peers)))
		peer_drop(p);

	if (server) {
		ink_server_free(server);
		server = NULL;
	}

	return 0;
}

#endif /* HAVE_DBUS */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
