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
#include "log.h"
#include "service.h"
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

static const ink_method_t manager_methods[] = {
	{ .name = "ListServices", .in_sig = "", .out_sig = "as",
	  .handler = manager_list_services },
	{ NULL, NULL, NULL, NULL }
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
