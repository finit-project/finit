/* Finit-side glue between the event loop and libink.
 *
 * Owns the libink server, accepts new peers, and drives each peer's
 * state machine when its fd becomes readable.  Nothing in this file
 * leaks finit-internal types into libink, by design: the boundary
 * here is the prospective extraction line.
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

struct peer {
	uev_t              watcher;
	ink_connection_t  *conn;
	TAILQ_ENTRY(peer)  link;
};

/* Cap the per-process peer count.  The socket is world-accessible by
 * design (introspection should work for unprivileged users) so an
 * unprivileged local actor could connect in a loop until EMFILE
 * without this. */
#define DBUS_MAX_PEERS 64

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

int dbus_init(uev_ctx_t *ctx)
{
	dbg("Setting up D-Bus listening socket at %s ...", FINIT_BUS_SOCKET);

	if (ink_server_new(&server, FINIT_BUS_SOCKET) < 0) {
		err(1, "Failed binding D-Bus socket %s", FINIT_BUS_SOCKET);
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
