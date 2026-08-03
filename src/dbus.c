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
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <uev/uev.h>

#include <ftw.h>

#include "link.h"
#include "path.h"

#include "finit.h"
#include "cond.h"
#include "conf.h"
#include "log.h"
#include "private.h"
#include "service.h"
#include "sig.h"
#include "sm.h"
#include "svc.h"
#include "util.h"

#define DBUS_MAX_PEERS 64

struct peer {
	uev_t              watcher;
	link_connection_t  *conn;
	TAILQ_ENTRY(peer)  link;
};

static TAILQ_HEAD(, peer) peers = TAILQ_HEAD_INITIALIZER(peers);
static link_server_t      *server;
static uev_t              accept_watcher;
static size_t             peer_count;
static struct peer        *sysbus_peer;

static void sysbus_probe(void);

static void peer_drop(struct peer *p)
{
	int was_sysbus = p == sysbus_peer;

	uev_io_stop(&p->watcher);
	link_connection_close(p->conn);
	TAILQ_REMOVE(&peers, p, link);
	peer_count--;
	free(p);

	/* broker gone; the notify paths probe for its return */
	if (was_sysbus)
		sysbus_peer = NULL;
}

static void peer_cb(uev_t *w, void *arg, int events)
{
	struct peer *p = arg;

	(void)w;

	if (UEV_ERROR == events) {
		peer_drop(p);
		return;
	}

	if (link_connection_process(p->conn) < 0)
		peer_drop(p);
}

/* Wrap an authenticated connection in a struct peer, insert into the
 * peer list, and register an event-loop watcher.  Enforces
 * DBUS_MAX_PEERS.  Closes the connection and returns NULL on failure.
 * Used by both the accept path and the system-bus attach path. */
static struct peer *peer_register(uev_ctx_t *ctx, link_connection_t *conn)
{
	struct peer *p;

	if (peer_count >= DBUS_MAX_PEERS) {
		logit(LOG_WARNING, "D-Bus peer cap reached (%zu), dropping",
		      peer_count);
		link_connection_close(conn);
		return NULL;
	}

	p = calloc(1, sizeof(*p));
	if (!p) {
		link_connection_close(conn);
		return NULL;
	}

	p->conn = conn;
	TAILQ_INSERT_TAIL(&peers, p, link);
	peer_count++;

	if (uev_io_init(ctx, &p->watcher, peer_cb, p,
			link_connection_get_fd(conn), UEV_READ)) {
		peer_drop(p);
		return NULL;
	}
	return p;
}

static void accept_cb(uev_t *w, void *arg, int events)
{
	(void)arg;

	if (UEV_ERROR == events) {
		err(1, "D-Bus accept watcher error");
		return;
	}

	for (;;) {
		link_connection_t *conn = NULL;

		if (link_server_accept(server, &conn) < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK)
				err(1, "Failed accepting D-Bus client");
			break;
		}

		if (!peer_register(w->ctx, conn))
			continue;	/* logged inside */
	}
}

/* ---------- org.finit.Manager1 ---------- */

/* Forward decl + buffer-size constant — both consumed by Manager1
 * handlers below, defined in the Service1 block further down. */
#define SERVICE_PATH_PREFIX "/org/finit/service/"
#define SERVICE_PATH_PREFIX_LEN (sizeof(SERVICE_PATH_PREFIX) - 1)
#define FINIT_SVC_PATH_MAX 512
static int service_path_for(svc_t *svc, char *buf, size_t bufsz);

static int manager_list_services(link_call_t *call, void *userdata)
{
	link_writer_t *w;
	svc_t        *iter = NULL;
	svc_t        *svc;

	(void)userdata;

	w = link_call_reply(call);
	if (!w)
		return -1;

	link_w_array_begin(w, 's');
	for (svc = svc_iterator(&iter, 1); svc; svc = svc_iterator(&iter, 0)) {
		char ident[MAX_IDENT_LEN];

		svc_ident(svc, ident, sizeof(ident));
		link_w_string(w, ident);
	}
	link_w_array_end(w);
	return 0;
}

static int manager_get_service(link_call_t *call, void *userdata)
{
	const char *ident;
	svc_t      *svc;
	char        path[FINIT_SVC_PATH_MAX];
	link_writer_t *w;

	(void)userdata;

	if (link_call_read_string(call, &ident) < 0)
		return link_call_reply_error(call,
			"org.freedesktop.DBus.Error.InvalidArgs",
			"expected (s)");

	svc = svc_find_by_str(ident);
	if (!svc)
		return link_call_reply_error(call,
			"org.finit.Error.NoSuchService", ident);

	if (service_path_for(svc, path, sizeof(path)) < 0)
		return link_call_reply_error(call,
			"org.finit.Error.Failed",
			"Path encoding overflow");

	w = link_call_reply(call);
	if (!w)
		return -1;
	link_w_path(w, path);
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
	void *udata;
	int   matched;
};

static int dispatch_found(svc_t *svc, void *udata)
{
	struct dispatch_ctx *ctx = udata;

	ctx->matched++;
	return ctx->action(svc, ctx->udata);
}

static int dispatch_missing(char *job, char *id, void *udata)
{
	(void)job; (void)id; (void)udata;
	return 0;	/* don't penalise the return; we'll check ->matched */
}

/* Apply `action(svc, udata)` to every service matched by `ident`.
 * Returns 0 if at least one service matched and the action succeeded
 * on all; -1 if no service matched the identity (caller sends
 * NoSuchService). */
static int dispatch_action(const char *ident,
			   int (*action)(svc_t *, void *), void *udata)
{
	char buf[MAX_IDENT_LEN];
	struct dispatch_ctx ctx = { .action = action, .udata = udata };
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

static int manager_take_string_method(link_call_t *call,
				      int (*action)(svc_t *, void *))
{
	const char *ident;
	int rc;

	if (link_call_read_string(call, &ident) < 0)
		return link_call_reply_error(call,
			"org.freedesktop.DBus.Error.InvalidArgs",
			"expected (s)");

	rc = dispatch_action(ident, action, NULL);
	if (rc < 0)
		return link_call_reply_error(call,
			"org.finit.Error.NoSuchService", ident);
	if (rc)
		return link_call_reply_error(call,
			"org.finit.Error.Failed",
			"failed on matched service(s)");

	(void)link_call_reply(call);	/* empty reply */
	return 0;
}

static int manager_start  (link_call_t *call, void *u) { (void)u; return manager_take_string_method(call, dbus_apply_start);   }
static int manager_stop   (link_call_t *call, void *u) { (void)u; return manager_take_string_method(call, dbus_apply_stop);    }
static int manager_restart(link_call_t *call, void *u) { (void)u; return manager_take_string_method(call, dbus_apply_restart); }

static int manager_reload(link_call_t *call, void *userdata)
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
	(void)link_call_reply(call);
	return 0;
}

static int manager_set_runlevel(link_call_t *call, void *userdata)
{
	uint32_t lvl;

	(void)userdata;
	if (link_call_read_u32(call, &lvl) < 0)
		return link_call_reply_error(call,
			"org.freedesktop.DBus.Error.InvalidArgs",
			"expected (u)");
	if (lvl > 9 || lvl == INIT_LEVEL)
		return link_call_reply_error(call,
			"org.freedesktop.DBus.Error.InvalidArgs",
			"runlevel must be 0-9 (excluding internal levels)");

	if (lvl == 0) halt = SHUT_OFF;
	if (lvl == 6) halt = SHUT_REBOOT;
	sm_runlevel((int)lvl);

	(void)link_call_reply(call);
	return 0;
}

static int dbus_shutdown(link_call_t *call, shutop_t target, int level)
{
	if (IS_RESERVED_RUNLEVEL(runlevel))
		return link_call_reply_error(call,
			"org.finit.Error.WrongRunlevel",
			"Already in shutdown");
	halt = target;
	sm_runlevel(level);
	(void)link_call_reply(call);
	return 0;
}

static int manager_reboot  (link_call_t *c, void *u) { (void)u; return dbus_shutdown(c, SHUT_REBOOT, 6); }
static int manager_poweroff(link_call_t *c, void *u) { (void)u; return dbus_shutdown(c, SHUT_OFF,    0); }
static int manager_halt    (link_call_t *c, void *u) { (void)u; return dbus_shutdown(c, SHUT_HALT,   0); }

static int manager_set_debug(link_call_t *call, void *u)
{
	(void)u;
	log_debug();
	(void)link_call_reply(call);
	return 0;
}

static int signal_one(svc_t *svc, void *udata)
{
	int signo = *(int *)udata;

	/* Silently skip stopped services -- a multi-match ident
	 * (e.g. "sshd:*") should not fail the whole call just because
	 * one of the matches happens to be in a halted state. */
	if (!svc_is_running(svc))
		return 0;
	return !!kill(svc->pid, signo);
}

static int manager_signal(link_call_t *call, void *u)
{
	const char *ident;
	uint32_t signo;
	int sig, rc;

	(void)u;
	if (link_call_read_string(call, &ident) < 0 ||
	    link_call_read_u32   (call, &signo) < 0)
		return link_call_reply_error(call,
			"org.freedesktop.DBus.Error.InvalidArgs",
			"expected (s, u)");
	/* Match the upper bound `initctl signal` allows (1..31).  RT
	 * signals are a future story; keep both sides in lockstep so
	 * users see the same range regardless of transport. */
	if (signo == 0 || signo > 31)
		return link_call_reply_error(call,
			"org.freedesktop.DBus.Error.InvalidArgs",
			"signal out of range (1..31)");

	sig = (int)signo;
	rc = dispatch_action(ident, signal_one, &sig);
	if (rc < 0)
		return link_call_reply_error(call,
			"org.finit.Error.NoSuchService", ident);
	if (rc)
		return link_call_reply_error(call,
			"org.finit.Error.Failed",
			"failed signalling matched service(s)");

	(void)link_call_reply(call);
	return 0;
}

static int manager_suspend(link_call_t *call, void *u)
{
	(void)u;
	sync();
	if (suspend() < 0) {
		const char *msg = (errno == EINVAL)
			? "Kernel does not support suspend to RAM"
			: strerror(errno);
		return link_call_reply_error(call,
			"org.finit.Error.Failed", msg);
	}
	(void)link_call_reply(call);
	return 0;
}

/* ---------- Manager1 properties ----------
 *
 * Read-only string properties exposed via the standard
 * org.freedesktop.DBus.Properties interface.  Getters write a
 * variant containing a single string. */

/* Two distinct getters because the property table is static const --
 * we can't bind &runlevel/&prevlevel through userdata. */
static int prop_runlevel(link_writer_t *w, void *u)
{
	char buf[8];

	(void)u;
	snprintf(buf, sizeof(buf), "%d", runlevel);
	link_w_string(w, buf);
	return 0;
}

static int prop_prevrunlevel(link_writer_t *w, void *u)
{
	char buf[8];

	(void)u;
	snprintf(buf, sizeof(buf), "%d", prevlevel);
	link_w_string(w, buf);
	return 0;
}

static int prop_version(link_writer_t *w, void *u)
{
	(void)u;
	link_w_string(w, PACKAGE_VERSION);
	return 0;
}

static const link_property_t manager_properties[] = {
	{ .name = "Runlevel",     .sig = "s", .getter = prop_runlevel     },
	{ .name = "PrevRunlevel", .sig = "s", .getter = prop_prevrunlevel },
	{ .name = "Version",      .sig = "s", .getter = prop_version      },
	{ NULL, NULL, NULL }
};

static const link_method_t manager_methods[] = {
	{ .name = "ListServices", .in_sig = "",  .out_sig = "as",
	  .handler = manager_list_services },
	{ .name = "GetService",   .in_sig = "s", .out_sig = "o",
	  .handler = manager_get_service },
	{ .name = "Start",        .in_sig = "s", .out_sig = "",
	  .flags = LINK_METHOD_PRIVILEGED, .handler = manager_start },
	{ .name = "Stop",         .in_sig = "s", .out_sig = "",
	  .flags = LINK_METHOD_PRIVILEGED, .handler = manager_stop },
	{ .name = "Restart",      .in_sig = "s", .out_sig = "",
	  .flags = LINK_METHOD_PRIVILEGED, .handler = manager_restart },
	{ .name = "Reload",       .in_sig = "",  .out_sig = "",
	  .flags = LINK_METHOD_PRIVILEGED, .handler = manager_reload },
	{ .name = "SetRunlevel",  .in_sig = "u", .out_sig = "",
	  .flags = LINK_METHOD_PRIVILEGED, .handler = manager_set_runlevel },
	{ .name = "Reboot",       .in_sig = "",  .out_sig = "",
	  .flags = LINK_METHOD_PRIVILEGED, .handler = manager_reboot },
	{ .name = "Poweroff",     .in_sig = "",  .out_sig = "",
	  .flags = LINK_METHOD_PRIVILEGED, .handler = manager_poweroff },
	{ .name = "Halt",         .in_sig = "",  .out_sig = "",
	  .flags = LINK_METHOD_PRIVILEGED, .handler = manager_halt },
	{ .name = "Suspend",      .in_sig = "",  .out_sig = "",
	  .flags = LINK_METHOD_PRIVILEGED, .handler = manager_suspend },
	{ .name = "SetDebug",     .in_sig = "",  .out_sig = "",
	  .flags = LINK_METHOD_PRIVILEGED, .handler = manager_set_debug },
	{ .name = "Signal",       .in_sig = "su", .out_sig = "",
	  .flags = LINK_METHOD_PRIVILEGED, .handler = manager_signal },
	{ NULL, NULL, NULL, 0, NULL }
};

static const link_vtable_t manager_vtable = {
	.interface  = "org.finit.Manager1",
	.methods    = manager_methods,
	.properties = manager_properties,
};

/* ---------- org.finit.Service1 (one object per service) ----------
 *
 * Per-service object at /org/finit/service/<encoded-identity>.
 * The vtable's `userdata` is the svc_t * for the specific service.
 * Registration is driven dynamically from svc_new()/svc_del() via
 * dbus_register_service() / dbus_unregister_service() below. */

/* SERVICE_PATH_PREFIX / SERVICE_PATH_PREFIX_LEN / FINIT_SVC_PATH_MAX
 * defined near the top of the file so Manager1.GetService can refer
 * to them. */

static int service_action_method(link_call_t *call, void *userdata,
				 int (*action)(svc_t *, void *))
{
	svc_t *svc = userdata;

	if (!svc)
		return link_call_reply_error(call,
			"org.finit.Error.NoSuchService",
			"Service object no longer valid");

	action(svc, NULL);
	(void)link_call_reply(call);
	return 0;
}

static int service1_start  (link_call_t *c, void *u) { return service_action_method(c, u, dbus_apply_start);   }
static int service1_stop   (link_call_t *c, void *u) { return service_action_method(c, u, dbus_apply_stop);    }
static int service1_restart(link_call_t *c, void *u) { return service_action_method(c, u, dbus_apply_restart); }

static int service1_reload(link_call_t *call, void *userdata)
{
	svc_t *svc = userdata;

	if (!svc)
		return link_call_reply_error(call,
			"org.finit.Error.NoSuchService",
			"Service object no longer valid");

	service_reload(svc);
	(void)link_call_reply(call);
	return 0;
}

static const link_method_t service_methods[] = {
	{ .name = "Start",   .in_sig = "", .out_sig = "",
	  .flags = LINK_METHOD_PRIVILEGED, .handler = service1_start   },
	{ .name = "Stop",    .in_sig = "", .out_sig = "",
	  .flags = LINK_METHOD_PRIVILEGED, .handler = service1_stop    },
	{ .name = "Restart", .in_sig = "", .out_sig = "",
	  .flags = LINK_METHOD_PRIVILEGED, .handler = service1_restart },
	{ .name = "Reload",  .in_sig = "", .out_sig = "",
	  .flags = LINK_METHOD_PRIVILEGED, .handler = service1_reload  },
	{ NULL, NULL, NULL, 0, NULL }
};

/*
 * Getters write the bare value; the framework emits the variant
 * signature from the table below.  `State` deliberately uses the
 * initctl status vocabulary from svc_status(), not the coarser
 * ServiceStateChanged strings -- a client that only tracks edges
 * has the signal, a client that asks gets the full story.
 */
#define SVC_PROP_STR(fn, field)					\
static int fn(link_writer_t *w, void *arg)			\
{								\
	link_w_string(w, ((svc_t *)arg)->field);		\
	return 0;						\
}

#define SVC_PROP_U32(fn, field)					\
static int fn(link_writer_t *w, void *arg)			\
{								\
	link_w_u32(w, (uint32_t)((svc_t *)arg)->field);		\
	return 0;						\
}

#define SVC_PROP_BOOL(fn, field)				\
static int fn(link_writer_t *w, void *arg)			\
{								\
	link_w_bool(w, ((svc_t *)arg)->field);			\
	return 0;						\
}

static int svc_prop_identity(link_writer_t *w, void *arg)
{
	link_w_string(w, svc_ident(arg, NULL, 0));
	return 0;
}

static int svc_prop_state(link_writer_t *w, void *arg)
{
	link_w_string(w, svc_status(arg));
	return 0;
}

static int svc_prop_type(link_writer_t *w, void *arg)
{
	link_w_string(w, svc_typestr((svc_t *)arg));
	return 0;
}

static int svc_prop_command(link_writer_t *w, void *arg)
{
	svc_t *svc = arg;
	char   buf[512];

	compose_cmdline(svc, buf, sizeof(buf));
	if (svc_is_sysv(svc)) {
		strlcat(buf, " ", sizeof(buf));
		strlcat(buf, svc->state == SVC_HALTED_STATE
			? "stop" : "start", sizeof(buf));
	}

	link_w_string(w, buf);
	return 0;
}

static int svc_prop_pid(link_writer_t *w, void *arg)
{
	svc_t *svc = arg;

	link_w_u32(w, svc->pid > 0 ? (uint32_t)svc->pid : 0);
	return 0;
}

static int svc_prop_restarts(link_writer_t *w, void *arg)
{
	svc_t *svc = arg;

	link_w_u32(w, svc->restart_cnt > 0 ? (uint32_t)svc->restart_cnt : 0);
	return 0;
}

static int svc_prop_uptime(link_writer_t *w, void *arg)
{
	svc_t *svc = arg;
	long   up = 0;

	if (svc->pid > 0) {
		up = jiffies() - svc->start_time;
		if (up < 0)
			up = 0;
	}
	link_w_u32(w, (uint32_t)up);
	return 0;
}

SVC_PROP_STR (svc_prop_name,         name)
SVC_PROP_STR (svc_prop_desc,         desc)
SVC_PROP_STR (svc_prop_conditions,   cond)
SVC_PROP_STR (svc_prop_origin,       file)
SVC_PROP_STR (svc_prop_environ,      env)
SVC_PROP_STR (svc_prop_pidfile,      pidfile)
SVC_PROP_STR (svc_prop_user,         username)
SVC_PROP_STR (svc_prop_group,        group)
SVC_PROP_U32 (svc_prop_runlevels,    runlevels)
SVC_PROP_U32 (svc_prop_exitstatus,   status)
SVC_PROP_U32 (svc_prop_restarts_tot, restart_tot)
SVC_PROP_U32 (svc_prop_restart_max,  restart_max)
SVC_PROP_U32 (svc_prop_starts,       once)
SVC_PROP_BOOL(svc_prop_manual,       manual)
SVC_PROP_BOOL(svc_prop_forking,      forking)
SVC_PROP_BOOL(svc_prop_started,      started)

static const link_property_t service_properties[] = {
	{ .name = "Identity",     .sig = "s", .getter = svc_prop_identity   },
	{ .name = "Name",         .sig = "s", .getter = svc_prop_name       },
	{ .name = "State",        .sig = "s", .getter = svc_prop_state      },
	{ .name = "Pid",          .sig = "u", .getter = svc_prop_pid        },
	{ .name = "RestartCount", .sig = "u", .getter = svc_prop_restarts   },
	{ .name = "Runlevels",    .sig = "u", .getter = svc_prop_runlevels  },
	{ .name = "Description",  .sig = "s", .getter = svc_prop_desc       },
	{ .name = "Command",      .sig = "s", .getter = svc_prop_command    },
	{ .name = "Conditions",   .sig = "s", .getter = svc_prop_conditions },
	{ .name = "Type",         .sig = "s", .getter = svc_prop_type       },
	{ .name = "Origin",       .sig = "s", .getter = svc_prop_origin     },
	{ .name = "Environment",  .sig = "s", .getter = svc_prop_environ    },
	{ .name = "PidFile",      .sig = "s", .getter = svc_prop_pidfile    },
	{ .name = "User",         .sig = "s", .getter = svc_prop_user       },
	{ .name = "Group",        .sig = "s", .getter = svc_prop_group      },
	{ .name = "Uptime",       .sig = "u", .getter = svc_prop_uptime     },
	{ .name = "ExitStatus",   .sig = "u", .getter = svc_prop_exitstatus },
	{ .name = "RestartsTotal",.sig = "u", .getter = svc_prop_restarts_tot },
	{ .name = "RestartMax",   .sig = "u", .getter = svc_prop_restart_max },
	{ .name = "Starts",       .sig = "u", .getter = svc_prop_starts     },
	{ .name = "ManualStart",  .sig = "b", .getter = svc_prop_manual     },
	{ .name = "Forking",      .sig = "b", .getter = svc_prop_forking    },
	{ .name = "Started",      .sig = "b", .getter = svc_prop_started    },
	{ NULL, NULL, NULL }
};

static const link_vtable_t service_vtable = {
	.interface  = "org.finit.Service1",
	.methods    = service_methods,
	.properties = service_properties,
};

/* Build the canonical object path for a service.  Identity is
 * "name" for single-instance services, "name:id" otherwise. */
static int service_path_for(svc_t *svc, char *buf, size_t bufsz)
{
	char ident[MAX_IDENT_LEN];
	size_t plen = SERVICE_PATH_PREFIX_LEN;
	int    enc;

	if (bufsz <= plen)
		return -1;
	memcpy(buf, SERVICE_PATH_PREFIX, plen);

	svc_ident(svc, ident, sizeof(ident));
	enc = link_path_encode(ident, buf + plen, bufsz - plen);
	if (enc < 0)
		return -1;
	return (int)plen + enc;
}

void dbus_register_service(svc_t *svc)
{
	char path[FINIT_SVC_PATH_MAX];

	if (!server || !svc)
		return;
	if (service_path_for(svc, path, sizeof(path)) < 0)
		return;

	if (link_server_add_object(server, path, &service_vtable, svc) < 0)
		logit(LOG_WARNING, "dbus: failed registering %s", path);
}

void dbus_unregister_service(svc_t *svc)
{
	char path[FINIT_SVC_PATH_MAX];

	if (!server || !svc)
		return;
	if (service_path_for(svc, path, sizeof(path)) < 0)
		return;

	(void)link_server_remove_object(server, path);
}

/* ---------- signal fan-out helper ----------
 *
 * Fan out a pre-marshalled signal body to every connected peer,
 * letting each connection apply its AddMatch filter.  Short-circuits
 * when no peers are connected so dbus_notify_* callers don't have
 * to inspect that state themselves. */
static void dbus_emit_signal(const char *path,
			     const char *interface,
			     const char *member,
			     const char *signature,
			     const uint8_t *body, size_t body_len)
{
	struct peer *p, *tmp;

	if (!server || TAILQ_EMPTY(&peers))
		return;
	TAILQ_FOREACH_SAFE(p, &peers, link, tmp) {
		if (link_connection_emit_signal(p->conn,
				path, interface, member,
				signature, body, body_len) < 0) {
			/* nothing hit the wire, and same for every peer */
			if (errno == EMSGSIZE || errno == EINVAL)
				break;
			logit(LOG_WARNING, "D-Bus peer fd %d write failed: "
			      "%s, dropping",
			      link_connection_get_fd(p->conn),
			      strerror(errno));
			peer_drop(p);
		}
	}
}

/* ---------- signal emission: ServiceStateChanged ---------- */

/*
 * Coarse svc_state_t -> string.  svc_status() in svc.h returns a
 * richer string that also considers svc->block, but emitting just
 * the state-machine state is enough for clients to track lifecycle
 * transitions.  Keep the strings stable -- they're a wire-API
 * commitment once shipped.
 *
 * No `default:` on purpose: a new SVC_*_STATE added to svc.h must
 * also pick a wire name here, and -Wall (-Wswitch) flags the
 * missing case.
 */
static const char *state_name(svc_state_t s)
{
	switch (s) {
	case SVC_HALTED_STATE:   return "halted";
	case SVC_DONE_STATE:     return "done";
	case SVC_DEAD_STATE:     return "dead";
	case SVC_CLEANUP_STATE:  return "cleanup";
	case SVC_TEARDOWN_STATE: return "teardown";
	case SVC_STOPPING_STATE: return "stopping";
	case SVC_SETUP_STATE:    return "setup";
	case SVC_PAUSED_STATE:   return "paused";
	case SVC_WAITING_STATE:  return "waiting";
	case SVC_STARTING_STATE: return "starting";
	case SVC_RUNNING_STATE:  return "running";
	}
	return "unknown";
}

void dbus_notify_service_state(svc_t *svc, int old_state, int new_state)
{
	uint8_t      body[256];
	link_writer_t w;
	char         ident[MAX_IDENT_LEN];
	char         path[FINIT_SVC_PATH_MAX];
	ssize_t      blen;

	if (!svc)
		return;

	sysbus_probe();

	svc_ident(svc, ident, sizeof(ident));

	link_writer_init(&w, body, sizeof(body));
	link_w_string(&w, ident);
	link_w_string(&w, state_name((svc_state_t)old_state));
	link_w_string(&w, state_name((svc_state_t)new_state));
	blen = link_writer_finish(&w);
	if (blen < 0)
		return;

	dbus_emit_signal("/org/finit/manager", "org.finit.Manager1",
			 "ServiceStateChanged", "sss", body, (size_t)blen);

	/*
	 * Dual emission: Properties-aware clients track one object via
	 * the standard PropertiesChanged instead of filtering the
	 * manager-wide signal.  Volatile numerics are invalidated, not
	 * marshalled -- interested clients re-Get.
	 */
	if (service_path_for(svc, path, sizeof(path)) < 0)
		return;

	link_writer_init(&w, body, sizeof(body));
	link_w_string(&w, "org.finit.Service1");
	link_w_array_begin(&w, '{');
	link_w_struct_begin(&w);
	link_w_string(&w, "State");
	link_w_variant_string(&w, svc_status(svc));
	link_w_struct_end(&w);
	link_w_array_end(&w);
	link_w_array_begin(&w, 's');
	link_w_string(&w, "Pid");
	link_w_string(&w, "RestartCount");
	link_w_array_end(&w);
	blen = link_writer_finish(&w);
	if (blen < 0)
		return;

	dbus_emit_signal(path, "org.freedesktop.DBus.Properties",
			 "PropertiesChanged", "sa{sv}as",
			 body, (size_t)blen);
}

/* ---------- signal emission: RunlevelChanged ----------
 *
 * Fired by sm.c right after the runlevel global flips.  Body is
 * (old, new) as one-digit strings, matching the format that
 * Manager1.Runlevel (the property) returns. */
void dbus_notify_runlevel_change(int old_level, int new_level)
{
	uint8_t      body[64];
	link_writer_t w;
	char         old_s[8], new_s[8];
	ssize_t      blen;

	snprintf(old_s, sizeof(old_s), "%d", old_level);
	snprintf(new_s, sizeof(new_s), "%d", new_level);

	link_writer_init(&w, body, sizeof(body));
	link_w_string(&w, old_s);
	link_w_string(&w, new_s);
	blen = link_writer_finish(&w);
	if (blen < 0)
		return;

	dbus_emit_signal("/org/finit/manager", "org.finit.Manager1",
			 "RunlevelChanged", "ss", body, (size_t)blen);
}

/* ---------- org.finit.Cond1 ---------- */

#define COND_PATH_OBJECT "/org/finit/cond"
#define COND_INTERFACE   "org.finit.Cond1"

/* Cond1.Set/Clear refuse anything that isn't a usr/ condition --
 * pid/, sys/, hook/ are owned by Finit's state machine and giving
 * clients write access there would let them corrupt service state.
 * Bare names ("foo") are normalised to "usr/foo" the same way
 * initctl does.  The returned pointer is valid for the duration
 * of the caller's stack frame (`buf` must be at least 128 bytes). */
static const char *normalise_usr_cond(const char *name, char *buf, size_t bufsz)
{
	const char *tail;

	if (!name || !*name)
		return NULL;
	if (strchr(name, '.'))
		return NULL;

	if (strchr(name, '/')) {
		if (strncmp(name, "usr/", 4) != 0)
			return NULL;
		tail = name + 4;
		/* Match initctl's policy: no further slashes in the tail,
		 * and no empty tail ("usr/" alone). */
		if (!*tail || strchr(tail, '/'))
			return NULL;
		if (strlen(name) >= bufsz)
			return NULL;
		memcpy(buf, name, strlen(name) + 1);
		return buf;
	}

	if ((size_t)snprintf(buf, bufsz, "usr/%s", name) >= bufsz)
		return NULL;
	return buf;
}

/* Reject names that would escape /run/finit/cond/.  cond_get(name)
 * boils down to fopen(_PATH_COND + name), so without this check any
 * caller can make PID 1 open arbitrary files -- a path traversal
 * primitive that also stalls PID 1 if pointed at a FIFO or a slow
 * device.  Legal cond names look like "usr/foo", "pid/sshd",
 * "service/keventd/ready"; no leading slash, no ".." segment. */
static int cond_name_valid(const char *name)
{
	const char *p;

	if (!name || !*name || *name == '/')
		return 0;
	for (p = name; *p; p++) {
		if (*p == '.' && p[1] == '.' &&
		    (p[2] == '\0' || p[2] == '/'))
			return 0;
	}
	return 1;
}

static int cond1_get(link_call_t *call, void *userdata)
{
	const char    *name;
	link_writer_t  *w;

	(void)userdata;

	if (link_call_read_string(call, &name) < 0)
		return link_call_reply_error(call,
			"org.freedesktop.DBus.Error.InvalidArgs",
			"expected (s)");
	if (!cond_name_valid(name))
		return link_call_reply_error(call,
			"org.freedesktop.DBus.Error.InvalidArgs",
			"invalid condition name");

	w = link_call_reply(call);
	if (!w)
		return -1;
	link_w_string(w, condstr(cond_get(name)));
	return 0;
}

static int cond1_set_or_clear(link_call_t *call, int do_set)
{
	const char *name;
	char        buf[128];
	const char *full;

	if (link_call_read_string(call, &name) < 0)
		return link_call_reply_error(call,
			"org.freedesktop.DBus.Error.InvalidArgs",
			"expected (s)");

	full = normalise_usr_cond(name, buf, sizeof(buf));
	if (!full)
		return link_call_reply_error(call,
			"org.freedesktop.DBus.Error.InvalidArgs",
			"Set/Clear is restricted to usr/* conditions");

	if (do_set)
		/* cond_set_oneshot, not cond_set: a user-asserted condition
		 * is a symlink to _PATH_RECONF, so it tracks the reconf
		 * generation automatically and stays "on" across reloads
		 * and runlevel switches.  cond_set() writes a fixed
		 * generation that goes "flux" on the next reload -- wrong
		 * semantics for user conditions, and what initctl cond set
		 * has done forever via the filesystem path. */
		cond_set_oneshot(full);
	else
		cond_clear(full);

	(void)link_call_reply(call);
	return 0;
}

static int cond1_set  (link_call_t *c, void *u) { (void)u; return cond1_set_or_clear(c, 1); }
static int cond1_clear(link_call_t *c, void *u) { (void)u; return cond1_set_or_clear(c, 0); }

/* nftw() can't pass user data so a single static handle ferries the
 * writer into the callback.  Safe because dispatch is single-threaded. */
static link_writer_t *cond_walk_writer;
static int           cond_walk_dump;

static int cond_walk_cb(const char *fpath, const struct stat *sb,
			int tflag, struct FTW *ftwbuf)
{
	const char  *name;
	const char  *state;
	size_t       prefix_len;

	(void)sb;
	(void)ftwbuf;

	if (tflag != FTW_F)
		return 0;
	if (!strcmp(fpath, _PATH_RECONF))
		return 0;

	prefix_len = strlen(_PATH_COND);
	if (strlen(fpath) <= prefix_len)
		return 0;
	name = fpath + prefix_len;

	if (cond_walk_dump) {
		state = condstr(cond_get_path(fpath));
		link_w_struct_begin(cond_walk_writer);
		link_w_string(cond_walk_writer, name);
		link_w_string(cond_walk_writer, state);
		link_w_struct_end(cond_walk_writer);
	} else {
		link_w_string(cond_walk_writer, name);
	}
	return 0;
}

static int cond1_list(link_call_t *call, void *userdata)
{
	link_writer_t *w;

	(void)userdata;

	w = link_call_reply(call);
	if (!w)
		return -1;

	link_w_array_begin(w, 's');
	cond_walk_writer = w;
	cond_walk_dump   = 0;
	(void)nftw(_PATH_COND, cond_walk_cb, 20, 0);
	cond_walk_writer = NULL;
	link_w_array_end(w);
	return 0;
}

static int cond1_dump(link_call_t *call, void *userdata)
{
	link_writer_t *w;

	(void)userdata;

	w = link_call_reply(call);
	if (!w)
		return -1;

	link_w_array_begin(w, '(');
	cond_walk_writer = w;
	cond_walk_dump   = 1;
	(void)nftw(_PATH_COND, cond_walk_cb, 20, 0);
	cond_walk_writer = NULL;
	link_w_array_end(w);
	return 0;
}

static const link_method_t cond_methods[] = {
	{ .name = "Get",   .in_sig = "s", .out_sig = "s",
	  .handler = cond1_get },
	{ .name = "Set",   .in_sig = "s", .out_sig = "",
	  .flags = LINK_METHOD_PRIVILEGED, .handler = cond1_set },
	{ .name = "Clear", .in_sig = "s", .out_sig = "",
	  .flags = LINK_METHOD_PRIVILEGED, .handler = cond1_clear },
	{ .name = "List",  .in_sig = "",  .out_sig = "as",
	  .handler = cond1_list },
	{ .name = "Dump",  .in_sig = "",  .out_sig = "a(ss)",
	  .handler = cond1_dump },
	{ NULL, NULL, NULL, 0, NULL }
};

static const link_vtable_t cond_vtable = {
	.interface = COND_INTERFACE,
	.methods   = cond_methods,
};

/* ---------- signal emission: ConditionChanged ---------- */

void dbus_notify_condition_change(const char *name, const char *state)
{
	uint8_t      body[256];
	link_writer_t w;
	ssize_t      blen;

	if (!name || !state)
		return;

	sysbus_probe();

	link_writer_init(&w, body, sizeof(body));
	link_w_string(&w, name);
	link_w_string(&w, state);
	blen = link_writer_finish(&w);
	if (blen < 0)
		return;

	dbus_emit_signal(COND_PATH_OBJECT, COND_INTERFACE,
			 "ConditionChanged", "ss", body, (size_t)blen);
}

/* ---------- system-bus attach (opportunistic) ----------
 *
 * If /var/run/dbus/system_bus_socket is reachable, libink connects to
 * the system bus as a regular client, claims org.finit as a well-known
 * name, then promotes the authenticated fd into a server-attached
 * peer so the same vtables serve incoming method calls and outgoing
 * signal fan-out reaches the system bus.
 *
 * peer_uid is set to (uid_t)-1 so LINK_METHOD_PRIVILEGED methods
 * reject by default -- per-request sender uid lookup via
 * GetConnectionUnixUser is a follow-up.  Read-only methods
 * (ListServices, Properties.Get, Introspect, ...) work as expected.
 *
 * A bounded SO_SNDTIMEO/SO_RCVTIMEO budget is applied via
 * link_client_open_timeout so a hung dbus-daemon can't stall boot;
 * once the connection is attached and flipped to non-blocking, those
 * timeouts are silently inert. */

#define SYSTEM_BUS_PATH    "/var/run/dbus/system_bus_socket"
#define FINIT_BUS_NAME     "org.finit"
/* Budget for the synchronous AUTH + Hello + RequestName round-trips.
 * If the system bus is alive but the daemon is wedged we'd rather
 * give up after a couple of seconds than stall the rest of dbus_init
 * (and through it, boot). */
#define SYSTEM_BUS_TIMEOUT_MS 2000
/* DBUS_NAME_FLAG_DO_NOT_QUEUE: fail fast if the name is taken
 * (something else owns org.finit -- shouldn't happen and we'd
 * rather log than silently sit in the queue). */
#define DBUS_NAME_FLAG_DO_NOT_QUEUE  0x04

static int sysbus_request_name(link_client_t *c)
{
	uint32_t result = 0;
	int rc;

	rc = link_client_call_v(c, "/org/freedesktop/DBus",
				"org.freedesktop.DBus", "RequestName",
				"su", FINIT_BUS_NAME,
				(uint32_t)DBUS_NAME_FLAG_DO_NOT_QUEUE);
	if (rc != LINK_CALL_OK)
		return -1;
	if (link_reply_get_u32(link_client_reply(c), &result) < 0)
		return -1;
	/* 1 = primary owner; 2/3/4 mean we didn't get the name */
	return (result == 1) ? 0 : -1;
}

static int try_attach_system_bus(uev_ctx_t *ctx)
{
	link_client_t     *c;
	link_connection_t *conn;
	struct peer       *p;
	int rc;

	c = link_client_open_timeout(SYSTEM_BUS_PATH, SYSTEM_BUS_TIMEOUT_MS);
	if (!c) {
		dbg("System bus unavailable at %s; skipping registration",
		    SYSTEM_BUS_PATH);
		return -1;
	}

	rc = link_client_call_v(c, "/org/freedesktop/DBus",
				"org.freedesktop.DBus", "Hello", NULL);
	if (rc != LINK_CALL_OK) {
		dbg("System-bus Hello failed (rc=%d); skipping", rc);
		link_client_close(c);
		return -1;
	}

	if (sysbus_request_name(c) < 0) {
		logit(LOG_WARNING, "Failed to claim %s on system bus", FINIT_BUS_NAME);
		link_client_close(c);
		return -1;
	}

	/* link_server_attach owns the fd from this point on whether it
	 * succeeds or fails, so the steal-then-attach pair has no leak
	 * window. */
	conn = link_server_attach(server, link_client_steal_fd(c), (uid_t)-1);
	if (!conn)
		return -1;

	p = peer_register(ctx, conn);
	if (!p) {
		logit(LOG_WARNING, "Failed registering system-bus peer");
		return -1;
	}

	sysbus_peer = p;
	logit(LOG_NOTICE, "Registered %s on system bus", FINIT_BUS_NAME);
	return 0;
}

/*
 * The broker is usually not up yet when dbus_init() runs -- it is
 * typically a finit service itself -- and it may restart at any
 * time.  The service and condition notify paths call sysbus_probe()
 * on every event: when org.finit is unclaimed and the broker's
 * socket exists, one coalesced attach attempt is scheduled.  This
 * stays daemon-agnostic -- only the socket is probed, never a
 * service name -- and the broker's own service transitions are what
 * trigger it.
 */
static uev_t sysbus_tmr;
static int   sysbus_tmr_up;

static void sysbus_probe_cb(uev_t *w, void *arg, int events)
{
	(void)arg;
	(void)events;

	if (!sysbus_peer)
		(void)try_attach_system_bus(w->ctx);
}

static void sysbus_probe(void)
{
	if (sysbus_peer || !server)
		return;
	if (access(SYSTEM_BUS_PATH, F_OK))
		return;

	/* coalesce bursts to a single probe */
	if (!sysbus_tmr_up)
		sysbus_tmr_up = !uev_timer_init(ctx, &sysbus_tmr,
						sysbus_probe_cb, NULL,
						200, 0);
	else
		uev_timer_set(&sysbus_tmr, 200, 0);
}

/* ---------- init / exit ---------- */

int dbus_init(uev_ctx_t *ctx)
{
	dbg("Setting up D-Bus listening socket at %s ...", FINIT_BUS_SOCKET);

	if (link_server_new(&server, FINIT_BUS_SOCKET) < 0) {
		err(1, "Failed binding D-Bus socket %s", FINIT_BUS_SOCKET);
		return 1;
	}

	if (link_server_add_object(server, "/org/finit/manager",
				  &manager_vtable, NULL) < 0) {
		err(1, "Failed registering Manager1 object");
		link_server_free(server);
		server = NULL;
		return 1;
	}

	if (link_server_add_object(server, COND_PATH_OBJECT,
				  &cond_vtable, NULL) < 0) {
		err(1, "Failed registering Cond1 object");
		link_server_free(server);
		server = NULL;
		return 1;
	}

	if (uev_io_init(ctx, &accept_watcher, accept_cb, NULL,
			link_server_get_fd(server), UEV_READ)) {
		err(1, "Failed registering D-Bus accept watcher");
		link_server_free(server);
		server = NULL;
		return 1;
	}

	/* Register Service1 objects for every service already loaded.
	 * Subsequent svc_new()/svc_del() calls into
	 * dbus_register_service()/dbus_unregister_service(). */
	{
		svc_t *iter = NULL;
		svc_t *svc;

		for (svc = svc_iterator(&iter, 1); svc;
		     svc = svc_iterator(&iter, 0))
			dbus_register_service(svc);
	}

	(void)try_attach_system_bus(ctx);

	return 0;
}

int dbus_exit(void)
{
	struct peer *p;

	if (sysbus_tmr_up) {
		uev_timer_stop(&sysbus_tmr);
		sysbus_tmr_up = 0;
	}
	uev_io_stop(&accept_watcher);

	while ((p = TAILQ_FIRST(&peers)))
		peer_drop(p);

	if (server) {
		link_server_free(server);
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
