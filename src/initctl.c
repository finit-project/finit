/* New client tool, replaces old /dev/initctl API and telinit tool
 *
 * Copyright (c) 2015-2025  Joachim Wiberg <troglobit@gmail.com>
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

#include <ftw.h>
#include <ctype.h>
#include <getopt.h>
#include <paths.h>
#include <signal.h>
#include <stdio.h>
#include <syslog.h>
#include <time.h>
#include <utmp.h>
#include <arpa/inet.h>

#include "initctl.h"
#include "client.h"
#include "cond.h"
#include "serv.h"
#include "service.h"
#include "cgutil.h"
#include "utmp-api.h"
#ifdef HAVE_DBUS
#include "link.h"
#include "path.h"
#endif

/* Used by both do_cond_act and (with HAVE_DBUS) cond_dbus_call. */
typedef enum { COND_CLR, COND_SET, COND_GET } condop_t;

struct cmd {
	char        *cmd;
	struct cmd  *ctx;
	int        (*cb)(char *arg);
	int         *cond;
	int        (*cb_multiarg)(int argc, char **argv);
};

char *finit_conf = NULL;
char *finit_rcsd = NULL;

int icreate  = 0;
int iforce   = 0;
int ionce    = 0;
int debug    = 0;
int heading  = 1;
int json     = 0;
int noerr    = 0;
int verbose  = 0;
int plain    = 0;
int quiet    = 0;
int runlevel = 0;
int timeout  = 0;
int cgrp     = 0;
int utmp     = 0;

int iw, pw;

extern int reboot_main(int argc, char *argv[]);

/* figure ut width of IDENT and PID columns */
static void col_widths(void)
{
	char ident[MAX_IDENT_LEN];
	char pid[10];
	svc_t *svc;

	iw = 0;
	pw = 0;

	for (svc = client_svc_iterator(1); svc; svc = client_svc_iterator(0)) {
		int w, p;

		svc_ident(svc, ident, sizeof(ident));
		w = (int)strlen(ident);
		if (w > iw)
			iw = w;

		p = snprintf(pid, sizeof(pid), "%d", svc->pid);
		if (p > pw)
			pw = p;
	}

	/* adjust for min col width */
	if (iw < 6)
		iw = 6;
	if (pw < 3)
		pw = 3;
}

void print_header(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	if (plain) {
		int len;

		vfprintf(stdout, fmt, ap);
		fputs("\n", stdout);
		for (len = 0; len < ttcols; len++)
			fputc('=', stdout);
		fputs("\n", stdout);
	} else {
		char buf[ttcols - 9];

		vsnprintf(buf, sizeof(buf), fmt, ap);
		printheader(stdout, buf, 0);
	}

        va_end(ap);
}

static int runlevel_get(int *prevlevel)
{
	struct init_request rq;
	int rc;

	rq.cmd = INIT_CMD_GET_RUNLEVEL;
	rq.magic = INIT_MAGIC;

	rc = client_send(&rq, sizeof(rq));
	if (!rc) {
		rc = rq.runlevel;
		if (prevlevel)
			*prevlevel = rq.sleeptime;
	}

	return rc;
}

#ifdef HAVE_DBUS
static int try_dbus_manager(const char *method, const char *arg_sig,
			    const char *arg);
#endif

static int toggle_debug(char *arg)
{
	struct init_request rq = {
		.magic = INIT_MAGIC,
		.cmd = INIT_CMD_DEBUG,
	};

	(void)arg;
#ifdef HAVE_DBUS
	{
		int rc = try_dbus_manager("SetDebug", "", NULL);
		if (rc >= 0) return rc;
	}
#endif
	return client_send(&rq, sizeof(rq));
}

static int do_log_named(const char *nm, pid_t pid, char *tail)
{
	const char *logfile = "/var/log/syslog";

	if (!pid)
		return 0; /* not running */

	if (!fexist(logfile)) {
		logfile = "/var/log/messages";
		if (!fexist(logfile))
			return 0; /* bail out, maybe in container */
	}

	return systemf("cat %s | grep '\\[%d\\]\\|%s' %s", logfile, pid, nm, tail);
}

static int do_log(svc_t *svc, char *tail)
{
	if (svc)
		return do_log_named(svc_ident(svc, NULL, 0), svc->pid, tail);
	return do_log_named("finit", 1, tail);
}

static int show_log(char *arg)
{
	svc_t *svc = NULL;

	if (arg) {
		svc = client_svc_find(arg);
		if (!svc)
			ERRX(noerr ? 0 : 69, "no such task or service(s): %s", arg);
	}

	return do_log(svc, "");
}

#ifdef HAVE_DBUS
/*
 * Advance one a{sv} dict entry: key + variant type; the caller reads
 * the value with the link_r_* matching `type`.
 */
static int dbus_dict_next(link_reader_t *r, const char **key, char *type)
{
	if (link_r_align(r, 8) < 0)
		return -1;
	if (link_r_string(r, key) < 0)
		return -1;
	return link_r_variant_begin(r, type);
}

/* Fetch all org.finit.Manager1 string properties in one Properties.GetAll
 * round-trip, then pick out a subset.  `wanted` is a NULL-terminated array
 * of property names; `out` parallel-receives the values (each entry left
 * untouched if its property wasn't returned).  Returns 0 on transport
 * success (even if some properties weren't present), -1 on transport or
 * parse failure. */
static int dbus_get_manager_props(const char *const *wanted, char **out, size_t out_sz)
{
	link_client_t *c;
	const link_reply_t *r;
	link_reader_t reader;
	size_t         end;
	int            rc;

	c = link_client_open(FINIT_BUS_SOCKET);
	if (!c)
		return -1;

	rc = link_client_call_v(c, "/org/finit/manager",
				"org.freedesktop.DBus.Properties", "GetAll",
				"s", "org.finit.Manager1");
	if (rc != LINK_CALL_OK) {
		link_client_close(c);
		return -1;
	}

	r = link_client_reply(c);
	if (!r || !r->body) {
		link_client_close(c);
		return -1;
	}

	link_reader_init(&reader, r->body, r->body_len);
	if (link_r_array_begin(&reader, &end) < 0) {
		link_client_close(c);
		return -1;
	}

	while (link_r_pos(&reader) < end) {
		const char *key  = NULL;
		const char *val  = NULL;
		char        type;
		size_t i;

		if (dbus_dict_next(&reader, &key, &type) < 0)
			goto fail;
		if (type != 's' || link_r_string(&reader, &val) < 0)
			goto fail;

		for (i = 0; wanted[i]; i++) {
			if (!strcmp(key, wanted[i])) {
				strlcpy(out[i], val, out_sz);
				break;
			}
		}
	}

	link_client_close(c);
	return 0;
fail:
	link_client_close(c);
	return -1;
}

#endif

static int do_runlevel(char *arg)
{
	struct init_request rq = {
		.magic = INIT_MAGIC,
		.cmd = INIT_CMD_RUNLVL,
	};

	if (!arg) {
		int prevlevel = 0;
		int currlevel;
		char prev, curr;

#ifdef HAVE_DBUS
		char curr_buf[16] = { 0 }, prev_buf[16] = { 0 };
		const char *const wanted[] = { "Runlevel", "PrevRunlevel", NULL };
		char *out[] = { curr_buf, prev_buf };

		if (dbus_get_manager_props(wanted, out, sizeof(curr_buf)) == 0 &&
		    curr_buf[0] && prev_buf[0]) {
			/* already in runlevel(8) encoding: digits, S, N */
			printf("%s %s\n", prev_buf, curr_buf);
			return 0;
		}
#endif

		currlevel = runlevel_get(&prevlevel);
		switch (currlevel) {
		case 255:
			printf("unknown\n");
			return 0;
		case INIT_LEVEL:
			curr = 'S';
			break;
		default:
			curr = currlevel + '0';
			break;
		}

		prev = prevlevel + '0';
		if (prev <= '0' || prev > '9')
			prev = 'N';

		printf("%c %c\n", prev , curr);
		return 0;
	}

	/* set runlevel */
	rq.runlevel = (int)arg[0];

	return client_send(&rq, sizeof(rq));
}

static int do_svc(int cmd, char *arg)
{
	struct init_request rq = {
		.magic = INIT_MAGIC,
		.cmd   = cmd,
		.data  = "",
	};

	if (arg)
		strlcpy(rq.data, arg, sizeof(rq.data));

	return client_send(&rq, sizeof(rq));
}

/*
 * This is a wrapper for do_svc() that adds a simple sanity check of
 * the service(s) provided as argument.  If a service does not exist
 * we make sure to return an error code.
 */
static int do_startstop(int cmd, char *arg)
{
	struct init_request rq = {
		.magic = INIT_MAGIC,
		.cmd   = INIT_CMD_SVC_QUERY
	};

	if (!arg || !arg[0])
		ERRX(2, "missing command argument");

	strlcpy(rq.data, arg, sizeof(rq.data));
	if (client_send(&rq, sizeof(rq)))
		ERRX(noerr ? 0 : 69, "no such task or service(s): %s", arg);

	return do_svc(cmd, arg);
}

#ifdef HAVE_DBUS

/* Map a LINK_CALL_ERROR reply on `c` to the appropriate ERRX exit:
 *    org.finit.Error.NoSuchService      -> exit 69 (legacy "no such svc")
 *    org.freedesktop.DBus.Error.AccessDenied -> exit 1 (permission denied)
 *    anything else                       -> exit 1 (method: err)
 * `c` is closed before exit either way.  Use exact-match on the
 * fully-qualified error name; a substring match would misfire on a
 * future name that contained one of these as a prefix. */
static void map_dbus_err(link_client_t *c, const char *method, const char *ident)
{
	const link_reply_t *r = link_client_reply(c);
	char err[128];

	/* The reply view points into c->rxbuf; copy the error name out
	 * before link_client_close() frees the client.  Otherwise the
	 * strcmps below read freed memory. */
	if (r && r->error_name)
		strlcpy(err, r->error_name, sizeof(err));
	else
		err[0] = '\0';
	link_client_close(c);

	if (!strcmp(err, "org.finit.Error.NoSuchService"))
		ERRX(noerr ? 0 : 69, "no such task or service(s): %s",
		     ident ? ident : "");
	if (!strcmp(err, "org.freedesktop.DBus.Error.AccessDenied"))
		ERRX(1, "permission denied: %s requires root", method);
	ERRX(1, "%s: %s", method, *err ? err : "D-Bus error");
}

/* Try the D-Bus path for a Manager1 method.  Returns:
 *    0  succeeded via D-Bus
 *   -1  D-Bus not reachable -- callers should fall back to the
 *       legacy INIT_SOCKET transport
 * LINK_CALL_ERROR is handled internally via map_dbus_err (does not
 * return). */
static int try_dbus_manager(const char *method, const char *arg_sig,
			    const char *arg)
{
	link_client_t *c;
	int            rc;

	c = link_client_open(FINIT_BUS_SOCKET);
	if (!c)
		return -1;

	/* "s" methods take the service identity (arg may be NULL ->
	 * empty string); void methods pass no body. */
	if (arg_sig && !strcmp(arg_sig, "s"))
		rc = link_client_call_v(c, "/org/finit/manager",
					"org.finit.Manager1", method,
					"s", arg ? arg : "");
	else if (!arg_sig || !*arg_sig)
		rc = link_client_call_v(c, "/org/finit/manager",
					"org.finit.Manager1", method, NULL);
	else
		rc = LINK_CALL_FAIL;

	if (rc == LINK_CALL_ERROR)
		map_dbus_err(c, method, arg);	/* exits */
	link_client_close(c);
	return (rc == LINK_CALL_OK) ? 0 : -1;
}

/* Build the object path for a service identity, same encoding as the
 * server side; use instead of a Manager1.GetService round-trip. */
static int dbus_svc_path(const char *ident, char *path, size_t len)
{
	const char *prefix = "/org/finit/service/";
	size_t plen = strlen(prefix);

	if (!ident || !*ident || plen >= len)
		return -1;
	memcpy(path, prefix, plen);
	return link_path_encode(ident, path + plen, len - plen);
}

/* Call a void-arg method on Service1 at /org/finit/service/<encoded>.
 * Same return convention as try_dbus_manager. */
static int try_dbus_service(const char *method, const char *ident)
{
	char path[256];
	link_client_t *c;
	int rc;

	if (dbus_svc_path(ident, path, sizeof(path)) < 0)
		return -1;

	c = link_client_open(FINIT_BUS_SOCKET);
	if (!c)
		return -1;

	rc = link_client_call_v(c, path, "org.finit.Service1", method, NULL);
	if (rc == LINK_CALL_ERROR)
		map_dbus_err(c, method, ident);	/* exits */
	link_client_close(c);
	return (rc == LINK_CALL_OK) ? 0 : -1;
}

/* Try one Cond1.{Get,Set,Clear} call.  On COND_GET success the helper
 * fills *out_exit with the exit code (0 = on, 1 = off, 255 = flux).
 * Outcomes:
 *   1   call succeeded; for GET the result is in *out_exit, for
 *       SET/CLR the caller loops to the next arg
 *   0   bus not reachable, or LINK_CALL_FAIL -- *bus is closed/NULLed
 *       and the caller should drop to the legacy filesystem path
 *   (LINK_CALL_ERROR exits via ERRX inside the helper)
 *
 * `*bus` is borrowed; the helper closes it (and sets NULL) on every
 * exit path that leaves the bus unusable. */
static int cond_dbus_call(link_client_t **bus, condop_t op,
			  const char *arg, int *out_exit)
{
	const char *method = (op == COND_GET) ? "Get"
			   : (op == COND_SET) ? "Set" : "Clear";
	int rc;

	if (!*bus)
		return 0;

	rc = link_client_call_v(*bus, "/org/finit/cond",
				"org.finit.Cond1", method,
				"s", arg);
	if (rc == LINK_CALL_OK) {
		if (op == COND_GET) {
			const char *state = NULL;

			link_reply_get_string(link_client_reply(*bus), &state);
			if (verbose && state)
				puts(state);
			*out_exit = (state && !strcmp(state, "on"))  ? 0
				  : (state && !strcmp(state, "off")) ? 1 : 255;
		}
		return 1;
	}
	if (rc == LINK_CALL_ERROR) {
		const link_reply_t *r = link_client_reply(*bus);
		const char *err = (r && r->error_name) ? r->error_name : "";

		link_client_close(*bus);
		*bus = NULL;
		if (!strcmp(err, "org.freedesktop.DBus.Error.AccessDenied"))
			ERRX(1, "permission denied: cond %s requires root", method);
		ERRX(73, "Failed %s condition <%s>: %s",
		     op == COND_SET ? "asserting" : "deasserting",
		     arg, *err ? err : "D-Bus error");
	}
	/* LINK_CALL_FAIL */
	link_client_close(*bus);
	*bus = NULL;
	return 0;
}

/* Subscribe to every signal on the bus and print one line per
 * incoming message:
 *     HH:MM:SS interface.member(arg1, arg2, ...)
 *
 * Only string-typed leading args are decoded (matches what our two
 * current signals -- ServiceStateChanged (sss) and ConditionChanged
 * (ss) -- emit).  Non-string args are silently skipped.  Loops until
 * the connection drops or the user hits ^C. */
static int do_monitor(char *arg)
{
	link_client_t *c;
	int            rc;

	(void)arg;

	c = link_client_open(FINIT_BUS_SOCKET);
	if (!c)
		ERRX(1, "monitor requires the D-Bus socket at %s", FINIT_BUS_SOCKET);

	rc = link_client_call_v(c, "/org/freedesktop/DBus",
				"org.freedesktop.DBus", "AddMatch",
				"s", "type='signal'");
	if (rc != LINK_CALL_OK) {
		link_client_close(c);
		ERRX(1, "AddMatch failed (rc=%d)", rc);
	}

	for (;;) {
		const link_reply_t *r;
		link_reader_t       reader;
		char                ts[16];
		time_t              now;
		struct tm           tm;

		rc = link_client_wait(c, -1);
		if (rc < 0) {
			link_client_close(c);
			ERRX(1, "bus connection lost");
		}
		if (rc > 0)	/* impossible with timeout=-1, but harmless */
			continue;
		r = link_client_reply(c);
		if (!r || r->type != LINK_MSG_SIGNAL)
			continue;

		now = time(NULL);
		localtime_r(&now, &tm);
		strftime(ts, sizeof(ts), "%H:%M:%S", &tm);
		printf("%s %s.%s(", ts,
		       r->interface ? r->interface : "?",
		       r->member    ? r->member    : "?");

		link_reader_init(&reader, r->body, r->body_len);
		if (r->signature) {
			const char *p;
			int         first = 1;

			for (p = r->signature; *p == 's'; p++) {
				const char *s;

				if (link_r_string(&reader, &s) < 0)
					break;
				printf("%s%s", first ? "" : ", ", s);
				first = 0;
			}
		}
		printf(")\n");
		fflush(stdout);
	}

	link_client_close(c);
	return 0;
}
#endif /* HAVE_DBUS */

static int do_start  (char *arg)
{
#ifdef HAVE_DBUS
	int rc = try_dbus_manager("Start", "s", arg);
	if (rc >= 0) return rc;
#endif
	return do_startstop(INIT_CMD_START_SVC, arg);
}

static int do_stop   (char *arg)
{
#ifdef HAVE_DBUS
	int rc = try_dbus_manager("Stop", "s", arg);
	if (rc >= 0) return rc;
#endif
	return do_startstop(INIT_CMD_STOP_SVC, arg);
}

static int do_reload (char *arg)
{
	if (!arg || !arg[0]) {
#ifdef HAVE_DBUS
		int rc = try_dbus_manager("Reload", "", NULL);
		if (rc >= 0) return rc;
#endif
		return do_svc(INIT_CMD_RELOAD, NULL);
	}

#ifdef HAVE_DBUS
	{
		int rc = try_dbus_service("Reload", arg);
		if (rc >= 0) return rc;
	}
#endif
	return do_startstop(INIT_CMD_RELOAD_SVC, arg);
}

static int do_restart(char *arg)
{
#ifdef HAVE_DBUS
	int rc = try_dbus_manager("Restart", "s", arg);
	if (rc == 0) return 0;
	if (rc == 1) ERRX(noerr ? 0 : 7, "failed restarting %s", arg);
#endif
	if (do_startstop(INIT_CMD_RESTART_SVC, arg))
		ERRX(noerr ? 0 : 7, "failed restarting %s", arg);

	return 0;
}

/**
 * do_signal - Ask finit to send a signal to a service.
 * @argv: must point to an array of strings, containing a service
 *        and signal name, in that order.
 * @argc: must be 2.
 *
 * A signal can be a complete signal name such as "SIGHUP", or
 * it can be the shortest unique name, such as "HUP" (no SIG prefix).
 * It can also be a raw signal number, such as "9" (SIGKILL).
 */
int do_signal(int argc, char *argv[])
{
	struct init_request rq = {
		.magic = INIT_MAGIC,
		.cmd   = INIT_CMD_SVC_QUERY
	};
	int signo;

	if (argc != 2)
		ERRX(2, "invalid number of arguments to signal");

	signo = str2sig(argv[1]);
	if (signo == -1) {
		const char *errstr = NULL;

		signo = (int)strtonum(argv[1], 1, 31, &errstr);
		if (errstr)
			ERRX(65, "%s signal: %s", errstr, argv[1]);
	}

#ifdef HAVE_DBUS
	{
		link_client_t *c = link_client_open(FINIT_BUS_SOCKET);

		if (c) {
			int rc = link_client_call_v(c, "/org/finit/manager",
						    "org.finit.Manager1", "Signal",
						    "su", argv[0], (uint32_t)signo);

			if (rc == LINK_CALL_ERROR)
				map_dbus_err(c, "Signal", argv[0]);	/* exits */
			link_client_close(c);
			if (rc == LINK_CALL_OK)
				return 0;
			/* LINK_CALL_FAIL: drop to legacy */
		}
	}
#endif

	strlcpy(rq.data, argv[0], sizeof(rq.data));
	if (client_send(&rq, sizeof(rq)))
		ERRX(noerr ? 0 : 69, "no such task or service(s): %s", argv[0]);

	/* Reuse runlevel for signal number. */
	rq.magic    = INIT_MAGIC;
	rq.cmd      = INIT_CMD_SIGNAL;
	rq.runlevel = signo;
	strlcpy(rq.data, argv[0], sizeof(rq.data));

	return client_send(&rq, sizeof(rq));
}

int dump_once;
char *dump_filter;
static int dump_one_cond(const char *fpath, const struct stat *sb, int tflag, struct FTW *ftwbuf)
{
	const char *cond, *asserted;
	char *nm = "init";
	pid_t pid = 1;
	svc_t *svc;

	if (tflag != FTW_F)
		return 0;

	if (!strcmp(fpath, _PATH_RECONF))
		return 0;

	asserted = condstr(cond_get_path(fpath));
	cond = &fpath[strlen(_PATH_COND)];

	if (dump_filter && dump_filter[0] && strncmp(cond, dump_filter, strlen(dump_filter)))
		return 0;

	/*
	 * Any namespace can be claimed with provides, so ask who owns
	 * the condition before falling back to what the namespace
	 * implies on its own.
	 */
	svc = client_svc_find_by_cond(cond);
	if (svc) {
		nm  = svc_ident(svc, NULL, 0);
		pid = svc->pid;
	} else if (strncmp("pid/", cond, 4) == 0) {
		nm  = "unknown";
		pid = 0;
	} else if (strncmp("usr/", cond, 4) == 0) {
		nm  = "static";
		pid = 0;
	} else if (strncmp("hook/", cond, 4) == 0) {
		nm  = "static";
		pid = 1;
	}

	if (json) {
		if (!dump_once)
			puts("[");

		printf("%s  {\n"
		       "    \"pid\": %d,\n"
		       "    \"identity\": \"%s\",\n"
		       "    \"status\": \"%s\",\n"
		       "    \"condition\": \"%s\"\n"
		       "  }",
		       dump_once ? ",\n" : "",
		       pid, nm, asserted, cond);

		dump_once++;
	} else
		printf("%-*d  %-*s  %-6s  <%s>\n", pw, pid, iw, nm, asserted, cond);

	return 0;
}

static int do_cond_dump(char *arg)
{
	col_widths();
	if (heading && !json)
		print_header("%-*s  %-*s  %-6s  %s", pw, "PID", iw, "IDENT",
			     "STATUS", "CONDITION");

	dump_once = 0;
	dump_filter = arg;
	if (nftw(_PATH_COND, dump_one_cond, 20, 0) == -1) {
		WARNX("Failed parsing %s", _PATH_COND);
		return 1;
	}
	if (dump_once)
		puts("\n]");

	return 0;
}

static cond_state_t cond_read(char *path)
{
	int now, gen;

	if (fngetint(path, &gen) == -1)
		return COND_OFF;

	/*
	 * if we cannot read the reconf generation, then either sth is
	 * very wrong, or we are called very early/late boot/shutdown.
	 */
	if (fngetint(_PATH_RECONF, &now) == -1)
		return COND_FLUX;	/* classify as flux */

	if (now != gen)
		return COND_FLUX;

	return COND_ON;
}

/*
 * cond get allows only one argument
 * cond set|clr iterate over multiple args
 */
static int do_cond_act(char *args, condop_t op)
{
	cond_state_t cstate;
	char path[256];
	char *arg;
#ifdef HAVE_DBUS
	link_client_t *bus = link_client_open(FINIT_BUS_SOCKET);
#endif

	if (!args || !args[0])
		ERRX(2, "Invalid condition (empty)");

	arg = strtok(args, " \t");
	while (arg) {
		size_t off;

		if (strncmp(arg, COND_USR, strlen(COND_USR)) == 0)
			arg += strlen(COND_USR);

		/* allowed to read any condition, but not set/clr */
		if (op != COND_GET) {
			if (strchr(arg, '/'))
				ERRX(2, "Invalid condition (slashes)");
			if (strchr(arg, '.'))
				ERRX(2, "Invalid condition (periods)");
		}

#ifdef HAVE_DBUS
		{
			int exit_code;

			if (cond_dbus_call(&bus, op, arg, &exit_code)) {
				if (op == COND_GET) {
					link_client_close(bus);
					return exit_code;
				}
				arg = strtok(NULL, " \t");
				continue;
			}
			/* bus is NULL now -- drop through to legacy */
		}
#endif

		if (strchr(arg, '/'))
			snprintf(path, sizeof(path), _PATH_COND "%s", arg);
		else
			snprintf(path, sizeof(path), _PATH_CONDUSR "%s", arg);
		off = strlen(_PATH_COND);

		switch (op) {
		case COND_GET:
			cstate = cond_read(path);
			if (verbose)
				puts(condstr(cstate));

			switch (cstate) {
			case COND_ON:
				return 0;
			case COND_OFF:
				return 1;
			case COND_FLUX:
			default:
				break;
			}
			return 255;

		case COND_SET:
			if (symlink(_PATH_RECONF, path) && errno != EEXIST)
				ERR(73, "Failed asserting condition <%s>", &path[off]);
			break;
		case COND_CLR:
			if (erase(path) && errno != ENOENT)
				ERR(73, "Failed deasserting condition <%s>", &path[off]);
			break;
		}

		arg = strtok(NULL, " \t");
	}

#ifdef HAVE_DBUS
	if (bus)
		link_client_close(bus);
#endif
	return 0;
}

static int do_cond_get(char *arg) { return do_cond_act(arg, COND_GET); }
static int do_cond_set(char *arg) { return do_cond_act(arg, COND_SET); }
static int do_cond_clr(char *arg) { return do_cond_act(arg, COND_CLR); }

static char *cond_string(const char *condstr, char *buf, size_t len, int ansi)
{
	char *cond, *conds;

	buf[0] = 0;

	if (!condstr || !condstr[0])
		return buf;

	conds = strdupa(condstr);
	if (!conds)
		return buf;

	if (json)
		strlcat(buf, "[ ", len);

	for (cond = strtok(conds, ","); cond; cond = strtok(NULL, ",")) {
		if (cond != conds) {
			strlcat(buf, ",", len);
			if (json)
				strlcat(buf, " ", len);
		}

		if (json)
			strlcat(buf, "\"", len);

		switch (cond_get(cond)) {
		case COND_ON:
			strlcat(buf, "+", len);
			strlcat(buf, cond, len);
			break;

		case COND_FLUX:
			if (ansi)
				strlcat(buf, "\e[1m", len);
			strlcat(buf, "~", len);
			strlcat(buf, cond, len);
			if (ansi)
				strlcat(buf, "\e[0m", len);
			break;

		case COND_OFF:
			if (ansi)
				strlcat(buf, "\e[1m", len);
			strlcat(buf, "-", len);
			strlcat(buf, cond, len);
			if (ansi)
				strlcat(buf, "\e[0m", len);
			break;
		}

		if (json)
			strlcat(buf, "\"", len);
	}

	if (json)
		strlcat(buf, " ]", len);

	return buf;
}

static char *svc_cond(svc_t *svc, char *buf, size_t len, int ansi)
{
	return cond_string(svc->cond, buf, len, ansi);
}

static int do_cond_show(char *arg)
{
	enum cond_state cond;
	char buf[512];
	int once = 0;
	svc_t *svc;

	col_widths();
	if (heading && !json)
		print_header("%-*s  %-*s  %-6s  %s", pw, "PID", iw, "IDENT",
			     "STATUS", "CONDITION (+ ON, ~ FLUX, - OFF)");

	for (svc = client_svc_iterator(1); svc; svc = client_svc_iterator(0)) {
		if (!svc->cond[0])
			continue;

		cond = cond_get_agg(svc->cond);
		svc_ident(svc, buf, sizeof(buf));

		if (json) {
			if (!once)
				puts("[");

			printf("%s  {\n"
			       "    \"pid\": %d,\n"
			       "    \"identity\": \"%s\",\n"
			       "    \"status\": \"%s\",\n",
			       once ? ",\n" : "",
			       svc->pid,
			       buf,
			       condstr(cond));
			svc_cond(svc, buf, sizeof(buf), !plain);
			printf("    \"condition\": %s\n"
			       "  }", buf);

			once++;
			continue;
		}

		printf("%-*d  %-*s  ", pw, svc->pid, iw, buf);

		if (cond == COND_ON)
			printf("%-6.6s  ", condstr(cond));
		else
			printf("\e[1m%-6.6s\e[0m  ", condstr(cond));

		svc_cond(svc, buf, sizeof(buf), !plain);
		if (buf[0])
			printf("<%s>", buf);
		puts("");
	}

	if (json && once)
		puts("\n]");

	return 0;
}

static int do_cmd(int cmd)
{
	struct init_request rq = {
		.magic     = INIT_MAGIC,
		.cmd       = cmd,
		.sleeptime = timeout,
	};

	if (client_send(&rq, sizeof(rq))) {
		if (rq.cmd == INIT_CMD_NACK)
			puts(rq.data);

		return 1;
	}

	/* Wait here for systemd to shutdown/reboot */
	sleep(5);

	return 0;
}

#ifdef HAVE_DBUS
static int do_reboot_dbus(const char *method)
{
	int rc = try_dbus_manager(method, "", NULL);

	if (rc == 0) {
		sleep(5);	/* match legacy: wait for finit to shut down */
		return 0;
	}
	return rc;	/* 1 = error, -1 = fall back */
}
#endif

int do_reboot  (char *arg)
{
#ifdef HAVE_DBUS
	int rc = do_reboot_dbus("Reboot");
	if (rc >= 0) return rc;
#endif
	return do_cmd(INIT_CMD_REBOOT);
}

int do_halt    (char *arg)
{
#ifdef HAVE_DBUS
	int rc = do_reboot_dbus("Halt");
	if (rc >= 0) return rc;
#endif
	return do_cmd(INIT_CMD_HALT);
}

int do_poweroff(char *arg)
{
#ifdef HAVE_DBUS
	int rc = do_reboot_dbus("Poweroff");
	if (rc >= 0) return rc;
#endif
	return do_cmd(INIT_CMD_POWEROFF);
}

int do_suspend(char *arg)
{
	(void)arg;
#ifdef HAVE_DBUS
	{
		int rc = try_dbus_manager("Suspend", "", NULL);
		if (rc >= 0) return rc;
	}
#endif
	return do_cmd(INIT_CMD_SUSPEND);
}

/**
 * do_switch_root - Switch to a new root filesystem (initramfs only)
 * @argc: Number of arguments (1 or 2)
 * @argv: [0] = newroot path, [1] = optional init path
 *
 * This command is only valid during runlevel S (bootstrap) or 1 when
 * running from an initramfs.  It stops all services, moves virtual
 * filesystems, and exec's the new init.
 */
int do_switch_root(int argc, char *argv[])
{
	struct init_request rq = {
		.magic = INIT_MAGIC,
		.cmd   = INIT_CMD_SWITCH_ROOT,
	};
	char *newroot, *newinit = NULL;
	size_t off;

	if (argc < 1)
		ERRX(2, "Usage: initctl switch-root NEWROOT [INIT]");

	newroot = argv[0];
	if (argc > 1)
		newinit = argv[1];

	/* Verify newroot exists */
	if (access(newroot, F_OK))
		ERR(1, "Cannot access %s", newroot);

	/*
	 * Pack both strings into rq.data with null separators:
	 * "newroot\0newinit\0"
	 */
	strlcpy(rq.data, newroot, sizeof(rq.data));
	off = strlen(newroot) + 1;

	if (newinit && off < sizeof(rq.data) - 1)
		strlcpy(rq.data + off, newinit, sizeof(rq.data) - off);

	printf("Switching root to %s", newroot);
	if (newinit)
		printf(", init %s", newinit);
	printf(" ...\n");

	/*
	 * On success, finit exec's new init and we lose connection.
	 * A "failure" to read reply is actually expected on success.
	 */
	client_send(&rq, sizeof(rq));

	return 0;
}

int utmp_show(char *file)
{
	struct utmp *ut;
	time_t sec;

	if (heading) {
		static int once = 0;

		print_header("%s%s ", once ? "\n" : "", file);
		once++;
	}
	utmpname(file);

	setutent();
	while ((ut = getutent())) {
		char user[sizeof(ut->ut_user) + 1];
		char id[sizeof(ut->ut_id) + 1];
		struct tm *sectm;
		char when[80];
		char addr[64];
		int pid;

		strlcpy(id, ut->ut_id, sizeof(id));
		strlcpy(user, ut->ut_user, sizeof(user));

		sec = ut->ut_tv.tv_sec;
		sectm = localtime(&sec);
		strftime(when, sizeof(when), "%F %T", sectm);

		pid = ut->ut_pid;
		if (ut->ut_addr_v6[1] || ut->ut_addr_v6[2] || ut->ut_addr_v6[3])
			inet_ntop(AF_INET6, ut->ut_addr_v6, addr, sizeof(addr));
		else
			inet_ntop(AF_INET, &ut->ut_addr, addr, sizeof(addr));

		printf("[%d] [%05d] [%-4.4s] [%-8.8s] [%-12.12s] [%-20.20s] [%-15.15s] [%-19.19s]\n",
		       ut->ut_type, pid, id, user, ut->ut_line, ut->ut_host, addr, when);
	}
	endutent();

	return 0;
}

static int do_utmp(char *file)
{
	if (!utmp)
		return 1;

	if (fexist(file))
		return utmp_show(file);

	return  utmp_show(_PATH_WTMP) ||
		utmp_show(_PATH_UTMP);
}

static int show_version(char *arg)
{
	puts(PACKAGE_STRING);
	printf("Bug report address: %-40s\n", PACKAGE_BUGREPORT);
#ifdef PACKAGE_URL
	printf("Project homepage: %s\n", PACKAGE_URL);
#endif

	return 0;
}

static int plugins_list(char *arg)
{
	struct init_request rq = {
		.magic = INIT_MAGIC,
		.cmd   = INIT_CMD_GET_PLUGINS,
	};
	char buf[sizeof(rq.data) + 1];
	char *ptr;
	int rc;

	rc = client_send(&rq, sizeof(rq));
	if (rc) {
		if (rc == 255)
			return 69;
		else
			ERRX(69, "No such command");
	}
	memcpy(buf, rq.data, sizeof(buf) - 1);
	buf[sizeof(rq.data)] = 0;

	if (heading)
		print_header("%-18s  %s", "PLUGIN", "DEPENDENCIES");

	ptr = strtok(buf, " ");
	while (ptr) {
		rq.cmd = INIT_CMD_PLUGIN_DEPS;
		strlcpy(rq.data, ptr, sizeof(rq.data));
		rc = client_send(&rq, sizeof(rq));
		if (rc)
			printf("%s\n", ptr);
		else
			printf("%-18s  %s\n", ptr, rq.data);

		ptr = strtok(NULL, " ");
	}

	return 0;
}

/**
 * runlevel_string - Convert a bit encoded runlevel to .conf syntax
 * @levels: Bit encoded runlevels
 *
 * Returns:
 * Pointer to string on the form [2345], may be up to 12 chars long,
 * plus escape sequences for highlighting current runlevel.
 */
char *runlevel_string(int currlevel, int levels)
{
	static char lvl[32];
	int i = INIT_LEVEL;

	strlcpy(lvl, "[", sizeof(lvl));

	do {
		if (ISSET(levels, i)) {
			char l[2] = { '0' + i, 0 };

			if (!plain && currlevel == i)
				strlcat(lvl, "\e[1m", sizeof(lvl));

			strlcat(lvl, i == INIT_LEVEL ? "S" : l, sizeof(lvl));

			if (!plain && currlevel == i)
				strlcat(lvl, "\e[0m", sizeof(lvl));
		} else {
			strlcat(lvl, "-", sizeof(lvl));
		}

		/* XXX: ugly hack to get order right: S0123456789 */
		if (i == INIT_LEVEL)
			i = 0;
		else
			i++;
	} while (i < INIT_LEVEL);

	strlcat(lvl, "]", sizeof(lvl));

	return lvl;
}

char *runlevel_arr(int levels)
{
	static char lvl[42];
	int i = INIT_LEVEL;
	int p = 2, s = 0;

	strlcpy(lvl, "[ ", sizeof(lvl));
	do {
		if (ISSET(levels, i)) {
			if (i == INIT_LEVEL)
				p += snprintf(&lvl[p], sizeof(lvl) - p, "\"S\"");
			else
				p += snprintf(&lvl[p], sizeof(lvl) - p, "%s%c", s ? ", " : "", '0' + i);
			s++;
		}
		/* XXX: ugly hack to get order right: S0123456789 */
		if (i == INIT_LEVEL)
			i = 0;
		else
			i++;
	} while (i < INIT_LEVEL);
	strlcat(lvl, " ]", sizeof(lvl));

	return lvl;
}

static char *svc_command(svc_t *svc, char *buf, size_t len)
{
	strlcpy(buf, svc->cmd, len);

	for (int i = 1; i < MAX_NUM_SVC_ARGS; i++) {
		if (!svc->args[i][0])
			break;

		strlcat(buf, " ", len);
		strlcat(buf, svc->args[i], len);
	}

	if (svc_is_sysv(svc)) {
		char *cmd = svc->state == SVC_HALTED_STATE ? "stop" : "start";

		strlcat(buf, " ", len);
		strlcat(buf, cmd, len);
	}

	return buf;
}

static char *exit_status_raw(int status, int manual, char *buf, size_t len)
{
	int rc, sig;
	char *str;

	rc = WEXITSTATUS(status);
	sig = WTERMSIG(status);

	if (WIFEXITED(status)) {
		str = code2str(rc);
		snprintf(buf, len, " (code=exited, status=%d%s%s%s)", rc,
			 str[0] ? "/" : "", str,
			 manual ? ", manual=yes" : "");
	}
	else if (WIFSIGNALED(status)) {
		str = sig2str(sig);
		snprintf(buf, len, " (code=signal, status=%d%s%s)", sig, str[0] ? "/" : "", str);
	}

	return buf;
}

static void show_cgroup_tree(char *group, char *pfx)
{
	char path[256];

	if (!group) {
		puts("");
		return;
	}

	strlcpy(path, FINIT_CGPATH, sizeof(path));
	strlcat(path, group, sizeof(path));

	cgroup_tree(path, pfx, 0, 0);
}

/*
 * arg: 'foo'   should match foo:1 foo:2, etc. but not foobar
 * arg: 'foo:1' should only match foo:1
 * arg: 'foo:'  is allowed to fail, unsupported syntax atm
 * arg: 'foo:*' is allowed to fail, unsupported syntax atm
 */
static int svc_compare(svc_t *svc, char *arg)
{
	char ident[MAX_IDENT_LEN];
	char *ptr;

	svc_ident(svc, ident, sizeof(ident));
	ptr = strchr(ident, ':');
	if (ptr && !strchr(arg, ':'))
		*ptr = 0;

	if (!strcmp(ident, arg))
		return 1;

	return 0;
}

/*
 * All fields the status views need, transport-independent: filled
 * from a raw svc_t on the legacy socket path or from Service1
 * properties on the D-Bus path, rendered by the same printers.
 */
struct svc_row {
	char     ident[MAX_IDENT_LEN];
	char     state[16];
	char     type[16];
	char     desc[MAX_STR_LEN];
	char     cmdline[512];
	char     env[MAX_CMD_LEN];
	char     cond[MAX_COND_LEN];
	char     pidfile[MAX_CMD_LEN];
	char     user[MAX_USER_LEN];
	char     grp[MAX_USER_LEN];
	char     origin[MAX_ARG_LEN];
	uint32_t pid;
	uint32_t runlevels;
	uint32_t uptime;	/* seconds, 0 when not running */
	uint32_t exitstatus;	/* raw waitpid(2) status */
	uint32_t starts;
	int32_t  restart_tot;
	int32_t  restart_cnt;
	int32_t  restart_max;	/* -1 = restart:always */
	int      manual;
	int      forking;
	int      started;
};

static void fill_row_from_svc(struct svc_row *r, svc_t *svc)
{
	long now = jiffies();

	memset(r, 0, sizeof(*r));
	svc_ident(svc, r->ident, sizeof(r->ident));
	strlcpy(r->state,   svc_status(svc),  sizeof(r->state));
	strlcpy(r->type,    svc_typestr(svc), sizeof(r->type));
	strlcpy(r->desc,    svc->desc,        sizeof(r->desc));
	svc_command(svc, r->cmdline, sizeof(r->cmdline));
	strlcpy(r->env,     svc->env,         sizeof(r->env));
	strlcpy(r->cond,    svc->cond,        sizeof(r->cond));
	strlcpy(r->pidfile, svc->pidfile,     sizeof(r->pidfile));
	strlcpy(r->user,    svc->username,    sizeof(r->user));
	strlcpy(r->grp,     svc->group,       sizeof(r->grp));
	strlcpy(r->origin,  svc->file,        sizeof(r->origin));
	r->pid         = svc->pid > 0 ? (uint32_t)svc->pid : 0;
	r->runlevels   = (uint32_t)svc->runlevels;
	if (svc->pid && now > svc->start_time)
		r->uptime = (uint32_t)(now - svc->start_time);
	r->exitstatus  = (uint32_t)svc->status;
	r->starts      = (uint32_t)svc->once;
	r->restart_tot = (int32_t)svc->restart_tot;
	r->restart_cnt = (int32_t)svc->restart_cnt;
	r->restart_max = (int32_t)svc->restart_max;
	r->manual      = svc->manual;
	r->forking     = svc->forking;
	r->started     = svc->started;
}

static const char *pidfile_str(struct svc_row *r)
{
	const char *pidfn = r->pidfile;

	if (pidfn[0] == '!')
		pidfn++;
	else if (pidfn[0] == 0)
		pidfn = "none";

	return pidfn;
}

/* string-only twin of svc_checkenv() */
static int checkenv_str(const char *env)
{
	if (!env || !env[0] || env[0] == '-')
		return 1;

	return fexist(env);
}

/* same matching rules as svc_compare() */
static int row_compare(struct svc_row *r, char *arg)
{
	char ident[MAX_IDENT_LEN];
	char *ptr;

	strlcpy(ident, r->ident, sizeof(ident));
	ptr = strchr(ident, ':');
	if (ptr && !strchr(arg, ':'))
		*ptr = 0;

	return !strcmp(ident, arg);
}

static int row_missing(struct svc_row *r)
{
	char argv0[512];
	char *sep;

	if (strcmp(r->state, "missing"))
		return 0;

	strlcpy(argv0, r->cmdline, sizeof(argv0));
	sep = strchr(argv0, ' ');
	if (sep)
		*sep = 0;

	return !whichp(argv0);
}

/* the words svc_status() emits for a blocked/halted service */
static const char *halted_words[] = {
	"halted", "missing", "crashed", "stopped", "busy",
	"restart", "conflict", "unknown", NULL
};

/* transport-independent status(svc, full) */
static char *row_status(struct svc_row *r, int full)
{
	static char buf[96];
	const char *color;
	char ok[48] = {0};
	int  st = (int)r->exitstatus;
	size_t i;

	if (!full) {
		snprintf(buf, sizeof(buf), "%-8.8s", r->state);
		return buf;
	}

	if (!strcmp(r->state, "running")) {
		color = "\e[1;32m";
	} else if (!strcmp(r->state, "done") || !strcmp(r->state, "failed")) {
		exit_status_raw(st, r->manual, ok, sizeof(ok));
		if (WIFEXITED(st))
			color = WEXITSTATUS(st) ? "\e[1;31m" : "\e[1;32m";
		else if (WIFSIGNALED(st))
			color = "\e[1;31m";
		else
			color = "\e[1;33m";
	} else {
		exit_status_raw(st, r->manual, ok, sizeof(ok));
		color = "\e[1;33m";
		for (i = 0; halted_words[i]; i++) {
			if (!strcmp(r->state, halted_words[i])) {
				color = "\e[1m";
				break;
			}
		}
	}

	if (plain)
		color = NULL;

	snprintf(buf, sizeof(buf), "%s%s%s%s",
		 color ? color : "", r->state, ok, color ? "\e[0m" : "");

	return buf;
}

/* scripting mode: exit code only, same rules as the legacy path */
static int quiet_row(struct svc_row *r)
{
	if (!strcmp(r->type, "run") || !strcmp(r->type, "task"))
		return r->started ? 0 : 1;

	return strcmp(r->state, "running") != 0;
}

/*
 * Escape a string for safe JSON output. Handles quotes, backslashes,
 * and control characters.  Returns pointer to static buffer.
 */
static char *json_escape(const char *str)
{
	static char buf[1024];
	char *ptr = buf;
	size_t left = sizeof(buf) - 1;

	if (!str)
		return "";

	while (*str && left > 1) {
		char c = *str++;

		switch (c) {
		case '"':
		case '\\':
			*ptr++ = '\\';
			*ptr++ = c;
			left -= 2;
			break;
		case '\n':
			*ptr++ = '\\';
			*ptr++ = 'n';
			left -= 2;
			break;
		case '\r':
			*ptr++ = '\\';
			*ptr++ = 'r';
			left -= 2;
			break;
		case '\t':
			*ptr++ = '\\';
			*ptr++ = 't';
			left -= 2;
			break;
		default:
			if ((unsigned char)c < 0x20) {
				/* Other control chars: use \uXXXX */
				int n = snprintf(ptr, left, "\\u%04x", (unsigned char)c);
				ptr += n;
				left -= n;
			} else {
				*ptr++ = c;
				left--;
			}
			break;
		}
	}
	*ptr = '\0';

	return buf;
}

static int json_status_one(FILE *fp, struct svc_row *r, char *indent, int prev)
{
	const char *pidfn = pidfile_str(r);
	char buf[512];

	fprintf(fp,
		"%s"
		"%s{\n"
		"%s  \"identity\": \"%s\",\n",
		prev ? ",\n" : indent, prev ? indent : "",
		indent, r->ident);
	fprintf(fp,
		"%s  \"description\": \"%s\",\n",
		indent, json_escape(r->desc));
	fprintf(fp,
		"%s  \"type\": \"%s\",\n"
		"%s  \"forking\": %s,\n"
		"%s  \"status\": \"%s\",\n",
		indent, r->type,
		indent, r->forking ? "true" : "false",
		indent, r->state);

	if (strcmp(r->state, "running")) {
		int st = (int)r->exitstatus;
		int rc, sig;

		rc = WEXITSTATUS(st);
		sig = WTERMSIG(st);

		if (WIFEXITED(st))
			fprintf(fp,
				"%s  \"exit\": { \"%s\": %d },\n",
				indent, "code", rc);
		else if (WIFSIGNALED(st))
			fprintf(fp,
				"%s  \"exit\": { \"%s\": %d },\n",
				indent, "signal", sig);
	}

	fprintf(fp,
		"%s  \"origin\": \"%s\",\n",
		indent, r->origin[0] ? r->origin : "built-in");
	fprintf(fp,
		"%s  \"command\": \"%s\",\n",
		indent, json_escape(r->cmdline));

	if (r->env[0])
		fprintf(fp,
			"%s  \"environment\": \"%s\",\n", indent, json_escape(r->env));

	cond_string(r->cond, buf, sizeof(buf), 0);
	if (buf[0])
		fprintf(fp,
			"%s  \"condition\": %s,\n", indent, buf);

	if (r->manual)
		fprintf(fp,
			"%s  \"starts\": %u,\n", indent, r->starts);

	fprintf(fp,
		"%s  \"restarts\": %d,\n", indent, r->restart_tot); /* XXX: add restart_cnt and restart_max */

	/* Add memory and CPU information if cgroup support is available */
	if (cgrp && r->pid > 1) {
		char *group = pid_cgroup(r->pid);

		if (group) {
			uint64_t throttled_usec = 0;
			uint64_t nr_throttled = 0;
			char path[256];
			struct cg *cg;

			fprintf(fp, "%s  \"cgroup\": \"%s\",\n", indent, group);
			fprintf(fp, "%s  \"memory\": %lu,\n", indent, cgroup_memory(group));

			if (cgroup_throttle(group, &throttled_usec, &nr_throttled) == 0) {
				fprintf(fp, "%s  \"cpu\": {\n", indent);
				fprintf(fp, "%s    \"throttled_usec\": %lu,\n", indent, throttled_usec);
				fprintf(fp, "%s    \"nr_throttled\": %lu\n", indent, nr_throttled);
				fprintf(fp, "%s  },\n", indent);
			}

			/* Add limits structure using existing cg_conf() */
			snprintf(path, sizeof(path), "%s/%s", FINIT_CGPATH, group);
			cg = cg_conf(path);

			if (cg && (cg->cg_mem.min[0] || cg->cg_mem.max[0] ||
				   cg->cg_cpu.weight[0] || cg->cg_cpu.max[0])) {
				int has_memory = cg->cg_mem.min[0] || cg->cg_mem.max[0];
				int has_cpu = cg->cg_cpu.weight[0] || cg->cg_cpu.max[0];

				fprintf(fp, "%s  \"limits\": {\n", indent);

				if (has_memory) {
					fprintf(fp, "%s    \"memory\": {\n", indent);
					if (cg->cg_mem.min[0]) {
						if (!strcmp(cg->cg_mem.min, "max"))
							fprintf(fp, "%s      \"min\": \"%s\"", indent, cg->cg_mem.min);
						else
							fprintf(fp, "%s      \"min\": %s", indent, cg->cg_mem.min);
						if (cg->cg_mem.max[0])
							fprintf(fp, ",\n");
						else
							fprintf(fp, "\n");
					}
					if (cg->cg_mem.max[0]) {
						if (!strcmp(cg->cg_mem.max, "max"))
							fprintf(fp, "%s      \"max\": \"%s\"\n", indent, cg->cg_mem.max);
						else
							fprintf(fp, "%s      \"max\": %s\n", indent, cg->cg_mem.max);
					}
					fprintf(fp, "%s    }", indent);
					if (has_cpu)
						fprintf(fp, ",\n");
					else
						fprintf(fp, "\n");
				}

				if (has_cpu) {
					char cpu_burst[32];
					char *quota, *period;
					char max_copy[32];

					fprintf(fp, "%s    \"cpu\": {\n", indent);

					if (cg->cg_cpu.weight[0])
						fprintf(fp, "%s      \"weight\": %s,\n", indent, cg->cg_cpu.weight);

					if (cg->cg_cpu.max[0]) {
						/* Split cpu.max into quota and period */
						strlcpy(max_copy, cg->cg_cpu.max, sizeof(max_copy));
						quota = strtok(max_copy, " ");
						period = strtok(NULL, " ");

						fprintf(fp, "%s      \"max\": {\n", indent);
						if (quota) {
							if (!strcmp(quota, "max"))
								fprintf(fp, "%s        \"quota\": \"%s\"", indent, quota);
							else
								fprintf(fp, "%s        \"quota\": %s", indent, quota);
							if (period)
								fprintf(fp, ",\n");
							else
								fprintf(fp, "\n");
						}
						if (period)
							fprintf(fp, "%s        \"period\": %s\n", indent, period);
						fprintf(fp, "%s      }", indent);

						/* Check for cpu.max.burst (kernel >= 5.14) */
						if (cgroup_val(path, "cpu.max.burst", cpu_burst, sizeof(cpu_burst)))
							fprintf(fp, ",\n%s      \"max_burst\": %s\n", indent, cpu_burst);
						else
							fprintf(fp, "\n");
					}

					fprintf(fp, "%s    }\n", indent);
				}

				fprintf(fp, "%s  },\n", indent);
			}

			free(group);
		}
	}

	fprintf(fp,
		"%s  \"pidfile\": \"%s\",\n"
		"%s  \"pid\": %u,\n"
		"%s  \"user\": \"%s\",\n"
		"%s  \"group\": \"%s\",\n"
		"%s  \"uptime\": %ld,\n"
		"%s  \"runlevels\": %s\n"
		"%s}",
		indent, pidfn,
		indent, r->pid,
		indent, r->user,
		indent, r->grp,
		indent, (long)r->uptime,
		indent, runlevel_arr((int)r->runlevels),
		indent);

	return 0;
}

static void status_heading(int pidw, int identw)
{
	char title[80];

	snprintf(title, sizeof(title), "%-*s  %-*s  %-8s %-13s ",
		 pidw, "PID", identw, "IDENT", "STATUS", "RUNLEVELS");
	strlcat(title, !verbose ? "DESCRIPTION" : "COMMAND", sizeof(title));
	print_header("%s", title);
}

static void print_runlevels(const char *lvls)
{
	/* ANSI escapes for the active level eat into the field width */
	if (strchr(lvls, '\e'))
		printf("%-21.21s ", lvls);
	else
		printf("%-13.13s ", lvls);
}

/*
 * The detail view, shared by the legacy and D-Bus paths; the caller
 * fills a svc_row from its transport first.  Cgroup statistics and
 * the log tail are always local operations, they only need the PID.
 */
static int show_one_row(struct svc_row *r)
{
	char uptm[42] = "N/A";
	char buf[512];
	int bold;

	printf("     Status : %s\n", row_status(r, 1));
	printf("   Identity : %s\n", r->ident);
	printf("Description : %s\n", r->desc);
	printf("     Origin : %s\n", r->origin[0] ? r->origin : "built-in");

	if (r->env[0]) {
		bold = !plain && !strcmp(r->state, "missing") &&
			!checkenv_str(r->env);
		printf("Environment : %s%s%s\n", bold ? "\e[1m" : "",
		       r->env, bold ? "\e[0m" : "");
	}

	cond_string(r->cond, buf, sizeof(buf), !plain);
	if (buf[0])
		printf("Condition(s): <%s>\n", buf);

	bold = !plain && row_missing(r);
	printf("    Command : %s%s%s\n", bold ? "\e[1m" : "",
	       r->cmdline, bold ? "\e[0m" : "");
	printf("   PID file : %s\n", pidfile_str(r));
	printf("        PID : %u\n", r->pid);
	printf("       User : %s\n", r->user);
	printf("      Group : %s\n", r->grp);
	printf("     Uptime : %s\n", r->pid
	       ? uptime((long)r->uptime, uptm, sizeof(uptm)) : uptm);
	if (r->manual)
		printf("     Starts : %u\n", r->starts);
	printf("   Restarts : %d (%d/%d)\n",
	       r->restart_tot, r->restart_cnt, r->restart_max);
	printf("  Runlevels : %s\n",
	       runlevel_string(runlevel, (int)r->runlevels));

	if (cgrp && r->pid > 1) {
		const struct cg *cg;
		uint64_t throttled_usec = 0;
		uint64_t nr_throttled = 0;
		char path[256];
		char *group;

		group = pid_cgroup(r->pid);
		if (!group)
			goto no_cgroup; /* ... or PID doesn't exist (anymore) */

		snprintf(path, sizeof(path), "%s/%s", FINIT_CGPATH, group);
		cg = cg_conf(path);

		printf("     Memory : %s\n", memsz(cgroup_memory(group), uptm, sizeof(uptm)));

		if (cgroup_throttle(group, &throttled_usec, &nr_throttled) == 0) {
			printf("CPU Throttle : %lu usec (%lu times)\n",
			       throttled_usec, nr_throttled);
		}

		printf("     CGroup : %s cpu %s [%s, %s] mem [%s, %s]\n",
		       group, cg->cg_cpu.set, cg->cg_cpu.weight, cg->cg_cpu.max,
		       cg->cg_mem.min, cg->cg_mem.max);
		show_cgroup_tree(group, "              ");

		free(group);
	}
no_cgroup:
	printf("\n");

	return do_log_named(r->ident, r->pid, "| tail -10");
}

static void render_table(struct svc_row *rows, int n, char *filter)
{
	int i, identw = 0, pidw = 0;

	for (i = 0; i < n; i++) {
		int w;

		w = (int)strlen(rows[i].ident);
		if (w > identw)
			identw = w;
		w = snprintf(NULL, 0, "%u", rows[i].pid);
		if (w > pidw)
			pidw = w;
	}
	if (identw < 6)
		identw = 6;
	if (pidw < 3)
		pidw = 3;

	if (heading)
		status_heading(pidw, identw);

	for (i = 0; i < n; i++) {
		struct svc_row *r = &rows[i];

		if (filter && !row_compare(r, filter))
			continue;

		printf("%-*u  ", pidw, r->pid);
		printf("%-*s  %s ", identw, r->ident, row_status(r, 0));
		print_runlevels(runlevel_string(runlevel, (int)r->runlevels));

		if (!verbose)
			puts(r->desc);
		else {
			int bold = !plain && row_missing(r);

			printf("%s%s%s\n", bold ? "\e[1m" : "",
			       r->cmdline, bold ? "\e[0m" : "");
		}
	}
}

#ifdef HAVE_DBUS
/*
 * Service1 wire properties -> svc_row fields.  Unknown keys and
 * value types are skipped so newer finit keeps working with older
 * initctl.
 */
#define ROW_STR(k, f)  { k, 's', offsetof(struct svc_row, f), \
			 sizeof(((struct svc_row *)0)->f) }
#define ROW_U32(k, f)  { k, 'u', offsetof(struct svc_row, f), 0 }
#define ROW_BOOL(k, f) { k, 'b', offsetof(struct svc_row, f), 0 }

static const struct row_field {
	const char *key;
	char        type;
	size_t      off;
	size_t      len;
} row_fields[] = {
	ROW_STR ("State",         state),
	ROW_STR ("Type",          type),
	ROW_STR ("Description",   desc),
	ROW_STR ("Command",       cmdline),
	ROW_STR ("Environment",   env),
	ROW_STR ("Conditions",    cond),
	ROW_STR ("PidFile",       pidfile),
	ROW_STR ("User",          user),
	ROW_STR ("Group",         grp),
	ROW_STR ("Origin",        origin),
	ROW_U32 ("Pid",           pid),
	ROW_U32 ("Runlevels",     runlevels),
	ROW_U32 ("Uptime",        uptime),
	ROW_U32 ("ExitStatus",    exitstatus),
	ROW_U32 ("Starts",        starts),
	ROW_U32 ("RestartsTotal", restart_tot),
	ROW_U32 ("RestartCount",  restart_cnt),
	ROW_U32 ("RestartMax",    restart_max),
	ROW_BOOL("ManualStart",   manual),
	ROW_BOOL("Forking",       forking),
	ROW_BOOL("Started",       started),
	{ NULL, 0, 0, 0 }
};

/*
 * One service's Properties.GetAll into a row.  Returns 0 on success,
 * 1 when the object vanished since ListServices (bus error reply),
 * -1 on transport failure.
 */
static int dbus_fill_row(link_client_t *c, struct svc_row *row)
{
	const link_reply_t *r;
	link_reader_t reader;
	char path[256];
	size_t end;
	int rc;

	if (dbus_svc_path(row->ident, path, sizeof(path)) < 0)
		return -1;

	rc = link_client_call_v(c, path,
				"org.freedesktop.DBus.Properties",
				"GetAll", "s", "org.finit.Service1");
	if (rc == LINK_CALL_ERROR)
		return 1;	/* gone since ListServices */
	if (rc != LINK_CALL_OK)
		return -1;
	r = link_client_reply(c);
	if (!r || !r->body)
		return -1;

	link_reader_init(&reader, r->body, r->body_len);
	if (link_r_array_begin(&reader, &end) < 0)
		return -1;

	while (link_r_pos(&reader) < end) {
		const struct row_field *f;
		const char *key, *val;
		uint32_t    u;
		int         b;
		char        type;

		if (dbus_dict_next(&reader, &key, &type) < 0)
			return -1;

		for (f = row_fields; f->key; f++)
			if (f->type == type && !strcmp(f->key, key))
				break;

		if (!f->key) {
			if (link_r_skip_basic(&reader, type) < 0)
				return -1;
			continue;
		}

		switch (type) {
		case 's':
			if (link_r_string(&reader, &val) < 0)
				return -1;
			strlcpy((char *)row + f->off, val, f->len);
			break;
		case 'u':
			if (link_r_u32(&reader, &u) < 0)
				return -1;
			memcpy((char *)row + f->off, &u, sizeof(u));
			break;
		case 'b':
			if (link_r_bool(&reader, &b) < 0)
				return -1;
			memcpy((char *)row + f->off, &b, sizeof(b));
			break;
		}
	}

	return 0;
}

/*
 * ListServices into a caller-freed ident array.  One round trip;
 * show_ident() needs nothing more.  Returns count or -1.
 */
static int dbus_list_idents(link_client_t *c, char (**out)[MAX_IDENT_LEN])
{
	char (*idents)[MAX_IDENT_LEN] = NULL, (*tmp)[MAX_IDENT_LEN];
	const link_reply_t *r;
	link_reader_t reader;
	size_t n = 0, end;
	int rc;

	rc = link_client_call_v(c, "/org/finit/manager",
				"org.finit.Manager1", "ListServices", NULL);
	if (rc != LINK_CALL_OK)
		return -1;

	r = link_client_reply(c);
	if (!r || !r->body)
		return -1;

	link_reader_init(&reader, r->body, r->body_len);
	if (link_r_array_begin(&reader, &end) < 0)
		return -1;

	while (link_r_pos(&reader) < end) {
		const char *ident;

		if (link_r_string(&reader, &ident) < 0)
			goto fail;
		tmp = realloc(idents, (n + 1) * sizeof(*idents));
		if (!tmp)
			goto fail;
		idents = tmp;
		/* copied: the next call clobbers the client rx buffer */
		strlcpy(idents[n], ident, sizeof(idents[n]));
		n++;
	}

	*out = idents;
	return (int)n;
fail:
	free(idents);
	return -1;
}

/*
 * Rows for every service matching `arg` (all when NULL), fetched over
 * D-Bus.  Returns the row count (caller frees *out), or -1 to fall
 * back to the legacy socket.
 */
static int dbus_fetch_svc_rows(char *arg, struct svc_row **out)
{
	char (*idents)[MAX_IDENT_LEN] = NULL;
	struct svc_row *rows = NULL;
	link_client_t *c;
	int n, i, m = 0;

	c = link_client_open(FINIT_BUS_SOCKET);
	if (!c)
		return -1;

	n = dbus_list_idents(c, &idents);
	if (n < 0)
		goto fail;

	rows = calloc(n ? n : 1, sizeof(*rows));
	if (!rows)
		goto fail;

	for (i = 0; i < n; i++) {
		struct svc_row *row = &rows[m];
		int rc;

		strlcpy(row->ident, idents[i], sizeof(row->ident));
		if (arg && arg[0] && !row_compare(row, arg))
			continue;

		rc = dbus_fill_row(c, row);
		if (rc < 0)
			goto fail;
		if (rc > 0)
			continue;	/* vanished, skip */
		m++;
	}

	free(idents);
	link_client_close(c);
	*out = rows;
	return m;
fail:
	free(idents);
	free(rows);
	link_client_close(c);
	return -1;
}

/* wire encoding is runlevel(8) style: digits, S, N */
static int runlevel_from_str(const char *s)
{
	if (!strcmp(s, "S"))
		return INIT_LEVEL;

	return atoi(s);
}

/*
 * All show_status() views over D-Bus, self-contained (the current
 * runlevel comes from Manager1, not the legacy socket).  Returns 0
 * with the command exit code in *retval, or -1 to fall back.
 */
static int dbus_show_status(char *arg, int *retval)
{
	static const char *const wanted[] = { "Runlevel", NULL };
	char curr[16] = "0";
	char *outv[] = { curr };
	struct svc_row *rows = NULL;
	char *filter;
	int n, i;

	n = dbus_fetch_svc_rows(arg, &rows);
	if (n < 0)
		return -1;

	*retval = 0;

	if (arg && arg[0]) {
		if (!n) {
			free(rows);
			/* exits, exactly like the legacy path */
			ERRX(noerr ? 0 : 69, "no such task or service(s): %s", arg);
		}
		if (n == 1) {
			if (quiet) {
				*retval = quiet_row(&rows[0]);
				free(rows);
				return 0;
			}
			/* runlevel feeds the detail view's Runlevels line */
			if (dbus_get_manager_props(wanted, outv, sizeof(curr)) < 0)
				goto fail;
			runlevel = runlevel_from_str(curr);
			if (json) {
				*retval = json_status_one(stdout, &rows[0], "", 0);
				puts("");
			} else
				*retval = show_one_row(&rows[0]);
			free(rows);
			return 0;
		}
		/* several matches: filtered table below */
	}

	if (dbus_get_manager_props(wanted, outv, sizeof(curr)) < 0)
		goto fail;
	runlevel = runlevel_from_str(curr);

	filter = (arg && arg[0]) ? arg : NULL;
	if (json) {
		int prev = 0;

		for (i = 0; i < n; i++) {
			if (filter && !row_compare(&rows[i], filter))
				continue;
			if (!prev)
				fputs("[\n", stdout);
			json_status_one(stdout, &rows[i], "  ", prev++);
		}
		if (prev)
			fputs("\n]\n", stdout);
	} else
		render_table(rows, n, filter);

	free(rows);
	return 0;
fail:
	free(rows);
	return -1;
}
#endif /* HAVE_DBUS */

static int show_status(char *arg)
{
	struct svc_row row;
	int num = 0;
	svc_t *svc;

#ifdef HAVE_DBUS
	{
		int rc;

		if (dbus_show_status(arg, &rc) == 0)
			return rc;
	}
#endif

	runlevel = runlevel_get(NULL);

	while (arg && arg[0]) {
		for (svc = client_svc_iterator(1); svc; svc = client_svc_iterator(0))
			num += svc_compare(svc, arg);

		if (num > 1)
			break;

		svc = client_svc_find(arg);
		if (!svc)
			ERRX(noerr ? 0 : 69, "no such task or service(s): %s", arg);

		fill_row_from_svc(&row, svc);
		if (quiet)
			return quiet_row(&row);

		if (json) {
			int rc;

			rc = json_status_one(stdout, &row, "", 0);
			puts("");
			return rc;
		}

		return show_one_row(&row);
	}

	if (json) {
		int prev = 0;

		for (svc = client_svc_iterator(1); svc; svc = client_svc_iterator(0)) {
			if (num && !svc_compare(svc, arg))
				continue;

			if (!prev)
				fputs("[\n", stdout);
			fill_row_from_svc(&row, svc);
			json_status_one(stdout, &row, "  ", prev++);
		}
		if (prev)
			fputs("\n]\n", stdout);

		return 0;
	}

	{
		struct svc_row *rows = NULL, *tmp;
		int n = 0;

		for (svc = client_svc_iterator(1); svc; svc = client_svc_iterator(0)) {
			tmp = realloc(rows, (n + 1) * sizeof(*rows));
			if (!tmp) {
				free(rows);
				return 1;
			}
			rows = tmp;
			fill_row_from_svc(&rows[n++], svc);
		}
		render_table(rows, n, num > 1 ? arg : NULL);
		free(rows);
	}

	return 0;
}

static void ident_line(const char *identity, char *arg)
{
	size_t len;
	char *pos;

	pos = strchr(identity, ':');
	if (pos)
		len = (size_t)(pos - identity);
	else
		len = strlen(identity);
	if (arg && arg[0] && strncasecmp(identity, arg, len))
		return;

	puts(identity);
}

static int show_ident(char *arg)
{
	svc_t *svc;

#ifdef HAVE_DBUS
	{
		char (*idents)[MAX_IDENT_LEN];
		link_client_t *c;
		int n = -1, i;

		c = link_client_open(FINIT_BUS_SOCKET);
		if (c) {
			n = dbus_list_idents(c, &idents);
			link_client_close(c);
		}
		if (n >= 0) {
			for (i = 0; i < n; i++)
				ident_line(idents[i], arg);
			free(idents);
			return 0;
		}
	}
#endif

	for (svc = client_svc_iterator(1); svc; svc = client_svc_iterator(0)) {
		char ident[MAX_IDENT_LEN];

		svc_ident(svc, ident, sizeof(ident));
		ident_line(ident, arg);
	}

	return 0;
}

static int transform(char *nm)
{
	char *names[] = {
		"reboot", "shutdown", "poweroff", "halt", "suspend",
		NULL
	};
	size_t i;

	for (i = 0; names[i]; i++) {
		if (!strcmp(nm, names[i]))
			return 1;
	}

	return 0;
}

static int has_conf(char *path, size_t len, char *name)
{
	paste(path, len, finit_rcsd, name);
	if (!fisdir(path)) {
		strlcpy(path, finit_rcsd, len);
		return 0;
	}

	return 1;
}

static int usage(int rc)
{
	int has_rcsd = fisdir(finit_rcsd);
	int has_ena;
	char avail[256];
	char ena[256];

	has_conf(avail, sizeof(avail), "available");
	has_ena = has_conf(ena, sizeof(ena), "enabled");

	fprintf(stderr,
		"Usage: %s [OPTIONS] [COMMAND]\n"
		"\n"
		"Options:\n"
		"  -b, --batch               Batch mode, no screen size probing\n"
		"  -c, --create              Create missing paths (and files) as needed\n"
		"  -f, --force               Ignore missing files and arguments, never prompt\n"
		"  -h, --help                This help text\n"
		"  -j, --json                JSON output in 'status' and 'cond' commands\n"
		"  -n, --noerr               Ignore error, e.g., already started/enabled/...\n"
		"  -1, --once                Only one lap in commands like 'top'\n"
		"  -p, --plain               Use plain table headings, no ctrl chars\n"
		"  -q, --quiet               Silent, only return status of command\n"
		"  -t, --no-heading          Skip table headings\n"
		"  -v, --verbose             Verbose output\n"
		"  -V, --version             Show program version\n"
		"\n"
		"Commands:\n"
		"  debug                     Toggle Finit (daemon) debug\n"
		"  help                      This help text\n"
		"  version                   Show program version\n"
		"\n", prognm);

	if (has_rcsd)
		fprintf(stderr,
			"  ls | list                 List all .conf in %s\n"
			"  create   <CONF>           Create   .conf in %s\n"
			"  delete   <CONF>           Delete   .conf in %s\n"
			"  show     <CONF>           Show     .conf in %s\n"
			"  edit     <CONF>           Edit     .conf in %s\n"
			"  touch    <CONF>           Change   .conf in %s\n",
			finit_rcsd, avail, avail, avail, avail, avail);
	else
		fprintf(stderr,
			"  show                      Show     %s\n", finit_conf);

	if (has_ena)
		fprintf(stderr,
			"  enable   <CONF>           Enable   .conf in %s\n", avail);
	if (has_ena)
		fprintf(stderr,
			"  disable  <CONF>           Disable  .conf in %s\n", ena);
	if (has_rcsd)
		fprintf(stderr,
			"  reload                    Reload  *.conf in %s (activate changes)\n", finit_rcsd);
	else
		fprintf(stderr,
			"  reload                    Reload   %s (activate changes)\n", finit_conf);

	fprintf(stderr,
		"\n"
		"  cond     set   <COND>     Set (assert) user-defined conditions     +usr/COND\n"
		"  cond     get   <COND>     Get status of user-defined condition, see $? and -v\n"
		"  cond     clear <COND>     Clear (deassert) user-defined conditions -usr/COND\n"
		"  cond     status           Show condition status, default cond command\n"
		"  cond     dump  [TYPE]     Dump all, or a type of, conditions and their status\n"
		"\n"
		"  log      [NAME]           Show ten last Finit, or NAME, messages from syslog\n"
		"  start    <NAME>[:ID]      Start service by name, with optional ID\n"
		"  stop     <NAME>[:ID]      Stop/Pause a running service by name\n"
		"  reload   <NAME>[:ID]      Reload service as if .conf changed (SIGHUP or restart)\n"
		"                            This allows restart of run/tasks that have already run\n"
		"                            Note: Finit .conf file(s) are *not* reloaded!\n"
		"  restart  <NAME>[:ID]      Restart (stop/start) service by name\n"
		"  kill     <NAME>[:ID] <S>  Send signal S to service by name, with optional ID\n"
#ifdef HAVE_DBUS
		"  monitor                   Stream D-Bus signals (service state, conditions) until ^C\n"
#endif
		"  ident    [NAME]           Show matching identities for NAME, or all\n"
		"  status   <NAME>[:ID]      Show service status, by name\n"
		"  status                    Show status of services, default command\n");
	if (cgrp)
		fprintf(stderr,
			"\n"
			"  cgroup                    List cgroup config overview\n"
			"  ps                        List processes based on cgroups\n"
			"  top                       Show top-like listing based on cgroups\n");
	fprintf(stderr,
		"\n"
		"  plugins                   List installed plugins\n"
		"\n"
		"  runlevel [0-9]            Show or set runlevel: 0 halt, 6 reboot\n"
		"  reboot                    Reboot system\n"
		"  halt                      Halt system\n"
		"  poweroff                  Halt and power off system\n"
		"  suspend                   Suspend system\n"
		"  switch-root ROOT [INIT]   Switch to new root filesystem (initramfs)\n");

	if (utmp)
		fprintf(stderr,
			"\n"
			"  utmp     show             Raw dump of UTMP/WTMP db\n");
	fprintf(stderr, "\n");

	return rc;
}

static int do_devel(char *arg)
{
	(void)arg;

	printf("Screen %dx%d\n", ttcols, ttrows);

	return 0;
}

static int do_help(char *arg)
{
	return usage(0);
}

static int cmd_cond(struct cmd *cmd)
{
	if (!cmd || !cmd->cond)
		return 1;

	return *cmd->cond;
}

static int cmd_parse(int argc, char *argv[], struct cmd *command)
{
	int i, j;

	for (i = 0; argc > 0 && command[i].cmd; i++) {
		if (!cmd_cond(&command[i]))
			continue;

		if (!string_compare(command[i].cmd, argv[0]))
			continue;

		if (command[i].ctx)
			return cmd_parse(argc - 1, &argv[1], command[i].ctx);

		if (command[i].cb_multiarg)
			return command[i].cb_multiarg(argc - 1, argv + 1);

		if (command[i].cb) {
			int rc = 0;

			if (argc == 1)
				return command[i].cb(NULL);

			for (j = 1; j < argc; j++)
				rc |= command[i].cb(argv[j]);

			return rc;
		}
	}

	if (argv[0] && strlen(argv[0]) > 0)
		ERRX(3, "No such command.  See 'initctl help' for an overview of available commands.");

	return command[0].cb(NULL); /* default cmd */
}

static void cleanup(void)
{
	if (finit_conf)
		free(finit_conf);
	if (finit_rcsd)
		free(finit_rcsd);
}

static void sourcerc(void)
{
	char *line;
	FILE *fp;

	fp = fopen(_PATH_VARRUN "finit/.initrc", "r");
	if (!fp)
		goto fallback;

	while ((line = fparseln(fp, NULL, NULL, NULL, 0))) {
		char *val;

		if ((val = fgetval(line, "FINIT_CONF", "="))) {
			if (finit_conf)
				free(finit_conf);
			finit_conf = val;
		}
		if ((val = fgetval(line, "FINIT_RCSD", "="))) {
			if (finit_rcsd)
				free(finit_rcsd);
			finit_rcsd = val;
		}

		free(line);
	}

fallback:
	if (!finit_conf)
		finit_conf = strdup(FINIT_CONF);
	if (!finit_rcsd)
		finit_rcsd = strdup(FINIT_RCSD);

	atexit(cleanup);
}

int main(int argc, char *argv[])
{
	struct option long_options[] = {
		{ "batch",      0, NULL, 'b' },
		{ "create",     0, NULL, 'c' },
		{ "debug",      0, NULL, 'd' },
		{ "force",      0, NULL, 'f' },
		{ "help",       0, NULL, 'h' },
		{ "json",       0, NULL, 'j' },
		{ "noerr",      0, NULL, 'n' },
		{ "once",       0, NULL, '1' },
		{ "plain",      0, NULL, 'p' },
		{ "quiet",      0, NULL, 'q' },
		{ "no-heading", 0, NULL, 't' },
		{ "verbose",    0, NULL, 'v' },
		{ "version",    0, NULL, 'V' },
		{ NULL, 0, NULL, 0 }
	};
	struct cmd cond[] = {
		{ "status",   NULL, do_cond_show, NULL, NULL }, /* default cmd */
		{ "dump",     NULL, do_cond_dump, NULL, NULL  },
		{ "set",      NULL, do_cond_set,  NULL, NULL  },
		{ "get",      NULL, do_cond_get,  NULL, NULL  },
		{ "clr",      NULL, do_cond_clr,  NULL, NULL  },
		{ "clear",    NULL, do_cond_clr,  NULL, NULL  },
		{ NULL, NULL, NULL, NULL, NULL  }
	};
	struct cmd command[] = {
		{ "status",   NULL, show_status,  NULL, NULL  }, /* default cmd */
		{ "ident",    NULL, show_ident,   NULL, NULL  },

		{ "debug",    NULL, toggle_debug, NULL, NULL  },
		{ "devel",    NULL, do_devel,     NULL, NULL  },
		{ "help",     NULL, do_help,      NULL, NULL  },
		{ "version",  NULL, show_version, NULL, NULL  },

		{ "list",     NULL, serv_list,    NULL, NULL  },
		{ "ls",       NULL, serv_list,    NULL, NULL  },
		{ "enable",   NULL, serv_enable,  NULL, NULL  },
		{ "disable",  NULL, serv_disable, NULL, NULL  },
		{ "touch",    NULL, serv_touch,   NULL, NULL  },
		{ "show",     NULL, serv_show,    NULL, NULL  },
		{ "cat",      NULL, serv_show,    NULL, NULL  }, /* alias */
		{ "edit",     NULL, serv_edit,    NULL, NULL  },
		{ "create",   NULL, serv_creat,   NULL, NULL  },
		{ "delete",   NULL, serv_delete,  NULL, NULL  },
		{ "reload",   NULL, do_reload,    NULL, NULL  },

		{ "cond",     cond, NULL, NULL, NULL          },

		{ "log",      NULL, show_log,     NULL, NULL  },
		{ "start",    NULL, do_start,     NULL, NULL  },
		{ "stop",     NULL, do_stop,      NULL, NULL  },
		{ "restart",  NULL, do_restart,   NULL, NULL  },
#ifdef HAVE_DBUS
		{ "monitor",  NULL, do_monitor,   NULL, NULL  },
#endif
		{ "signal",   NULL, NULL,         NULL, do_signal  },
		{ "kill",     NULL, NULL,         NULL, do_signal  }, /* alias */

		{ "cgroup",   NULL, show_cgroup, &cgrp, NULL  },
		{ "ps",       NULL, show_cgps,   &cgrp, NULL  },
		{ "top",      NULL, show_cgtop,  &cgrp, NULL  },

		{ "plugins",  NULL, plugins_list, NULL, NULL  },

		{ "runlevel", NULL, do_runlevel,  NULL, NULL  },
		{ "reboot",   NULL, do_reboot,    NULL, NULL  },
		{ "halt",     NULL, do_halt,      NULL, NULL  },
		{ "poweroff", NULL, do_poweroff,  NULL, NULL  },
		{ "suspend",  NULL, do_suspend,   NULL, NULL  },
		{ "switch-root", NULL, NULL,    NULL, do_switch_root },

		{ "utmp",     NULL, do_utmp,     &utmp, NULL  },
		{ NULL, NULL, NULL, NULL, NULL  }
	};
	int interactive = 1, c;

	if (transform(progname(argv[0])))
		return reboot_main(argc, argv);

	/* Enable functionality depending on system capabilities */
	sourcerc();
	cgrp = cgroup_avail();
	utmp = has_utmp();

	while ((c = getopt_long(argc, argv, "1bcdfh?jnpqtvV", long_options, NULL)) != EOF) {
		switch(c) {
		case '1':
			ionce = 1;
			break;

		case 'b':
			interactive = 0;
			break;

		case 'c':
			icreate = 1;
			break;

		case 'd':
			debug = 1;
			break;

		case 'f':
			iforce = 1;
			break;

		case 'h':
		case '?':
			return usage(0);

		case 'j':
			json = 1;
			break;

		case 'n':
			noerr = 1;
			break;

		case 'p':
			plain = 1;
			break;

		case 'q':
			quiet = 1;
			break;

		case 't':
			heading = 0;
			break;

		case 'v':
			verbose = 1;
			break;

		case 'V':
			return show_version(NULL);
		}
	}

	if (interactive)
		ttinit(0);

	return cmd_parse(argc - optind, &argv[optind], command);
}

void logit(int prio, const char *fmt, ...)
{
	va_list ap;

	if (quiet)
		return;

	va_start(ap, fmt);
	if (prio <= LOG_ERR)
		verrx(1, fmt, ap);
	else
		vwarnx(fmt, ap);
	va_end(ap);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
