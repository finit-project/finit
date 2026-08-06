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

static int toggle_debug(char *arg)
{
	struct init_request rq = {
		.magic = INIT_MAGIC,
		.cmd = INIT_CMD_DEBUG,
	};

	return client_send(&rq, sizeof(rq));
}

static int do_log(svc_t *svc, char *tail)
{
	const char *logfile = "/var/log/syslog";
	pid_t pid;
	char *nm;

	if (svc) {
		nm = svc_ident(svc, NULL, 0);
		pid = svc->pid;
		if (!pid)
			return 0; /* not running */
	} else {
		nm  = "finit";
		pid = 1;
	}

	if (!fexist(logfile)) {
		logfile = "/var/log/messages";
		if (!fexist(logfile))
			return 0; /* bail out, maybe in container */
	}

	return systemf("cat %s | grep '\\[%d\\]\\|%s' %s", logfile, pid, nm, tail);
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

static int do_start  (char *arg) { return do_startstop(INIT_CMD_START_SVC,   arg); }
static int do_stop   (char *arg) { return do_startstop(INIT_CMD_STOP_SVC,    arg); }

static int do_reload (char *arg)
{
	if (!arg || !arg[0])
		return do_svc(INIT_CMD_RELOAD, NULL);

	return do_startstop(INIT_CMD_RELOAD_SVC, arg);
}

static int do_restart(char *arg)
{
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

	strlcpy(rq.data, argv[0], sizeof(rq.data));
	if (client_send(&rq, sizeof(rq)))
		ERRX(noerr ? 0 : 69, "no such task or service(s): %s", argv[0]);

	signo = str2sig(argv[1]);
	if (signo == -1) {
		const char *errstr = NULL;

		signo = (int)strtonum(argv[1], 1, 31, &errstr);
		if (errstr)
			ERRX(65, "%s signal: %s", errstr, argv[1]);
	}

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

typedef enum { COND_CLR, COND_SET, COND_GET } condop_t;

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

	return 0;
}

static int do_cond_get(char *arg) { return do_cond_act(arg, COND_GET); }
static int do_cond_set(char *arg) { return do_cond_act(arg, COND_SET); }
static int do_cond_clr(char *arg) { return do_cond_act(arg, COND_CLR); }

static char *svc_cond(svc_t *svc, char *buf, size_t len, int ansi)
{
	char *cond, *conds;

	buf[0] = 0;

	if (!svc->cond[0])
		return buf;

	conds = strdupa(svc->cond);
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

int do_reboot  (char *arg) { return do_cmd(INIT_CMD_REBOOT);   }
int do_halt    (char *arg) { return do_cmd(INIT_CMD_HALT);     }
int do_poweroff(char *arg) { return do_cmd(INIT_CMD_POWEROFF); }
int do_suspend (char *arg) { return do_cmd(INIT_CMD_SUSPEND);  }

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

	/* NACK is the only real failure case here, ACK/lost connection means success */
	if (client_send(&rq, sizeof(rq)) && rq.cmd == INIT_CMD_NACK) {
		puts(rq.data);
		return 1;
	}

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

static int missing(svc_t *svc)
{
	if (svc->state == SVC_HALTED_STATE && svc_is_missing(svc))
		return 1;

	return 0;
}

static char *svc_command(svc_t *svc, char *buf, size_t len, int ansi)
{
	int bold = missing(svc) && ansi;

	if (whichp(svc->cmd))
		bold = 0;

	strlcpy(buf, bold ? "\e[1m" : "", len);
	strlcat(buf, svc->cmd, len);

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

	strlcat(buf, bold ? "\e[0m" : "", len);

	return buf;
}

static char *svc_environ(svc_t *svc, char *buf, size_t len, int ansi)
{
	int bold = missing(svc);

	if (!ansi || svc_checkenv(svc))
		bold = 0;

	strlcpy(buf, bold ? "\e[1m" : "", len);
	strlcat(buf, svc->env, len);
	strlcat(buf, bold ? "\e[0m" : "", len);

	return buf;
}

static char *exit_status(svc_t *svc, char *buf, size_t len)
{
	int rc, sig;
	char *str;

	rc = WEXITSTATUS(svc->status);
	sig = WTERMSIG(svc->status);

	if (WIFEXITED(svc->status)) {
		str = code2str(rc);
		snprintf(buf, len, " (code=exited, status=%d%s%s%s)", rc,
			 str[0] ? "/" : "", str,
			 svc->manual ? ", manual=yes" : "");
	}
	else if (WIFSIGNALED(svc->status)) {
		str = sig2str(sig);
		snprintf(buf, len, " (code=signal, status=%d%s%s)", sig, str[0] ? "/" : "", str);
	}

	return buf;
}

static char *status(svc_t *svc, int full)
{
	static char buf[96];
	const char *color;
	char ok[48] = {0};
	char *s;

	s = svc_status(svc);
	switch (svc->state) {
	case SVC_HALTED_STATE:
		exit_status(svc, ok, sizeof(ok));
		color = "\e[1m";
		break;

	case SVC_RUNNING_STATE:
		color = "\e[1;32m";
		break;

	case SVC_DONE_STATE:
		exit_status(svc, ok, sizeof(ok));
		if (WIFEXITED(svc->status)) {
			if (WEXITSTATUS(svc->status))
				color = "\e[1;31m";
			else
				color = "\e[1;32m";
		} else {
			if (full && WIFSIGNALED(svc->status))
				color = "\e[1;31m";
			else
				color = "\e[1;33m";
		}
		break;

	default:
		exit_status(svc, ok, sizeof(ok));
		color = "\e[1;33m";
		break;
	}

	if (!full || plain)
		color = NULL;

	if (!full)
		snprintf(buf, sizeof(buf), "%-8.8s", s);
	else
		snprintf(buf, sizeof(buf), "%s%s%s%s",
			 color ? color : "", s, ok, color ? "\e[0m" : "");

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

static int json_status_one(FILE *fp, svc_t *svc, char *indent, int prev)
{
	long now = jiffies();
	char *pidfn = NULL;
	char buf[512];

	pidfn = svc->pidfile;
	if (pidfn[0] == '!')
		pidfn++;
	else if (pidfn[0] == 0)
		pidfn = "none";

	fprintf(fp,
		"%s"
		"%s{\n"
		"%s  \"identity\": \"%s\",\n",
		prev ? ",\n" : indent, prev ? indent : "",
		indent, svc_ident(svc, NULL, 0));
	fprintf(fp,
		"%s  \"description\": \"%s\",\n",
		indent, json_escape(svc->desc));
	fprintf(fp,
		"%s  \"type\": \"%s\",\n"
		"%s  \"forking\": %s,\n"
		"%s  \"status\": \"%s\",\n",
		indent, svc_typestr(svc),
		indent, svc->forking ? "true" : "false",
		indent, svc_status(svc));

	if (svc->state != SVC_RUNNING_STATE) {
		int rc, sig;

		rc = WEXITSTATUS(svc->status);
		sig = WTERMSIG(svc->status);

		if (WIFEXITED(svc->status))
			fprintf(fp,
				"%s  \"exit\": { \"%s\": %d },\n",
				indent, "code", rc);
		else if (WIFSIGNALED(svc->status))
			fprintf(fp,
				"%s  \"exit\": { \"%s\": %d },\n",
				indent, "signal", sig);
	}

	fprintf(fp,
		"%s  \"origin\": \"%s\",\n",
		indent, svc->file[0] ? svc->file : "built-in");
	svc_command(svc, buf, sizeof(buf), 0);
	fprintf(fp,
		"%s  \"command\": \"%s\",\n",
		indent, json_escape(buf));

	svc_environ(svc, buf, sizeof(buf), 0);
	if (buf[0])
		fprintf(fp,
			"%s  \"environment\": \"%s\",\n", indent, json_escape(buf));

	svc_cond(svc, buf, sizeof(buf), 0);
	if (buf[0])
		fprintf(fp,
			"%s  \"condition\": %s,\n", indent, buf);

	if (svc->manual)
		fprintf(fp,
			"%s  \"starts\": %d,\n", indent, svc->once);

	fprintf(fp,
		"%s  \"restarts\": %d,\n", indent, svc->restart_tot); /* XXX: add restart_cnt and restart_max */

	/* Add memory and CPU information if cgroup support is available */
	if (cgrp && svc->pid > 1) {
		char *group = pid_cgroup(svc->pid);

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
		"%s  \"pid\": %d,\n"
		"%s  \"user\": \"%s\",\n"
		"%s  \"group\": \"%s\",\n"
		"%s  \"uptime\": %ld,\n"
		"%s  \"runlevels\": %s\n"
		"%s}",
		indent, pidfn,
		indent, svc->pid,
		indent, svc->username,
		indent, svc->group,
		indent, svc->pid ? now - svc->start_time : 0,
		indent, runlevel_arr(svc->runlevels),
		indent);

	return 0;
}

static int show_status(char *arg)
{
	char ident[MAX_IDENT_LEN];
	char buf[512];
	int num = 0;
	svc_t *svc;

	runlevel = runlevel_get(NULL);

	while (arg && arg[0]) {
		long now = jiffies();
		char uptm[42] = "N/A";
		char *pidfn = NULL;

		for (svc = client_svc_iterator(1); svc; svc = client_svc_iterator(0))
			num += svc_compare(svc, arg);

		if (num > 1)
			break;

		svc = client_svc_find(arg);
		if (!svc)
			ERRX(noerr ? 0 : 69, "no such task or service(s): %s", arg);

		if (quiet) {
			if (svc_is_runtask(svc)) {
				if (svc->started)
					return 0;
				return 1;
			}
			return svc->state != SVC_RUNNING_STATE;
		}

		if (json) {
			int rc;

			rc = json_status_one(stdout, svc, "", 0);
			puts("");
			return rc;
		}

		pidfn = svc->pidfile;
		if (pidfn[0] == '!')
			pidfn++;
		else if (pidfn[0] == 0)
			pidfn = "none";

		printf("     Status : %s\n", status(svc, 1));
		printf("   Identity : %s\n", svc_ident(svc, ident, sizeof(ident)));
		printf("Description : %s\n", svc->desc);
		printf("     Origin : %s\n", svc->file[0] ? svc->file : "built-in");
		svc_environ(svc, buf, sizeof(buf), !plain);
		if (buf[0])
			printf("Environment : %s\n", buf);
		svc_cond(svc, buf, sizeof(buf), !plain);
		if (buf[0])
			printf("Condition(s): <%s>\n", buf);
		printf("    Command : %s\n", svc_command(svc, buf, sizeof(buf), !plain));
		printf("   PID file : %s\n", pidfn);
		printf("        PID : %d\n", svc->pid);
		printf("       User : %s\n", svc->username);
		printf("      Group : %s\n", svc->group);
		printf("     Uptime : %s\n", svc->pid ? uptime(now - svc->start_time, uptm, sizeof(uptm)) : uptm);
		if (svc->manual)
			printf("     Starts : %d\n", svc->once);
		printf("   Restarts : %d (%d/%d)\n", svc->restart_tot, svc->restart_cnt, svc->restart_max);
		printf("  Runlevels : %s\n", runlevel_string(runlevel, svc->runlevels));

		if (cgrp && svc->pid > 1) {
			const struct cg *cg;
			uint64_t throttled_usec = 0;
			uint64_t nr_throttled = 0;
			char path[256];
			char *group;

			group = pid_cgroup(svc->pid);
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

		return do_log(svc, "| tail -10");
	}

	if (json) {
		int prev = 0;

		for (svc = client_svc_iterator(1); svc; svc = client_svc_iterator(0)) {
			svc_ident(svc, ident, sizeof(ident));
			if (num && !svc_compare(svc, arg))
				continue;

			if (!prev)
				fputs("[\n", stdout);
			json_status_one(stdout, svc, "  ", prev++);
		}
		if (prev)
			fputs("\n]\n", stdout);

		return 0;
	}

	col_widths();
	if (heading) {
		char title[80];

		snprintf(title, sizeof(title), "%-*s  %-*s  %-8s %-13s ",
			 pw, "PID", iw, "IDENT", "STATUS", "RUNLEVELS");
		if (!verbose)
			strlcat(title, "DESCRIPTION", sizeof(title));
		else
			strlcat(title, "COMMAND", sizeof(title));

		print_header("%s", title);
	}

	for (svc = client_svc_iterator(1); svc; svc = client_svc_iterator(0)) {
		char *lvls;

		svc_ident(svc, ident, sizeof(ident));
		if (num && !svc_compare(svc, arg))
			continue;

		printf("%-*d  ", pw, svc->pid);
		printf("%-*s  %s ", iw, ident, status(svc, 0));

		lvls = runlevel_string(runlevel, svc->runlevels);
		if (strchr(lvls, '\e'))
			printf("%-21.21s ", lvls);
		else
			printf("%-13.13s ", lvls);

		if (!verbose)
			puts(svc->desc);
		else
			puts(svc_command(svc, buf, sizeof(buf), !plain));
	}

	return 0;
}

static int show_ident(char *arg)
{
	svc_t *svc;

	for (svc = client_svc_iterator(1); svc; svc = client_svc_iterator(0)) {
		char ident[MAX_IDENT_LEN];
		size_t len;
		char *pos;

		svc_ident(svc, ident, sizeof(ident));
		pos = strchr(ident, ':');
		if (pos)
			len = pos - ident;
		else
			len = strlen(ident);
		if (arg && arg[0] && strncasecmp(ident, arg, len))
			continue;

		puts(ident);
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
