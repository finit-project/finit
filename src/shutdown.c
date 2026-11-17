/* Scheduled shutdown with wall messages and nologin, see issue #149
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

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <utmp.h>

#include "conf.h"
#include "finit.h"
#include "log.h"
#include "private.h"
#include "schedule.h"
#include "shutdown.h"
#include "sig.h"
#include "sm.h"
#include "util.h"
#include "utmp-api.h"

/* Minutes left at each warning, 0 is the deadline */
static const int warn_at[] = { 60, 30, 15, 10, 5, 4, 3, 2, 1, 0 };
#define NOLOGIN_MIN 5
#define MAX_WAIT    3600	/* sec, keeps the msec timer delay an int */
#define MAX_DELAY   (365 * 24 * 3600)

static struct {
	int       cmd;		/* INIT_CMD_REBOOT, _HALT, _POWEROFF, 0: none */
	long      when;		/* Deadline, jiffies() */
	int       next;		/* Minutes left at next warning */
	int       nologin;	/* We created FINIT_NOLOGIN_PATH */
	char      msg[256];
	struct wq work;
} sched;

static const char *action(int cmd)
{
	switch (cmd) {
	case INIT_CMD_REBOOT:
		return "reboot";
	case INIT_CMD_HALT:
		return "halt";
	default:
		return "power-off";
	}
}

/*
 * Write @text to the terminal of every logged-in user.  Done in a
 * child, reading utmp may wait for its lock and closing a serial
 * tty for its output to drain.
 */
static void wall(const char *text)
{
	char host[64] = "", tm[32], hdr[160];
	struct utmp *ut;
	time_t t;

	if (!has_utmp() || fork())
		return;

	t = time(NULL);
	gethostname(host, sizeof(host) - 1);
	strftime(tm, sizeof(tm), "%a %b %e %H:%M:%S %Y", localtime(&t));
	snprintf(hdr, sizeof(hdr), "\r\nBroadcast message from root@%s (%s):\r\n\r\n", host, tm);

	setutent();
	while ((ut = getutent())) {
		char tty[sizeof(ut->ut_line) + 6];
		int fd;

		if (ut->ut_type != USER_PROCESS || !ut->ut_line[0])
			continue;

		snprintf(tty, sizeof(tty), "/dev/%.*s", (int)sizeof(ut->ut_line), ut->ut_line);
		if (strstr(tty, ".."))
			continue;

		/* utmp is not ours alone to write, make sure it is a tty */
		fd = open(tty, O_WRONLY | O_NOCTTY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
		if (fd < 0)
			continue;
		if (isatty(fd) && write(fd, hdr, strlen(hdr)) > 0)
			(void)!write(fd, text, strlen(text));
		close(fd);
	}
	endutent();

	_exit(0);
}

static void announce(int min)
{
	char line[80], text[sizeof(sched.msg) + sizeof(line) + 8];

	if (min > 0)
		snprintf(line, sizeof(line), "The system is going DOWN for %s in %d minute%s!",
			 action(sched.cmd), min, min > 1 ? "s" : "");
	else
		snprintf(line, sizeof(line), "The system is going DOWN for %s NOW!", action(sched.cmd));

	logit(LOG_CONSOLE | LOG_NOTICE, "%s", line);
	snprintf(text, sizeof(text), "%s%s%s\r\n", sched.msg, sched.msg[0] ? "\r\n" : "", line);
	wall(text);
}

/* Never touch an admin's nologin, only create and remove our own */
static void nologin(void)
{
	FILE *fp;

	if (fexist(FINIT_NOLOGIN_PATH))
		return;

	fp = fopen(FINIT_NOLOGIN_PATH, "w");
	if (!fp) {
		dbg("Failed creating %s: %s", FINIT_NOLOGIN_PATH, strerror(errno));
		return;
	}
	fprintf(fp, "%s%sThe system is going down for %s.\n", sched.msg,
		sched.msg[0] ? "\n" : "", action(sched.cmd));
	fclose(fp);
	sched.nologin = 1;
}

static void tick(void *arg)
{
	long left, wait;
	size_t i;
	int min;

	if (!sched.cmd || IS_RESERVED_RUNLEVEL(runlevel))
		return;

	left = sched.when - jiffies();
	if (left <= 0) {
		announce(0);
		shutdown_now(sched.cmd, 0);
		return;
	}

	min = (left + 59) / 60;
	if (min <= NOLOGIN_MIN)
		nologin();
	if (min == sched.next)
		announce(min);

	for (i = 0; warn_at[i] >= min; i++)
		;
	sched.next = warn_at[i];

	wait = left - sched.next * 60;
	if (wait > MAX_WAIT)
		wait = MAX_WAIT;
	sched.work.delay = wait * 1000;
	schedule_work(&sched.work);
}

/*
 * Reboot, halt, or power off now, replacing any scheduled shutdown.
 * A @timeout in seconds arms the emergency shutdown bypass, 0: none.
 */
int shutdown_now(int cmd, int timeout)
{
	switch (cmd) {
	case INIT_CMD_REBOOT:
		halt = SHUT_REBOOT;
		break;
	case INIT_CMD_HALT:
		halt = SHUT_HALT;
		break;
	case INIT_CMD_POWEROFF:
		halt = SHUT_OFF;
		break;
	default:
		return 1;
	}

	if (sched.cmd) {
		sched.cmd = 0;
		uev_timer_stop(&sched.work.watcher);
	}

	shutdown_bypass(timeout);
	dbg("%s", action(cmd));
	sm_runlevel(cmd == INIT_CMD_REBOOT ? 6 : 0);

	return 0;
}

/* Replaces any already scheduled shutdown */
int shutdown_schedule(int cmd, int sec, const char *msg)
{
	if (cmd != INIT_CMD_REBOOT && cmd != INIT_CMD_HALT && cmd != INIT_CMD_POWEROFF)
		return 1;
	if (sec < 0 || sec > MAX_DELAY)
		return 1;

	/* Our nologin belongs to the shutdown being replaced */
	if (sched.nologin) {
		erase(FINIT_NOLOGIN_PATH);
		sched.nologin = 0;
	}

	sched.cmd  = cmd;
	sched.when = jiffies() + sec;
	sched.next = (sec + 59) / 60;	/* First tick warns */
	strlcpy(sched.msg, msg ? msg : "", sizeof(sched.msg));

	/* First tick right away, a zero delay would disarm the timer */
	sched.work.cb    = tick;
	sched.work.delay = 1;

	return schedule_work(&sched.work);
}

int shutdown_cancel(void)
{
	if (!sched.cmd)
		return 1;

	sched.cmd = 0;
	uev_timer_stop(&sched.work.watcher);

	if (sched.nologin) {
		erase(FINIT_NOLOGIN_PATH);
		sched.nologin = 0;
	}

	logit(LOG_CONSOLE | LOG_NOTICE, "The system shutdown has been cancelled.");
	wall("The system shutdown has been cancelled.\r\n");

	return 0;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
