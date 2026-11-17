/* reboot, halt, poweroff, shutdown, suspend for finit
 *
 * Copyright (c) 2009-2025  Joachim Wiberg <troglobit@gmail.com>
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

#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "finit.h"
#include "util.h"

typedef enum {
	CMD_UNKNOWN  = -1,
	CMD_REBOOT   = INIT_CMD_REBOOT,
	CMD_HALT     = INIT_CMD_HALT,
	CMD_POWEROFF = INIT_CMD_POWEROFF,
	CMD_SUSPEND  = INIT_CMD_SUSPEND,
} cmd_t;

static cmd_t cmd = CMD_UNKNOWN;
static char *msg = NULL;

/* initctl API */
extern int timeout;

extern int do_reboot  (char *arg);
extern int do_halt    (char *arg);
extern int do_poweroff(char *arg);
extern int do_suspend (char *arg);
extern int do_shutdown_at(int cmd, int sec, const char *msg);
extern int do_shutdown_cancel(void);


static void transform(char *nm)
{
	if (!nm)
		nm = prognm;

	if (cmd == CMD_UNKNOWN) {
		if (!strcmp(nm, "halt"))
			cmd = CMD_HALT;
		else if (!strcmp(nm, "poweroff") || !strcmp(nm, "shutdown"))
			cmd = CMD_POWEROFF;
		else if (!strcmp(nm, "suspend"))
			cmd = CMD_SUSPEND;
		else
			cmd = CMD_REBOOT;
	}

	switch (cmd) {
	case CMD_REBOOT:
		msg = "reboot";
		break;

	case CMD_HALT:
		msg = "halt";
		break;

	case CMD_POWEROFF:
		msg = "power-off";
		break;

	case CMD_SUSPEND:
		msg = "suspend";
		break;

	case CMD_UNKNOWN:
		cmd = CMD_REBOOT;
		msg = "reboot";
		break;
	}
}

/*
 * fallback in case of initctl API failure
 */
static void do_kill(int signo, char *msg)
{
	if (kill(1, signo))
		err(1, "Failed signalling init to %s", msg);
	do_sleep(5);
}

#define MAX_MIN (365 * 24 * 60)	/* Finit takes no more than a year */

/* now, +MIN, or HH:MM, as seconds from now, or -1 */
static int parse_time(const char *arg)
{
	struct tm tm;
	time_t t, at;
	int hh, mm;
	char *end;
	long min;
	char c;

	if (!strcmp(arg, "now"))
		return 0;

	if (arg[0] == '+') {
		min = strtol(&arg[1], &end, 10);
		if (end == &arg[1] || *end || min < 0 || min > MAX_MIN)
			return -1;
		return (int)min * 60;
	}

	if (sscanf(arg, "%d:%d%c", &hh, &mm, &c) != 2 || hh < 0 || hh > 23 || mm < 0 || mm > 59)
		return -1;

	/* Next time the clock shows HH:MM, today or tomorrow */
	t = time(NULL);
	localtime_r(&t, &tm);
	tm.tm_hour  = hh;
	tm.tm_min   = mm;
	tm.tm_sec   = 0;
	tm.tm_isdst = -1;
	at = mktime(&tm);
	if (at <= t) {
		tm.tm_mday++;
		tm.tm_isdst = -1;
		at = mktime(&tm);
	}

	return (int)(at - t);
}

static int schedule(int sec, const char *text)
{
	char tm[32];
	time_t at;

	if (do_shutdown_at(cmd, sec, text))
		errx(1, "Failed scheduling %s.", msg);

	if (sec > 0) {
		at = time(NULL) + sec;
		strftime(tm, sizeof(tm), "%a %Y-%m-%d %H:%M", localtime(&at));
		printf("Scheduled %s at %s, use 'shutdown -c' to cancel.\n", msg, tm);
	}

	return 0;
}

static int usage(int rc)
{
	int sd = !strcmp(prognm, "shutdown");

	fprintf(stderr, "Usage: %s [OPTIONS]%s\n\n"
		"Options:\n"
		"  -?, --help         This help text\n"
		"  -c                 Cancel a scheduled shutdown\n"
		"  -f, --force        Force unsafe %s now, do not contact the init system.\n"
		"      --halt         Halt system, regardless of how the command is called.\n"
		"  -h                 Halt or power off after shutdown.\n"
		"  -P, --poweroff     Power-off system, regardless of how the command is called.\n"
		"  -r, --reboot       Reboot system, regardless of how the command is called.\n"
		"  -t, --timeout=SEC  Force reboot/shutdown after a given timeout\n"
		"\n", prognm, sd ? " [TIME [MESSAGE]]" : "", msg);
	if (sd)
		fprintf(stderr, "TIME is now, +MIN, or HH:MM.  Logged-in users are sent MESSAGE as a\n"
			"warning, and from five minutes before, new logins are refused.\n\n");

	return rc;
}

int reboot_main(int argc, char *argv[])
{
	struct option long_options[] = {
		{"help",     0, NULL, '?'},
		{"force",    0, NULL, 'f'},
		{"halt",     0, NULL, 'H'},
		{"poweroff", 0, NULL, 'p'},
		{"reboot",   0, NULL, 'r'},
		{"timeout",  1, NULL, 't'},
		{NULL, 0, NULL, 0}
	};
	int c, force = 0, cancel = 0;
	int tmp;

	/* Initial command taken from program name */
	transform(prognm);

	while ((c = getopt_long(argc, argv, "h?cfHPprt:", long_options, NULL)) != EOF) {
		switch(c) {
		case '?':
			return usage(0);

		case 'c':
			cancel = 1;
			break;

		case 'f':
			force = 1;
			break;

		case 'H':
			cmd = CMD_HALT;
			break;

		case 'h':
		case 'P':
		case 'p':
			cmd = CMD_POWEROFF;
			break;

		case 'r':
			cmd = CMD_REBOOT;
			break;

		case 't':
			tmp = atoi(optarg);
			if (tmp < 1)
				errx(1, "Invalid forced timeout value.");
			timeout = tmp;
			break;

		default:
			return usage(1);
		}
	}

	/* Check for any overrides */
	transform(NULL);

	/* Check if we're in sulogin shell */
	if (getenv("SULOGIN"))
		force = 1;

	if (cancel)
		return do_shutdown_cancel();

	/* shutdown [opts] [TIME [MESSAGE]], see issue #149 */
	if (!strcmp(prognm, "shutdown") && optind < argc) {
		char text[256] = "";
		int sec, i;

		sec = parse_time(argv[optind]);
		if (sec < 0)
			errx(1, "Invalid time '%s', use now, +MIN, or HH:MM.", argv[optind]);

		for (i = optind + 1; i < argc; i++) {
			if (text[0])
				strlcat(text, " ", sizeof(text));
			strlcat(text, argv[i], sizeof(text));
		}

		if (sec > 0 || text[0]) {
			if (force)
				errx(1, "Cannot schedule a forced %s.", msg);
			return schedule(sec, text);
		}
	}

	if (force) {
		sync();

		switch (cmd) {
		case CMD_REBOOT:
			c = reboot(RB_AUTOBOOT);
			break;

		case CMD_HALT:
			c = reboot(RB_HALT_SYSTEM);
			break;

		case CMD_POWEROFF:
			c = reboot(RB_POWER_OFF);
			break;

		case CMD_SUSPEND:
			c = suspend();
			if (c && errno == EINVAL)
				errx(1, "Kernel does not support suspend to RAM.");
			break;

		case CMD_UNKNOWN:
			errx(1, "Invalid command");
			break;
		}

		if (c)
			err(1, "Failed forced %s", msg);

		return 0;
	}

	switch (cmd) {
	case CMD_REBOOT:
		if (do_reboot(NULL))
			do_kill(SIGTERM, msg);
		break;

	case CMD_HALT:
		if (do_halt(NULL))
			do_kill(SIGUSR2, msg);
		break;

	case CMD_POWEROFF:
		if (do_poweroff(NULL))
			do_kill(SIGUSR2, msg);
		break;

	case CMD_SUSPEND:
		/*
		 * Only initctl supports suspend, we avoid adding
		 * another signal to finit for compat reasons.
		 */
		do_suspend(NULL);
		break;


	case CMD_UNKNOWN:
		errx(1, "Invalid command");
		break;
	}

	return 0;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
