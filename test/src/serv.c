/*
 * Basic UNIX daemon
 *
 * Options to run in foreground and to create a PID file.  When running
 * in foregrund it does not create a PID file by default.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sysexits.h>
#include <sys/socket.h>
#include <sys/stat.h>
#ifdef HAVE_LIBSYSTEMD
#include "sd-daemon.h"
#endif

#define PROGNM "serv"

#define err(rc, fmt, args...)  do {fprintf(stderr, "%s: " fmt ": %s\n", ident, ##args, strerror(errno)); exit(rc);} while(0)
#define errx(rc, fmt, args...) do {fprintf(stderr, "%s: " fmt "\n", ident, ##args); exit(rc);} while(0)
#define inf(fmt, args...)      do {fprintf(stderr, "%s: " fmt "\n", ident, ##args);} while(0)

volatile sig_atomic_t reloading = 1;
volatile sig_atomic_t running   = 1;
static char *ident = PROGNM;
static char fn[80];

static void verify_env(char *arg)
{
	char *key, *value;
	char *replica;
	char *env;

	key = replica = strdupa(arg);
	if (!replica)
		err(1, "Failed duplicating arg %s", arg);

	value = strchr(replica, ':');
	if (!value)
		errx(1, "Invalid format of KEY:VALUE arg, missing ':' in %s", replica);
	*(value++) = 0;

	env = getenv(key);
	if (!env)
		errx(1, "No '%s' in environment", key);

	if (strcmp(env, value))
		errx(1, "Mismatch, environment '%s' vs expected value '%s'", env, value);
}

static void verify_noenv(char *key)
{
	char *val;

	val = getenv(key);
	if (val)
		errx(1, "Error, key %s is set in environment to '%s'", key, val);
}

static void inc_restarts(void)
{
	char buf[10];
	int cnt = 0;
	FILE *fp;

	fp = fopen("/tmp/serv-restart.cnt", "r+");
	if (!fp) {
		fp = fopen("/tmp/serv-restart.cnt", "w");
		if (!fp)
			err(1, "failed creating restart counter file");
	} else {
		if (fgets(buf, sizeof(buf), fp))
			cnt = atoi(buf);
	}
	cnt++;

	fseek(fp, SEEK_SET, 0);
	fprintf(fp, "%d", cnt);
	fclose(fp);
}

static void cleanup(void)
{
	remove(fn);
}

static void sig(int signo)
{
	inf("Got signal %d ...", signo);

	switch (signo) {
	case SIGHUP:
		reloading = 1;
		break;

	case SIGTERM:
		running = 0;
		break;
	}
}

static void writefn(char *fn, int val)
{
	FILE *fp;

	fp = fopen(fn, "w");
	if (!fp)
		err(1, "failed creating file %s", fn);
	fprintf(fp, "%d\n", val);
	fclose(fp);
}

static int checkfn(char *fn)
{
	return !access(fn, R_OK);
}

static void mine(char *fn)
{
	inf("Mining for spice in %s", fn);
	writefn(fn, 4711);
}

static void pidfile(char *pidfn)
{
	if (!pidfn) {
		if (fn[0] == 0)
			snprintf(fn, sizeof(fn), "%s%s.pid", _PATH_VARRUN, ident);
		pidfn = fn;
	}

	if (!checkfn(pidfn)) {
		pid_t pid;

		pid = getpid();
		inf("Creating PID file %s with %d", pidfn, pid);
		writefn(pidfn, pid);
		atexit(cleanup);
	} else {
		inf("Touching PID file %s", pidfn);
		utimensat(0, fn, NULL, 0);
	}
}

static int capabilities(void)
{
#ifdef HAVE_LIBSYSTEMD
	puts("libsystemd");
#endif
	puts("s6");

	return 0;
}

static int usage(int rc)
{
	FILE *fp = rc ? stderr : stdout;

	fprintf(fp,
		"%s [-nhp] [-P FILE]\n"
		"\n"
		" -C       Show capabilities and exit\n"
		" -c       Crash (exit) immediately\n"
		" -e K:V   Verify K environment variable is V value\n"
		" -E K     Verify K is not set in the environment\n"
		" -f FILE  Container file to keep the Melange in\n"
		" -F FILE  Where to look spice ...\n"
		" -h       Show help text (this)\n"
		" -i IDENT Change process identity, incl. logs, pidfile, etc.\n"
		" -n       Run in foreground\n"
		" -N SOCK  Send '\\n' on SOCK (integer), for s6 readiness\n"
		" -p       Create PID file despite running in foreground\n"
		" -P FILE  Create PID file using FILE\n"
		" -r SVC   Call initctl to restart service SVC (self)\n"
		"\n"
		"By default this program daemonizes itself to the background, and,\n"
		"when it's done setting up its signal handler(s), creates a PID file\n"
		"to let the rest of the system know it's done.  When the program runs\n"
		"in the foreground it does not create a PID file by default.\n"
		"\n"
		"When acting as a systemd daemon, this program expects NOTIFY_SOCKET\n"
		"\n"
		"Regardless of how This daemon is started it provides a single service\n"
		"to others, spice ... guarded by sandworms.\n",
		ident);

	return rc;
}

int main(int argc, char *argv[])
{
	int do_background = 1;
	int notify_s6 = 0;
	int do_pidfile = 1;
	int do_restart = 0;
	int do_notify = 0;
	int do_crash = 0;
	int vanish = 0;
	char *pidfn = NULL;
	char *melange = NULL;
	char *spice = NULL;
	char cmd[80];
	int c;

	while ((c = getopt(argc, argv, "cCe:E:f:F:hi:nN:pP:r:")) != EOF) {
		switch (c) {
		case 'c':
			do_crash = 1;
			break;
		case 'C':
			return capabilities();
		case 'e':
			verify_env(optarg);
			break;
		case 'E':
			verify_noenv(optarg);
			break;
		case 'f':
			melange = optarg;
			break;
		case 'F':
			spice = optarg;
			break;
		case 'h':
			return usage(0);
		case 'i':
			ident = optarg;
			break;
		case 'n':
			do_background = 0;
			do_pidfile--;
			break;
		case 'N':
			do_notify = atoi(optarg);
			notify_s6 = 1;
			break;
		case 'p':
			do_pidfile++;
			break;
		case 'P':
			pidfn = optarg;
			do_pidfile++;
			break;
		case 'r':
			snprintf(cmd, sizeof(cmd), "initctl restart %s", optarg);
			do_restart = 1;
			break;
		default:
			return usage(1);
		}
	}

	/* Daemonize, fork to background etc. */
	if (do_background) {
		if (daemon(0, 1))
			return 1;
	}

	/* Signal handlers first *then* PID file */
	signal(SIGTERM, sig);
	signal(SIGHUP, sig);

	/* This is our only service to the world */
	if (melange)
		mine(melange);

	/* Tell world where we are, but not if bg w/o pid file */
	if (do_pidfile > 0)
		pidfile(pidfn);

	if (!do_notify && getenv("NOTIFY_SOCKET"))
		do_notify = 1;

	if (do_notify)
		inf("Will notify %s ...", notify_s6 ? "s6" : "systemd");
	else
		inf("No notify socket ...");

	if (do_crash) {
		inf("Simulating crash, exiting with code %d", EX_SOFTWARE);
		exit(EX_SOFTWARE);
	}

	inf("Entering while(1) loop");
	while (running) {
		if (spice) {
			inf("Checking for spice in %s ...", spice);
			if (!checkfn(spice))
				err(1, "Melange");
		}

		if (reloading) {
			if (do_notify > 0) {
				/* Issue #343: see notify.sh test for more details */
				inf("Delaying notify by 3 seconds for notify.sh ...");
				sleep(3);

				if (notify_s6) {
					inf("Notifying Finit on socket %d", do_notify);
					if (write(do_notify, "\n", 1) < 1)
						err(1, "Failed sending ready notification to Finit");
					inf("s6 notify, closing socket %d ...", do_notify);
					if (close(do_notify))
						err(1, "Failed closing notify socket");
					do_notify = 0;
				} else {
#ifdef HAVE_LIBSYSTEMD
					int rc;

					inf("Notifying Finit on NOTIFY_SOCKET");
					rc = sd_notify(0, "READY=1");
					inf("sd_notify () => %d", rc);
#else
					inf("Skipping systemd notify - built without libsystemd support");
#endif
				}
			}

			if (melange) {
				mine(melange);
				vanish = -2;
			}

			if (do_pidfile > 0)
				pidfile(NULL);
			reloading = 0;
		}

		sleep(1);
		if (do_restart) {
			inc_restarts();
			if (system(cmd))
				return 1;
			break;
		}

		if (melange && vanish++ > 0) {
			if (checkfn(melange)) {
				inf("Oh no, sandworms! Harvest interrupted ...");
				remove(melange);
			}
		}
	}

	inf("Leaving ...");
	return 0;
}
