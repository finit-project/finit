/* Unified device manager - kernel events, device nodes, symlinks, conditions
 *
 * Copyright (c) 2021-2025  Joachim Wiberg <troglobit@gmail.com>
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

#include <errno.h>
#include <dirent.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <linux/types.h>
#include <linux/netlink.h>

#ifdef _LIBITE_LITE
# include <libite/lite.h>
#else
# include <lite/lite.h>
#endif

#include "keventd.h"
#include "cond.h"
#include "pid.h"
#include "util.h"

#define KEVENTD_VERSION "5.0"
#define _PATH_SYSFS_PWR "/sys/class/power_supply"

static int num_ac_online;
static int num_ac;

static int running = 1;
static int level;
static int logon;

int debug;			/* debug in other modules as well */

void logit(int prio, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (logon)
		vsyslog(prio, fmt, ap);
	else if (prio <= level) {
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
	}
	va_end(ap);
}
#define panic(fmt, args...) { logit(LOG_CRIT, fmt ":%s", ##args, strerror(errno)); exit(1); }
#define warn(fmt, args...)  { logit(LOG_WARNING, fmt ":%s", ##args, strerror(errno)); }

static void sys_cond(const char *cond, int set)
{
	char oneshot[256];

	snprintf(oneshot, sizeof(oneshot), "%s/%s", _PATH_CONDSYS, cond);
	if (set) {
		if (symlink(_PATH_RECONF, oneshot) && errno != EEXIST)
			warn("failed asserting sys/%s", cond);
	} else {
		if (erase(oneshot) && errno != ENOENT)
			warn("failed asserting sys/%s", cond);
	}
}

static int fgetline(char *path, char *buf, size_t len)
{
	FILE *fp;

	fp = fopen(path, "r");
	if (!fp)
		return -1;

	if (!fgets(buf, len, fp)) {
		fclose(fp);
		return -1;
	}

	chomp(buf);
	fclose(fp);

	return 0;
}

static int check_online(const char *online)
{
	int val;

	if (!online)
		return 0;

	val = atoi(online);
	logit(LOG_INFO, "AC %s", val ? "connected" : "disconnected");

	return val;
}

static int is_ac(const char *type)
{
	static const char *types[] = {
		"Mains",
		"USB",
		"BrickID",
		"Wireless",
		NULL
	};
	int i;

	for (i = 0; types[i]; i++) {
		if (!strncmp(type, types[i], strlen(types[i])))
			return 1;
	}

	return 0;
}

/*
 * Handle power_supply change events (original keventd functionality).
 */
static void power_supply_change(struct uevent *ev, char *buf, size_t len)
{
	int ac = 0;
	size_t i, hdrlen;

	/* Skip past header to key=value pairs */
	hdrlen = strlen(buf) + 1;
	if (ev->devpath)
		hdrlen += strlen(ev->devpath) + 1;

	for (i = hdrlen; i < len; ) {
		char *line = buf + i;

		if (!*line)
			break;

		if (!strncmp(line, "POWER_SUPPLY_TYPE=", 18)) {
			ac = is_ac(&line[18]);
		} else if (!strncmp(line, "POWER_SUPPLY_ONLINE=", 20) && ac) {
			if (check_online(&line[20])) {
				if (!num_ac_online)
					sys_cond("pwr/ac", 1);
				num_ac_online++;
			} else {
				if (num_ac_online > 0)
					num_ac_online--;
				if (!num_ac_online)
					sys_cond("pwr/ac", 0);
			}
		}

		i += strlen(line) + 1;
	}
}

/*
 * Handle a single uevent from the kernel.
 */
static void handle_uevent(char *buf, size_t len)
{
	struct uevent ev;

	if (uevent_parse(buf, len, &ev))
		return;

	logit(LOG_DEBUG, "uevent: %s@%s subsys=%s dev=%s major=%d minor=%d",
	      uevent_action_str(ev.action), ev.devpath ?: "",
	      ev.subsystem ?: "", ev.devname ?: "",
	      ev.major, ev.minor);

	switch (ev.action) {
	case ACT_ADD:
		/* Firmware loading takes priority */
		if (ev.firmware)
			firmware_load(&ev);

		/* Module loading */
		if (ev.modalias)
			modprobe_load(ev.modalias);

		/* Create device node if we have the info */
		if (ev.major >= 0 && ev.minor >= 0 && ev.devname)
			devnode_add(&ev);

		/* Create symlinks */
		symlink_add(&ev);
		break;

	case ACT_REMOVE:
		/* Remove symlinks first */
		symlink_del(&ev);

		/* Remove device node */
		if (ev.devname)
			devnode_del(&ev);
		break;

	case ACT_CHANGE:
		/* Handle power supply changes */
		if (ev.subsystem && !strcmp(ev.subsystem, "power_supply"))
			power_supply_change(&ev, buf, len);
		break;

	case ACT_BIND:
	case ACT_UNBIND:
		/* Driver bind/unbind - could trigger conditions */
		break;

	default:
		break;
	}
}

static void init_power_supply(void)
{
	struct dirent **d = NULL;
	char *cond_dirs[] = {
		_PATH_CONDSYS,
		_PATH_CONDSYS "/pwr",
	};
	char path[384];
	int i, n;

	for (i = 0; i < (int)NELEMS(cond_dirs); i++) {
		if (mkpath(cond_dirs[i], 0755) && errno != EEXIST) {
			warn("Failed creating %s condition directory, %s", COND_SYS,
			    cond_dirs[i]);
			return;
		}
	}

	n = scandir(_PATH_SYSFS_PWR, &d, NULL, alphasort);
	for (i = 0; i < n; i++) {
		char *nm = d[i]->d_name;
		char buf[10];

		snprintf(path, sizeof(path), "%s/%s/type", _PATH_SYSFS_PWR, nm);
		if (!fgetline(path, buf, sizeof(buf)) && is_ac(buf)) {
			num_ac++;

			snprintf(path, sizeof(path), "%s/%s/online", _PATH_SYSFS_PWR, nm);
			if (!fgetline(path, buf, sizeof(buf))) {
				if (check_online(buf))
					num_ac_online++;
			}
		}
		free(d[i]);
	}

	if (n > 0)
		free(d);

	/* if any power_supply is online, or none can be found */
	if (num_ac == 0 || num_ac_online > 0)
		sys_cond("pwr/ac", 1);
}

static void init_dev_condition_dir(void)
{
	char dir[256];

	/* Create /run/finit/cond/dev/ directory for device conditions */
	snprintf(dir, sizeof(dir), "%s", _PATH_CONDDEV);
	if (mkpath(dir, 0755) && errno != EEXIST)
		warn("Failed creating dev condition directory %s", dir);
}

static void set_logging(int prio)
{
	setlogmask(LOG_UPTO(prio));
	level = prio;
}

static void toggle_debug(int signo)
{
	(void)signo;

	debug ^= 1;
	set_logging(debug ? LOG_DEBUG : LOG_NOTICE);
}

static void shut_down(int signo)
{
	(void)signo;
	running = 0;
}

static int usage(int rc)
{
	fprintf(stderr,
		"Usage: keventd [-dhnv] [-c]\n"
		"\n"
		"Options:\n"
		"  -c        Run coldplug at startup\n"
		"  -d        Enable debug mode (foreground, verbose)\n"
		"  -h        Show this help text\n"
		"  -n        Run in foreground (no daemon)\n"
		"  -v        Show version\n"
		"\n");

	return rc;
}

/*
 * Unified device manager daemon.
 *
 * Started by Finit as soon as possible when base filesystem is up,
 * modules have been probed. Handles:
 *   - Device node creation/removal in /dev
 *   - Persistent symlinks in /dev/disk/by-*, /dev/input/by-*
 *   - Module loading via MODALIAS
 *   - Firmware loading via FIRMWARE
 *   - Power supply conditions (sys/pwr/ac)
 *   - Device conditions (dev/)
 */
int main(int argc, char *argv[])
{
	struct sockaddr_nl nls = { 0 };
	struct pollfd pfd;
	char buf[UEVENT_BUFFER_SIZE];
	int do_coldplug = 0;
	int foreground = 0;
	int c;

	while ((c = getopt(argc, argv, "cdhnv")) != -1) {
		switch (c) {
		case 'c':
			do_coldplug = 1;
			break;
		case 'd':
			debug = 1;
			foreground = 1;
			break;
		case 'h':
			return usage(0);
		case 'n':
			foreground = 1;
			break;
		case 'v':
			printf("keventd v%s\n", KEVENTD_VERSION);
			return 0;
		default:
			return usage(1);
		}
	}

	if (!foreground) {
		openlog("keventd", LOG_PID, LOG_DAEMON);
		set_logging(LOG_NOTICE);
		logon = 1;
	} else {
		set_logging(debug ? LOG_DEBUG : LOG_NOTICE);
	}

	signal(SIGUSR1, toggle_debug);
	signal(SIGTERM, shut_down);
	signal(SIGCHLD, SIG_IGN);	/* Don't wait for modprobe children */

	/* Initialize condition directories */
	init_power_supply();
	init_dev_condition_dir();

	/* Set up netlink socket for kernel uevents */
	pfd.events = POLLIN;
	pfd.fd = socket(PF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_KOBJECT_UEVENT);
	if (pfd.fd == -1)
		panic("failed creating netlink socket");

	nls.nl_family = AF_NETLINK;
	nls.nl_pid    = 0;
	nls.nl_groups = -1;	/* Subscribe to all multicast groups */
	if (bind(pfd.fd, (void *)&nls, sizeof(struct sockaddr_nl)))
		panic("bind failed");

	/* Increase receive buffer to reduce event loss */
	{
		int rcvbuf = 1024 * 1024;
		setsockopt(pfd.fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
	}

	/* Run coldplug if requested */
	if (do_coldplug)
		coldplug();

	logit(LOG_NOTICE, "keventd v%s started, waiting for events...", KEVENTD_VERSION);

	while (running) {
		int len;

		if (-1 == poll(&pfd, 1, -1)) {
			if (errno == EINTR)
				continue;
			break;
		}

		len = recv(pfd.fd, buf, sizeof(buf) - 1, MSG_DONTWAIT);
		if (len == -1) {
			switch (errno) {
			case EINTR:
				continue;
			case ENOBUFS:
				warn("lost events, buffer overflow");
				continue;
			default:
				panic("recv failed");
				continue;
			}
		}
		buf[len] = 0;

		/* Skip libudev events (start with "libudev") */
		if (!strncmp(buf, "libudev", 7))
			continue;

		handle_uevent(buf, len);
	}

	close(pfd.fd);
	logit(LOG_NOTICE, "keventd shutting down");

	return 0;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
