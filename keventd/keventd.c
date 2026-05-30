/* Unified device manager - kernel events, device nodes, symlinks, conditions
 *
 * TODO / known limitations
 *   - firmware_load() copies synchronously in the main event loop; a
 *     multi-MB blob (e.g. iwlwifi) blocks all other event handling for
 *     the duration.  Worker pool / fork-per-event would unblock this
 *     (see .notes/keventd-eudev-gap-analysis.md, gap #8).
 *   - firmware_load() does not handle compressed firmware (.xz, .zst).
 *     Modern linux-firmware ships .xz blobs; kernels with
 *     CONFIG_FW_LOADER_COMPRESS decompress in-kernel via direct
 *     loading, but the legacy /sys/.../loading path used here passes
 *     raw bytes only.  Adding liblzma/libzstd would close this gap for
 *     drivers using the userhelper fallback on systems without
 *     CONFIG_FW_LOADER_COMPRESS.
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

#include <ctype.h>
#include <errno.h>
#include <dirent.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <linux/types.h>
#include <linux/netlink.h>

#ifdef _LIBITE_LITE
# include <libite/lite.h>
#else
# include <lite/lite.h>
#endif

#include <uev/uev.h>

#include "keventd.h"
#include "rules.h"
#include "udevdb.h"
#include "cond.h"
#include "pid.h"
#include "util.h"

#define KEVENTD_VERSION "5.0"
#define _PATH_SYSFS_PWR "/sys/class/power_supply"

/* Default netlink group for uevent rebroadcast (libudev-zero convention) */
#define REBC_DEFAULT_NLGROUP 4

static int num_ac_online;
static int num_ac;

static int level;
static int logon;
static int passive;		/* power-supply only, no device management */

static struct rule_list rules = TAILQ_HEAD_INITIALIZER(rules);
static char *rules_dir;			/* extra rules dir from -r option */

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

/*
 * Netlink rebroadcast support.
 *
 * The Linux kernel sends uevents to netlink multicast group 1 (bit 0)
 * of NETLINK_KOBJECT_UEVENT.  Only the device manager should listen on
 * this raw kernel group.  Userspace consumers (e.g., applications using
 * libudev) expect to receive processed events on a separate group --
 * conventionally group 4 (bit 2), established by systemd/udevd.
 *
 * libudev-zero (https://github.com/illiliti/libudev-zero), a daemonless
 * replacement for libudev, listens on group 0x4 for these rebroadcast
 * events.  Without rebroadcast, graphical applications, Wayland/X11
 * compositors, libinput, and anything else using libudev to monitor
 * device hotplug will never see any events.
 *
 * Rebroadcast is enabled by default to group 0x4.  Use -g to override
 * the group mask, or -G to disable rebroadcast entirely.  Bit 0 is
 * always masked out to prevent a feedback loop with the kernel group.
 */
static int          rebc_fd = -1;
static unsigned int rebc_nlgroups;

static void rebc_init(unsigned int nlgroups)
{
	/* Mask out bit 0 (kernel group) to prevent feedback loop */
	if (nlgroups & 1) {
		logit(LOG_WARNING, "rebroadcast group mask 0x%x includes kernel group (bit 0), masking it out", nlgroups);
		nlgroups &= ~1U;
	}
	if (!nlgroups) {
		logit(LOG_WARNING, "no valid rebroadcast groups remaining, rebroadcast disabled");
		return;
	}

	rebc_fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_KOBJECT_UEVENT);
	if (rebc_fd == -1) {
		warn("failed creating rebroadcast socket");
		return;
	}

	rebc_nlgroups = nlgroups;
	logit(LOG_NOTICE, "rebroadcasting uevents to netlink group(s) 0x%x", nlgroups);
}

static void rebc_event(char *buf, size_t len)
{
	struct sockaddr_nl sa = { 0 };
	struct msghdr hdr = { 0 };
	struct iovec iov;

	if (rebc_fd == -1)
		return;

	iov.iov_base = buf;
	iov.iov_len  = len;

	sa.nl_family = AF_NETLINK;
	sa.nl_groups = rebc_nlgroups;

	hdr.msg_name    = &sa;
	hdr.msg_namelen = sizeof(sa);
	hdr.msg_iov     = &iov;
	hdr.msg_iovlen  = 1;

	if (sendmsg(rebc_fd, &hdr, 0) == -1)
		logit(LOG_DEBUG, "rebroadcast failed: %s", strerror(errno));
}

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

static int fgetline(const char *path, char *buf, size_t len)
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
static void power_supply_change(const struct uevent *ev, char *buf, size_t len)
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
 * True if rules have queued the kmod builtin for this event.  Used to
 * suppress the direct modprobe path when 80-drivers.rules will fork
 * modprobe anyway -- otherwise coldplug runs modprobe twice per event.
 */
static int applied_has_kmod(const struct uevent *ev)
{
	int i;

	for (i = 0; i < ev->applied.nruncmds; i++) {
		const char *cmd = ev->applied.run_cmds[i];

		if (ev->applied.run_types[i] != RUN_BUILTIN)
			continue;
		if (!strncmp(cmd, "kmod", 4) &&
		    (cmd[4] == '\0' || isspace((unsigned char)cmd[4])))
			return 1;
	}
	return 0;
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

	/* Apply udev rules before built-in device handling */
	if (!passive)
		rules_apply(&rules, &ev);

	switch (ev.action) {
	case ACT_ADD:
		if (!passive) {
			/* Firmware loading takes priority */
			if (ev.firmware)
				firmware_load(&ev);

			if (ev.modalias && !applied_has_kmod(&ev))
				modprobe_load(ev.modalias);

			/* Create device node if we have the info */
			if (ev.major >= 0 && ev.minor >= 0 && ev.devname)
				devnode_add(&ev);

			/* Rename network interface if NAME= rule was applied */
			if (ev.subsystem && !strcmp(ev.subsystem, "net"))
				netdev_add(&ev);

			/* Create symlinks */
			symlink_add(&ev);
		}
		break;

	case ACT_REMOVE:
		if (!passive) {
			/* Remove symlinks first */
			symlink_del(&ev);

			/* Remove device node */
			if (ev.devname)
				devnode_del(&ev);
		}
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

	/* Execute RUN+= commands from matched rules */
	if (!passive)
		rules_run_cmds(&ev);

	/* Persist device properties to /run/udev/data/ */
	if (!passive) {
		if (ev.action == ACT_REMOVE)
			udevdb_delete(&ev);
		else
			udevdb_write(&ev);
	}

	uevent_env_free(&ev);
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
		const char *nm = d[i]->d_name;
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

static void disable_uevent_helper(void)
{
	FILE *fp;

	fp = fopen("/proc/sys/kernel/hotplug", "w");
	if (!fp)
		return;
	fputs("\n", fp);
	fclose(fp);
}

static void set_logging(int prio)
{
	setlogmask(LOG_UPTO(prio));
	level = prio;
}

static void sigusr1_cb(uev_t *w, void *arg, int events)
{
	(void)w; (void)arg; (void)events;
	debug ^= 1;
	set_logging(debug ? LOG_DEBUG : LOG_NOTICE);
}

static void sigterm_cb(uev_t *w, void *arg, int events)
{
	(void)arg; (void)events;
	uev_exit(w->ctx);
}

static void sighup_cb(uev_t *w, void *arg, int events)
{
	(void)w; (void)arg; (void)events;
	rules_free(&rules);
	rules_load_all(&rules, rules_dir);
}

static void sigchld_cb(uev_t *w, void *arg, int events)
{
	(void)w; (void)arg; (void)events;

	/* Reap all the children. */
	while (waitpid(-1, NULL, WNOHANG) > 0)
		;
}

static void uevent_cb(uev_t *w, void *arg, int events)
{
	char *uevent_buf = arg;
	char  rebc_buf[UEVENT_BUFFER_SIZE];
	int   len;

	if (events & UEV_ERROR) {
		warn("netlink watcher error, re-arming");
		uev_io_start(w);
		return;
	}

	len = recv(w->fd, uevent_buf, UEVENT_BUFFER_SIZE - 1, MSG_DONTWAIT);
	if (len == -1) {
		switch (errno) {
		case EINTR:
		case EAGAIN:
			return;
		case ENOBUFS:
			warn("lost events, buffer overflow");
			return;
		default:
			panic("recv failed");
		}
	}
	uevent_buf[len] = 0;

	/* Skip libudev events (start with "libudev") */
	if (!strncmp(uevent_buf, "libudev", 7))
		return;

	/*
	 * Save raw buffer before handle_uevent() -- uevent_parse()
	 * modifies the buffer in-place (splits @ and = separators).
	 * Rebroadcast needs the original kernel format intact.
	 */
	if (rebc_fd != -1)
		memcpy(rebc_buf, uevent_buf, len);

	handle_uevent(uevent_buf, len);

	/* Rebroadcast after processing so consumers see ready state. */
	if (rebc_fd != -1)
		rebc_event(rebc_buf, len);
}

static int usage(int rc)
{
	fprintf(stderr,
		"Usage: keventd [-dGhnpv] [-c] [-g GROUP] [-r DIR]\n"
		"\n"
		"Options:\n"
		"  -c        Run coldplug at startup\n"
		"  -d        Enable debug mode (foreground, verbose)\n"
		"  -g GROUP  Override netlink rebroadcast group (default: %d)\n"
		"  -G        Disable netlink rebroadcast entirely\n"
		"  -h        Show this help text\n"
		"  -n        Run in foreground (no daemon)\n"
		"  -p        Passive mode: power supply events only (no device management)\n"
		"  -r DIR    Extra rules directory (in addition to standard udev paths)\n"
		"  -v        Show version\n"
		"\n", REBC_DEFAULT_NLGROUP);

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
	static char uevent_buf[UEVENT_BUFFER_SIZE];
	unsigned int nlgroups = REBC_DEFAULT_NLGROUP;
	struct sockaddr_nl nls = { 0 };
	uev_t sigusr1_w, sigterm_w, sighup_w, sigchld_w;
	uev_t netlink_w;
	uev_ctx_t ctx;
	int do_coldplug = 0;
	int foreground = 0;
	int nlfd;
	int c;

	/* Device nodes are created with explicit MODE= from rules or the
	 * built-in devrules table; clear umask so mknod() honors the
	 * requested bits verbatim instead of masking them. */
	umask(0);

	while ((c = getopt(argc, argv, "cdg:Ghnpr:v")) != -1) {
		switch (c) {
		case 'c':
			do_coldplug = 1;
			break;
		case 'd':
			debug = 1;
			foreground = 1;
			break;
		case 'g':
			nlgroups = (unsigned int)atoi(optarg);
			break;
		case 'G':
			nlgroups = 0;
			break;
		case 'h':
			return usage(0);
		case 'n':
			foreground = 1;
			break;
		case 'p':
			passive = 1;
			break;
		case 'r':
			rules_dir = optarg;
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

	uev_init(&ctx);

	uev_signal_init(&ctx, &sigusr1_w, sigusr1_cb, NULL, SIGUSR1);
	uev_signal_init(&ctx, &sigterm_w, sigterm_cb, NULL, SIGTERM);
	uev_signal_init(&ctx, &sighup_w,  sighup_cb,  NULL, SIGHUP);
	uev_signal_init(&ctx, &sigchld_w, sigchld_cb, NULL, SIGCHLD);

	/* Initialize condition directories */
	init_power_supply();
	init_dev_condition_dir();

	/* Disable legacy kernel uevent helper; we own events via netlink.
	 * Skip in passive mode -- the hotplug daemon handles this. */
	if (!passive)
		disable_uevent_helper();

	/* Set up netlink socket for kernel uevents */
	nlfd = socket(PF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_KOBJECT_UEVENT);
	if (nlfd == -1)
		panic("failed creating netlink socket");

	nls.nl_family = AF_NETLINK;
	nls.nl_pid    = 0;
	nls.nl_groups = 1;	/* Kernel uevents are on group 1 only */
	if (bind(nlfd, (void *)&nls, sizeof(struct sockaddr_nl)))
		panic("bind failed");

	/* Increase receive buffer to reduce event loss */
	{
		int rcvbuf = 1024 * 1024;
		setsockopt(nlfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
	}

	uev_io_init(&ctx, &netlink_w, uevent_cb, uevent_buf, nlfd, UEV_READ);

	/* Initialize rebroadcast socket (default on, -G to disable).
	 * Skip in passive mode -- the hotplug daemon rebroadcasts. */
	if (nlgroups && !passive)
		rebc_init(nlgroups);

	/* Run coldplug if requested */
	if (do_coldplug)
		coldplug();

	/* Load udev rules from standard directories (and -r extra_dir) */
	if (!passive)
		rules_load_all(&rules, rules_dir);

	pidfile(NULL);
	logit(LOG_NOTICE, "keventd v%s started, waiting for events...", KEVENTD_VERSION);

	uev_run(&ctx, 0);

	if (rebc_fd != -1)
		close(rebc_fd);
	close(nlfd);
	rules_free(&rules);
	logit(LOG_NOTICE, "keventd shutting down");

	return 0;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
