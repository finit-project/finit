/* Uevent parsing, device node management, symlinks, and firmware loading
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
#include <fcntl.h>
#include <fnmatch.h>
#include <ftw.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#ifdef _LIBITE_LITE
# include <libite/lite.h>
#else
# include <lite/lite.h>
#endif

#include "keventd.h"
#include "cond.h"
#include "util.h"

/* Forward declarations */
void logit(int prio, const char *fmt, ...);

/*
 * Set/clear a device condition by creating/removing a symlink.
 * keventd is a standalone daemon, so we manipulate the filesystem directly
 * rather than using Finit's internal cond_set()/cond_clear() API.
 */
static void dev_cond(const char *devname, int set)
{
	char cond[PATH_MAX];
	char *dir;

	if (!devname)
		return;

	snprintf(cond, sizeof(cond), "%s%s", _PATH_CONDDEV, devname);

	/* Create parent directory if needed (e.g., dev/input/) */
	dir = strdupa(cond);
	dir = dirname(dir);
	if (strcmp(dir, _PATH_CONDDEV)) {
		if (mkpath(dir, 0755) && errno != EEXIST)
			logit(LOG_WARNING, "Failed creating condition dir %s", dir);
	}

	if (set) {
		if (symlink(_PATH_RECONF, cond) && errno != EEXIST)
			logit(LOG_WARNING, "Failed setting dev/%s condition", devname);
	} else {
		if (erase(cond) && errno != ENOENT)
			logit(LOG_WARNING, "Failed clearing dev/%s condition", devname);
	}
}

/* Symlink tracking for cleanup on device removal */
static TAILQ_HEAD(, dev_symlink) symlinks = TAILQ_HEAD_INITIALIZER(symlinks);

/*
 * Default device permissions based on subsystem/name.
 * Simple built-in rules, no config file needed.
 */
struct devrule {
	const char *subsystem;	/* NULL matches any */
	const char *pattern;	/* fnmatch pattern, NULL = default */
	mode_t      mode;
	uid_t       uid;
	gid_t       gid;
};

static struct devrule devrules[] = {
	/* Block devices */
	{ "block", "sd[a-z]*",     0660, 0, 6 },	/* root:disk */
	{ "block", "vd[a-z]*",     0660, 0, 6 },
	{ "block", "nvme*",        0660, 0, 6 },
	{ "block", "mmcblk*",      0660, 0, 6 },
	{ "block", "loop*",        0660, 0, 6 },
	{ "block", "dm-*",         0660, 0, 6 },
	{ "block", "md*",          0660, 0, 6 },
	{ "block", NULL,           0660, 0, 6 },	/* default block */

	/* TTY devices */
	{ "tty",   "tty[0-9]*",    0620, 0, 5 },	/* root:tty */
	{ "tty",   "ttyS*",        0660, 0, 20 },	/* root:dialout */
	{ "tty",   "ttyUSB*",      0660, 0, 20 },
	{ "tty",   "ttyACM*",      0660, 0, 20 },
	{ "tty",   NULL,           0666, 0, 5 },

	/* Input devices */
	{ "input", "event*",       0660, 0, 0 },	/* root:input (13) */
	{ "input", "mouse*",       0660, 0, 0 },
	{ "input", "mice",         0660, 0, 0 },
	{ "input", NULL,           0660, 0, 0 },

	/* Sound devices */
	{ "sound", NULL,           0660, 0, 29 },	/* root:audio */

	/* Video devices */
	{ "video4linux", NULL,     0660, 0, 44 },	/* root:video */

	/* DRM (graphics) */
	{ "drm",   "card*",        0660, 0, 44 },
	{ "drm",   "render*",      0660, 0, 44 },

	/* USB devices */
	{ "usb",   NULL,           0664, 0, 0 },

	/* Network devices - no /dev node needed */

	/* Common char devices - match by name regardless of subsystem */
	{ NULL,    "null",         0666, 0, 0 },
	{ NULL,    "zero",         0666, 0, 0 },
	{ NULL,    "full",         0666, 0, 0 },
	{ NULL,    "random",       0666, 0, 0 },
	{ NULL,    "urandom",      0666, 0, 0 },
	{ NULL,    "tty",          0666, 0, 5 },
	{ NULL,    "console",      0600, 0, 0 },
	{ NULL,    "ptmx",         0666, 0, 5 },
	{ NULL,    "kmsg",         0640, 0, 0 },
	{ NULL,    "mem",          0640, 0, 0 },	/* root:kmem */
	{ NULL,    "kmem",         0640, 0, 0 },
	{ NULL,    "port",         0640, 0, 0 },
	{ NULL,    "fuse",         0666, 0, 0 },
	{ NULL,    "kvm",          0660, 0, 0 },

	/* Default fallback */
	{ NULL,    NULL,           0660, 0, 0 },
};

static uevent_action_t parse_action(const char *str)
{
	if (!strcmp(str, "add"))
		return ACT_ADD;
	if (!strcmp(str, "remove"))
		return ACT_REMOVE;
	if (!strcmp(str, "change"))
		return ACT_CHANGE;
	if (!strcmp(str, "move"))
		return ACT_MOVE;
	if (!strcmp(str, "online"))
		return ACT_ONLINE;
	if (!strcmp(str, "offline"))
		return ACT_OFFLINE;
	if (!strcmp(str, "bind"))
		return ACT_BIND;
	if (!strcmp(str, "unbind"))
		return ACT_UNBIND;

	return ACT_UNKNOWN;
}

const char *uevent_action_str(uevent_action_t action)
{
	switch (action) {
	case ACT_ADD:     return "add";
	case ACT_REMOVE:  return "remove";
	case ACT_CHANGE:  return "change";
	case ACT_MOVE:    return "move";
	case ACT_ONLINE:  return "online";
	case ACT_OFFLINE: return "offline";
	case ACT_BIND:    return "bind";
	case ACT_UNBIND:  return "unbind";
	default:          return "unknown";
	}
}

/*
 * Parse a uevent message from kernel netlink socket.
 *
 * Format:
 *   ACTION@DEVPATH\0
 *   KEY=VALUE\0
 *   KEY=VALUE\0
 *   ...
 *   \0
 */
int uevent_parse(char *buf, size_t len, struct uevent *ev)
{
	char *at, *line;
	size_t i, hdrlen;

	memset(ev, 0, sizeof(*ev));
	ev->major = -1;
	ev->minor = -1;

	/* Find ACTION@DEVPATH separator */
	at = strchr(buf, '@');
	if (!at)
		return -1;

	/* Split action and devpath */
	*at = 0;
	ev->action = parse_action(buf);
	ev->devpath = at + 1;

	/* Skip past the header to the key=value pairs */
	hdrlen = strlen(buf) + 1 + strlen(ev->devpath) + 1;
	i = hdrlen;

	/* Parse KEY=VALUE pairs */
	while (i < len) {
		char *eq;

		line = buf + i;
		if (!*line)
			break;

		eq = strchr(line, '=');
		if (eq) {
			*eq = 0;
			eq++;

			if (!strcmp(line, "SUBSYSTEM"))
				ev->subsystem = eq;
			else if (!strcmp(line, "DEVNAME"))
				ev->devname = eq;
			else if (!strcmp(line, "DEVTYPE"))
				ev->devtype = eq;
			else if (!strcmp(line, "MAJOR"))
				ev->major = atoi(eq);
			else if (!strcmp(line, "MINOR"))
				ev->minor = atoi(eq);
			else if (!strcmp(line, "MODALIAS"))
				ev->modalias = eq;
			else if (!strcmp(line, "FIRMWARE"))
				ev->firmware = eq;
			else if (!strcmp(line, "SEQNUM"))
				ev->seqnum = eq;
			else if (!strcmp(line, "DRIVER"))
				ev->driver = eq;
		}

		i += strlen(line) + (eq ? strlen(eq) + 1 : 1) + 1;
	}

	return 0;
}

static struct devrule *find_rule(struct uevent *ev)
{
	struct devrule *rule;
	size_t i;

	for (i = 0; i < NELEMS(devrules); i++) {
		rule = &devrules[i];

		/* Check subsystem if rule specifies one */
		if (rule->subsystem && ev->subsystem) {
			if (strcmp(rule->subsystem, ev->subsystem))
				continue;
		}

		/* Check pattern if rule specifies one */
		if (rule->pattern && ev->devname) {
			/* Just match basename, not full path */
			const char *name = strrchr(ev->devname, '/');
			name = name ? name + 1 : ev->devname;

			if (fnmatch(rule->pattern, name, 0))
				continue;
		}

		return rule;
	}

	/* Return last rule as default */
	return &devrules[NELEMS(devrules) - 1];
}

/*
 * Create device node in /dev.
 */
int devnode_add(struct uevent *ev)
{
	struct devrule *rule;
	char path[PATH_MAX];
	char *dir;
	mode_t mode;
	dev_t dev;
	int rc;

	if (!ev->devname || ev->major < 0 || ev->minor < 0)
		return -1;

	snprintf(path, sizeof(path), "/dev/%s", ev->devname);

	/* Create parent directories if needed (e.g., /dev/input/) */
	dir = strdupa(path);
	dir = dirname(dir);
	if (strcmp(dir, "/dev")) {
		rc = mkpath(dir, 0755);
		if (rc && errno != EEXIST) {
			logit(LOG_ERR, "Failed creating %s: %s", dir, strerror(errno));
			return -1;
		}
	}

	/* Find matching rule for permissions */
	rule = find_rule(ev);
	mode = rule->mode;
	dev = makedev(ev->major, ev->minor);

	/* Remove existing node if present */
	unlink(path);

	/* Create device node */
	if (ev->subsystem && !strcmp(ev->subsystem, "block"))
		mode |= S_IFBLK;
	else
		mode |= S_IFCHR;

	rc = mknod(path, mode, dev);
	if (rc) {
		logit(LOG_ERR, "Failed creating %s: %s", path, strerror(errno));
		return -1;
	}

	/* Set ownership */
	if (chown(path, rule->uid, rule->gid))
		logit(LOG_WARNING, "Failed chown %s: %s", path, strerror(errno));

	logit(LOG_DEBUG, "Created %s (%d:%d) mode %04o",
	      path, ev->major, ev->minor, rule->mode);

	/* Set dev/ condition */
	dev_cond(ev->devname, 1);

	return 0;
}

/*
 * Remove device node from /dev.
 */
int devnode_del(struct uevent *ev)
{
	char path[PATH_MAX];

	if (!ev->devname)
		return -1;

	snprintf(path, sizeof(path), "/dev/%s", ev->devname);

	/* Clear dev/ condition first */
	dev_cond(ev->devname, 0);

	if (unlink(path) && errno != ENOENT) {
		logit(LOG_WARNING, "Failed removing %s: %s", path, strerror(errno));
		return -1;
	}

	logit(LOG_DEBUG, "Removed %s", path);
	return 0;
}

/*
 * Track symlink for removal when device is unplugged.
 */
static void symlink_track(const char *devpath, const char *linkpath)
{
	struct dev_symlink *sl;

	sl = malloc(sizeof(*sl));
	if (!sl)
		return;

	sl->devpath = strdup(devpath);
	sl->linkpath = strdup(linkpath);

	if (!sl->devpath || !sl->linkpath) {
		free(sl->devpath);
		free(sl->linkpath);
		free(sl);
		return;
	}

	TAILQ_INSERT_TAIL(&symlinks, sl, link);
}

/*
 * Create a symlink and track it.
 */
static int symlink_create(const char *target, const char *link, const char *devpath)
{
	char *dir;
	int rc;

	/* Create parent directories */
	dir = strdupa(link);
	dir = dirname(dir);
	rc = mkpath(dir, 0755);
	if (rc && errno != EEXIST)
		return -1;

	/* Remove existing link */
	unlink(link);

	/* Create symlink */
	if (symlink(target, link)) {
		if (errno != EEXIST)
			return -1;
	}

	/* Track for removal */
	symlink_track(devpath, link);

	logit(LOG_DEBUG, "Created symlink %s -> %s", link, target);
	return 0;
}

/*
 * Read a single line from a sysfs attribute file.
 */
static int sysfs_read(const char *path, char *buf, size_t len)
{
	FILE *fp;

	fp = fopen(path, "r");
	if (!fp)
		return -1;

	if (!fgets(buf, len, fp)) {
		fclose(fp);
		return -1;
	}

	fclose(fp);
	chomp(buf);

	return 0;
}

/*
 * Build disk ID string from sysfs attributes.
 * Format: BUSTYPE-VENDOR_MODEL_SERIAL
 */
static int disk_serial_id(struct uevent *ev, char *id, size_t len)
{
	char path[PATH_MAX];
	char vendor[64] = "", model[64] = "", serial[64] = "";
	char *p;

	/* Try to read from device's sysfs attributes */
	snprintf(path, sizeof(path), "/sys%s/device/vendor", ev->devpath);
	sysfs_read(path, vendor, sizeof(vendor));

	snprintf(path, sizeof(path), "/sys%s/device/model", ev->devpath);
	sysfs_read(path, model, sizeof(model));

	snprintf(path, sizeof(path), "/sys%s/device/serial", ev->devpath);
	if (sysfs_read(path, serial, sizeof(serial))) {
		/* Try alternate location */
		snprintf(path, sizeof(path), "/sys%s/../serial", ev->devpath);
		sysfs_read(path, serial, sizeof(serial));
	}

	/* Need at least model or serial */
	if (!model[0] && !serial[0])
		return -1;

	/* Clean up strings - replace spaces with underscores */
	for (p = vendor; *p; p++)
		if (*p == ' ') *p = '_';
	for (p = model; *p; p++)
		if (*p == ' ') *p = '_';
	for (p = serial; *p; p++)
		if (*p == ' ') *p = '_';

	/* Remove trailing underscores */
	for (p = vendor + strlen(vendor) - 1; p >= vendor && *p == '_'; p--)
		*p = 0;
	for (p = model + strlen(model) - 1; p >= model && *p == '_'; p--)
		*p = 0;

	/* Build ID string */
	if (vendor[0] && model[0] && serial[0])
		snprintf(id, len, "%s_%s_%s", vendor, model, serial);
	else if (model[0] && serial[0])
		snprintf(id, len, "%s_%s", model, serial);
	else if (serial[0])
		snprintf(id, len, "%s", serial);
	else
		snprintf(id, len, "%s", model);

	return 0;
}

/*
 * Build disk path ID from devpath.
 * Convert /devices/pci0000:00/.../host0/.../0:0:0:0/block/sda
 * to pci-0000:00:1f.2-ata-1
 */
static int disk_path_id(struct uevent *ev, char *id, size_t len)
{
	/* Simplified: just use the devpath hash for now */
	const char *p;

	/* Find last component before block/ */
	p = strstr(ev->devpath, "/block/");
	if (!p)
		return -1;

	/* Use subsystem and devname */
	snprintf(id, len, "%s-%s", ev->subsystem ?: "disk", ev->devname);

	return 0;
}


/*
 * Create symlinks for block devices in /dev/disk/by-*.
 */
static int symlink_add_disk(struct uevent *ev)
{
	char target[PATH_MAX], link[PATH_MAX], id[256];
	const char *name;

	if (!ev->devname)
		return -1;

	/* Get basename for relative link */
	name = strrchr(ev->devname, '/');
	name = name ? name + 1 : ev->devname;

	/* by-id: serial-based identifier */
	if (!disk_serial_id(ev, id, sizeof(id))) {
		snprintf(target, sizeof(target), "../../%s", name);
		snprintf(link, sizeof(link), "/dev/disk/by-id/%s", id);
		symlink_create(target, link, ev->devpath);
	}

	/* by-path: topology-based identifier */
	if (!disk_path_id(ev, id, sizeof(id))) {
		snprintf(target, sizeof(target), "../../%s", name);
		snprintf(link, sizeof(link), "/dev/disk/by-path/%s", id);
		symlink_create(target, link, ev->devpath);
	}

	return 0;
}

/*
 * Create symlinks for input devices in /dev/input/by-*.
 */
static int symlink_add_input(struct uevent *ev)
{
	char target[PATH_MAX], link[PATH_MAX];
	char name[256], phys[256];
	char path[PATH_MAX];
	const char *devname;
	char *p;

	if (!ev->devname)
		return -1;

	devname = strrchr(ev->devname, '/');
	devname = devname ? devname + 1 : ev->devname;

	/* Read device name */
	snprintf(path, sizeof(path), "/sys%s/device/name", ev->devpath);
	if (sysfs_read(path, name, sizeof(name)))
		return -1;

	/* Clean up name */
	for (p = name; *p; p++) {
		if (*p == ' ' || *p == '/')
			*p = '_';
	}

	/* by-id: name-based */
	snprintf(target, sizeof(target), "../%s", devname);
	snprintf(link, sizeof(link), "/dev/input/by-id/%s", name);
	symlink_create(target, link, ev->devpath);

	/* by-path: physical path (if available) */
	snprintf(path, sizeof(path), "/sys%s/device/phys", ev->devpath);
	if (!sysfs_read(path, phys, sizeof(phys))) {
		for (p = phys; *p; p++) {
			if (*p == ' ' || *p == '/')
				*p = '_';
		}
		snprintf(link, sizeof(link), "/dev/input/by-path/%s", phys);
		symlink_create(target, link, ev->devpath);
	}

	return 0;
}

/*
 * Create appropriate symlinks based on device subsystem.
 */
int symlink_add(struct uevent *ev)
{
	if (!ev->subsystem)
		return 0;

	if (!strcmp(ev->subsystem, "block"))
		return symlink_add_disk(ev);

	if (!strcmp(ev->subsystem, "input"))
		return symlink_add_input(ev);

	return 0;
}

/*
 * Remove symlinks associated with a device.
 */
int symlink_del(struct uevent *ev)
{
	struct dev_symlink *sl, *tmp;

	if (!ev->devpath)
		return -1;

	TAILQ_FOREACH_SAFE(sl, &symlinks, link, tmp) {
		if (!strcmp(sl->devpath, ev->devpath)) {
			unlink(sl->linkpath);
			logit(LOG_DEBUG, "Removed symlink %s", sl->linkpath);

			TAILQ_REMOVE(&symlinks, sl, link);
			free(sl->devpath);
			free(sl->linkpath);
			free(sl);
		}
	}

	return 0;
}

/*
 * Load firmware for a device.
 *
 * The kernel sends a uevent with FIRMWARE=filename when a driver
 * requests firmware via request_firmware(). We need to:
 * 1. Find the firmware file
 * 2. Write "1" to /sys/.../loading
 * 3. Write firmware data to /sys/.../data
 * 4. Write "0" to /sys/.../loading (or "-1" on error)
 */
int firmware_load(struct uevent *ev)
{
	static const char *fw_paths[] = {
		"/lib/firmware/updates/%s/%s",	/* kernel version specific updates */
		"/lib/firmware/updates/%s",	/* updates */
		"/lib/firmware/%s/%s",		/* kernel version specific */
		"/lib/firmware/%s",		/* standard path */
		NULL
	};
	char fwpath[PATH_MAX], loading[PATH_MAX], data[PATH_MAX];
	struct utsname uts;
	char buf[4096];
	int fd_fw, fd_data;
	ssize_t n;
	int i, found = 0;

	if (!ev->firmware || !ev->devpath)
		return -1;

	uname(&uts);

	/* Search for firmware file */
	for (i = 0; fw_paths[i]; i++) {
		/* Try with kernel version */
		if (strchr(fw_paths[i], '%') && strchr(strchr(fw_paths[i], '%') + 1, '%')) {
			snprintf(fwpath, sizeof(fwpath), fw_paths[i],
				 uts.release, ev->firmware);
		} else {
			snprintf(fwpath, sizeof(fwpath), fw_paths[i], ev->firmware);
		}

		if (fexist(fwpath)) {
			found = 1;
			break;
		}
	}

	if (!found) {
		logit(LOG_WARNING, "Firmware not found: %s", ev->firmware);
		goto fail;
	}

	logit(LOG_INFO, "Loading firmware %s from %s", ev->firmware, fwpath);

	/* Build sysfs paths */
	snprintf(loading, sizeof(loading), "/sys%s/loading", ev->devpath);
	snprintf(data, sizeof(data), "/sys%s/data", ev->devpath);

	/* Signal loading start */
	if (fnwrite("1", "%s", loading) < 0) {
		logit(LOG_ERR, "Failed to signal firmware loading start");
		return -1;
	}

	/* Open firmware file */
	fd_fw = open(fwpath, O_RDONLY);
	if (fd_fw < 0) {
		logit(LOG_ERR, "Failed to open firmware %s: %s", fwpath, strerror(errno));
		goto fail;
	}

	/* Open data file */
	fd_data = open(data, O_WRONLY);
	if (fd_data < 0) {
		logit(LOG_ERR, "Failed to open %s: %s", data, strerror(errno));
		close(fd_fw);
		goto fail;
	}

	/* Copy firmware data */
	while ((n = read(fd_fw, buf, sizeof(buf))) > 0) {
		if (write(fd_data, buf, n) != n) {
			logit(LOG_ERR, "Failed writing firmware data");
			close(fd_fw);
			close(fd_data);
			goto fail;
		}
	}

	close(fd_fw);
	close(fd_data);

	/* Signal success */
	fnwrite("0", "%s", loading);
	logit(LOG_INFO, "Firmware %s loaded successfully", ev->firmware);

	return 0;

fail:
	fnwrite("-1", "%s", loading);
	return -1;
}

/*
 * Load kernel module for a device based on modalias.
 */
int modprobe_load(const char *modalias)
{
	pid_t pid;

	if (!modalias)
		return -1;

	logit(LOG_DEBUG, "Loading module for %s", modalias);

	pid = fork();
	if (pid < 0) {
		logit(LOG_ERR, "fork failed: %s", strerror(errno));
		return -1;
	}

	if (pid == 0) {
		/* Child: exec modprobe */
		execl("/sbin/modprobe", "modprobe", "-bq", modalias, NULL);
		_exit(127);
	}

	/* Parent: don't wait, let modules load asynchronously */
	return 0;
}

/*
 * Coldplug callback for nftw().
 * Writes "add" to each uevent file to trigger kernel to resend events.
 */
static int coldplug_cb(const char *path, const struct stat *st,
		       int type, struct FTW *ftw)
{
	size_t len;

	(void)st;
	(void)ftw;

	if (type != FTW_F)
		return 0;

	len = strlen(path);
	if (len < 6)
		return 0;

	/* Check if filename is "uevent" */
	if (strcmp(path + len - 6, "uevent"))
		return 0;

	/* Trigger add event */
	fnwrite("add", "%s", path);

	return 0;
}

/*
 * Trigger coldplug - replay device events for devices already present.
 */
int coldplug(void)
{
	logit(LOG_INFO, "Starting coldplug...");

	/* Walk /sys/devices and trigger uevents */
	if (nftw("/sys/devices", coldplug_cb, 64, FTW_PHYS) < 0) {
		logit(LOG_ERR, "Coldplug failed: %s", strerror(errno));
		return -1;
	}

	logit(LOG_INFO, "Coldplug complete");
	return 0;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
