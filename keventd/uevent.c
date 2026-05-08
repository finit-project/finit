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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#include <net/if.h>

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

	/* Seed env store with header fields not present as KEY=VALUE pairs */
	if (ev->nenv < UEVENT_ENV_MAX - 1) {
		ev->env_key[ev->nenv] = (char *)"ACTION";
		ev->env_val[ev->nenv] = buf;	/* points to null-term'd action string */
		ev->nenv++;
		ev->env_key[ev->nenv] = (char *)"DEVPATH";
		ev->env_val[ev->nenv] = ev->devpath;
		ev->nenv++;
	}

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
			else if (!strcmp(line, "INTERFACE") && !ev->devname)
				ev->devname = eq;	/* net devices use INTERFACE=, not DEVNAME= */
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

			/* Store every pair in the env store for rule matching */
			if (ev->nenv < UEVENT_ENV_MAX) {
				ev->env_key[ev->nenv] = line;
				ev->env_val[ev->nenv] = eq;
				/* alloc flags stay 0: buffer pointers, never freed */
				ev->nenv++;
			}
		}

		i += strlen(line) + (eq ? strlen(eq) + 1 : 1) + 1;
	}

	return 0;
}

const char *uevent_sysname(const struct uevent *ev)
{
	const char *p;

	if (!ev->devpath)
		return NULL;
	p = strrchr(ev->devpath, '/');
	return p ? p + 1 : ev->devpath;
}

const char *uevent_getenv(const struct uevent *ev, const char *key)
{
	int i;

	for (i = 0; i < ev->nenv; i++) {
		if (!strcmp(ev->env_key[i], key))
			return ev->env_val[i];
	}
	return NULL;
}

int uevent_setenv(struct uevent *ev, const char *key, const char *val)
{
	char *v;
	int i;

	/* Update value of an existing key */
	for (i = 0; i < ev->nenv; i++) {
		if (!strcmp(ev->env_key[i], key)) {
			if (!strcmp(ev->env_val[i], val))
				return 0;
			v = strdup(val);
			if (!v)
				return -1;
			if (ev->env_val_alloc[i])
				free(ev->env_val[i]);
			ev->env_val[i]       = v;
			ev->env_val_alloc[i] = 1;
			return 0;
		}
	}

	/* Add new key — both key and value are heap-allocated */
	if (ev->nenv >= UEVENT_ENV_MAX)
		return -1;

	i = ev->nenv;
	ev->env_key[i] = strdup(key);
	ev->env_val[i] = strdup(val);
	if (!ev->env_key[i] || !ev->env_val[i]) {
		free(ev->env_key[i]);
		free(ev->env_val[i]);
		return -1;
	}
	ev->env_key_alloc[i] = 1;
	ev->env_val_alloc[i] = 1;
	ev->nenv++;
	return 0;
}

void rule_ctx_free(struct rule_ctx *ctx)
{
	int i;

	free(ctx->name);
	ctx->name = NULL;

	for (i = 0; i < ctx->nsymlinks; i++) {
		free(ctx->symlinks[i]);
		ctx->symlinks[i] = NULL;
	}
	ctx->nsymlinks = 0;

	for (i = 0; i < ctx->nruncmds; i++) {
		free(ctx->run_cmds[i]);
		ctx->run_cmds[i] = NULL;
	}
	ctx->nruncmds = 0;
}

void uevent_env_free(struct uevent *ev)
{
	int i;

	for (i = 0; i < ev->nenv; i++) {
		if (ev->env_key_alloc[i])
			free(ev->env_key[i]);
		if (ev->env_val_alloc[i])
			free(ev->env_val[i]);
	}
	ev->nenv = 0;

	free(ev->result);
	ev->result = NULL;

	for (i = 0; i < ev->ntags; i++)
		free(ev->tags[i]);
	ev->ntags = 0;

	rule_ctx_free(&ev->applied);
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
	const char *devname;
	char *dir;
	mode_t mode;
	dev_t dev;
	int rc;

	if (!ev->devname || ev->major < 0 || ev->minor < 0)
		return -1;

	/* NAME= in a rule overrides the kernel-supplied device name */
	devname = ev->applied.name ?: ev->devname;
	snprintf(path, sizeof(path), "/dev/%s", devname);

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

	/* Built-in table provides defaults; rules engine may override */
	rule = find_rule(ev);
	mode = ev->applied.has_mode  ? ev->applied.mode : rule->mode;
	dev  = makedev(ev->major, ev->minor);

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

	/* mknod() applies umask; chmod() does not.  Explicitly chmod to
	 * the requested mode so the result is independent of umask state. */
	if (chmod(path, mode & ~S_IFMT))
		logit(LOG_WARNING, "Failed chmod %s: %s", path, strerror(errno));

	/* Set ownership */
	{
		uid_t uid = ev->applied.has_owner ? ev->applied.uid : rule->uid;
		gid_t gid = ev->applied.has_group ? ev->applied.gid : rule->gid;

		if (chown(path, uid, gid))
			logit(LOG_WARNING, "Failed chown %s: %s", path, strerror(errno));
	}

	logit(LOG_DEBUG, "Created %s (%d:%d) mode %04o",
	      path, ev->major, ev->minor, mode & ~S_IFMT);

	/* Set dev/ condition using the actual node name */
	dev_cond(devname, 1);

	return 0;
}

/*
 * Remove device node from /dev.
 */
int devnode_del(struct uevent *ev)
{
	const char *devname;
	char path[PATH_MAX];

	if (!ev->devname)
		return -1;

	/* Mirror devnode_add: NAME= overrides the kernel-supplied name */
	devname = ev->applied.name ?: ev->devname;
	snprintf(path, sizeof(path), "/dev/%s", devname);

	/* Clear dev/ condition first */
	dev_cond(devname, 0);

	if (unlink(path) && errno != ENOENT) {
		logit(LOG_WARNING, "Failed removing %s: %s", path, strerror(errno));
		return -1;
	}

	logit(LOG_DEBUG, "Removed %s", path);
	return 0;
}

/*
 * Handle network interface add: rename if NAME= was set by a rule, then
 * set the dev/ condition so Finit services can depend on the interface.
 *
 * The interface must be DOWN for SIOCSIFNAME to succeed.  Freshly added
 * interfaces always are, so we do not attempt to bring the link down.
 */
int netdev_add(struct uevent *ev)
{
	const char *new_name;

	if (!ev->devname)
		return -1;

	new_name = ev->applied.name;

	if (new_name && strcmp(ev->devname, new_name)) {
		struct ifreq ifr;
		int sock, rc;

		sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
		if (sock < 0) {
			logit(LOG_WARNING, "Cannot open socket for netif rename: %s",
			      strerror(errno));
			goto cond;
		}

		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name,    ev->devname, IFNAMSIZ - 1);
		strncpy(ifr.ifr_newname, new_name,    IFNAMSIZ - 1);

		rc = ioctl(sock, SIOCSIFNAME, &ifr);
		close(sock);

		if (rc < 0)
			logit(LOG_WARNING, "Failed renaming %s -> %s: %s",
			      ev->devname, new_name, strerror(errno));
		else
			logit(LOG_NOTICE, "Renamed interface %s -> %s",
			      ev->devname, new_name);
	}

cond:
	dev_cond(new_name ?: ev->devname, 1);
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
 * Write S: symlink records for a device into an already-open database file.
 * Called by udevdb_write() when building the per-device database entry.
 */
void symlink_write_db(const char *devpath, FILE *fp)
{
	struct dev_symlink *sl;

	TAILQ_FOREACH(sl, &symlinks, link) {
		if (strcmp(sl->devpath, devpath))
			continue;
		/* Store path relative to /dev/ */
		const char *rel = sl->linkpath;
		if (!strncmp(rel, "/dev/", 5))
			rel += 5;
		fprintf(fp, "S:%s\n", rel);
	}
}

/*
 * Create appropriate symlinks based on device subsystem and rules.
 */
int symlink_add(struct uevent *ev)
{
	int i;

	/* Built-in subsystem symlinks */
	if (ev->subsystem) {
		if (!strcmp(ev->subsystem, "block"))
			symlink_add_disk(ev);
		else if (!strcmp(ev->subsystem, "input"))
			symlink_add_input(ev);
	}

	/* SYMLINK+= from matched rules */
	for (i = 0; i < ev->applied.nsymlinks; i++) {
		const char *devname, *sl;
		char link[PATH_MAX], target[PATH_MAX];
		size_t toff = 0;
		int depth = 0;
		const char *p;

		sl = ev->applied.symlinks[i];
		if (!sl || !*sl)
			continue;

		devname = ev->applied.name ?: ev->devname;
		if (!devname)
			continue;

		/* basename of devname for the symlink target */
		const char *base = strrchr(devname, '/');
		base = base ? base + 1 : devname;

		/* Count '/' in symlink path to determine relative depth */
		for (p = sl; *p; p++)
			if (*p == '/')
				depth++;

		target[0] = 0;
		for (int d = 0; d < depth; d++)
			toff += snprintf(target + toff, sizeof(target) - toff, "../");
		snprintf(target + toff, sizeof(target) - toff, "%s", base);

		snprintf(link, sizeof(link), "/dev/%s", sl);
		symlink_create(target, link, ev->devpath ?: "");
	}

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
	static const struct {
		const char *fmt;
		int kver;	/* fmt has %s for uts.release before %s for firmware */
	} fw_paths[] = {
		{ "/lib/firmware/updates/%s/%s",     1 },
		{ "/lib/firmware/updates/%s",        0 },
		{ "/lib/firmware/%s/%s",             1 },
		{ "/lib/firmware/%s",                0 },
		{ "/usr/lib/firmware/updates/%s/%s", 1 },
		{ "/usr/lib/firmware/updates/%s",    0 },
		{ "/usr/lib/firmware/%s/%s",         1 },
		{ "/usr/lib/firmware/%s",            0 },
	};
	char fwpath[PATH_MAX], loading[PATH_MAX], data[PATH_MAX];
	struct utsname uts;
	char buf[4096];
	int fd_fw = -1, fd_data = -1;
	int ok = 0, found = 0;
	ssize_t n;
	size_t i;

	if (!ev->firmware || !ev->devpath)
		return -1;

	/*
	 * Build sysfs paths up front so the fail label can always write
	 * "-1" to abort the kernel firmware request, even if we never
	 * managed to write "1" to start it.
	 */
	snprintf(loading, sizeof(loading), "/sys%s/loading", ev->devpath);
	snprintf(data,    sizeof(data),    "/sys%s/data",    ev->devpath);

	uname(&uts);

	for (i = 0; i < NELEMS(fw_paths); i++) {
		if (fw_paths[i].kver)
			snprintf(fwpath, sizeof(fwpath), fw_paths[i].fmt,
				 uts.release, ev->firmware);
		else
			snprintf(fwpath, sizeof(fwpath), fw_paths[i].fmt,
				 ev->firmware);

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

	fd_fw = open(fwpath, O_RDONLY | O_CLOEXEC);
	if (fd_fw < 0) {
		logit(LOG_ERR, "Failed to open firmware %s: %s",
		      fwpath, strerror(errno));
		goto fail;
	}

	if (fnwrite("1", "%s", loading) < 0) {
		logit(LOG_ERR, "Failed to signal firmware loading start: %s",
		      strerror(errno));
		goto fail;
	}

	fd_data = open(data, O_WRONLY | O_CLOEXEC);
	if (fd_data < 0) {
		logit(LOG_ERR, "Failed to open %s: %s", data, strerror(errno));
		goto fail;
	}

	for (;;) {
		ssize_t total;

		n = read(fd_fw, buf, sizeof(buf));
		if (n == 0)
			break;
		if (n < 0) {
			if (errno == EINTR)
				continue;
			logit(LOG_ERR, "Failed reading firmware %s: %s",
			      fwpath, strerror(errno));
			goto fail;
		}

		for (total = 0; total < n; ) {
			ssize_t w = write(fd_data, buf + total, n - total);

			if (w < 0) {
				if (errno == EINTR)
					continue;
				logit(LOG_ERR, "Failed writing firmware data: %s",
				      strerror(errno));
				goto fail;
			}
			total += w;
		}
	}

	ok = 1;

fail:
	if (fd_fw >= 0)
		close(fd_fw);
	if (fd_data >= 0)
		close(fd_data);

	if (fnwrite(ok ? "0" : "-1", "%s", loading) < 0)
		logit(LOG_WARNING, "Failed to signal firmware load %s: %s",
		      ok ? "complete" : "abort", strerror(errno));
	else if (ok)
		logit(LOG_INFO, "Firmware %s loaded successfully", ev->firmware);

	return ok ? 0 : -1;
}

/*
 * Load kernel module for a device based on modalias.
 *
 * Synchronous: waits for modprobe to complete before returning so
 * that rules running after `kmod load` (e.g. IMPORT{builtin}=blkid
 * once the filesystem driver is in) see the post-load state.
 * keventd's main loop uses SIGCHLD=SIG_IGN to auto-reap stray
 * children, so we temporarily restore the default handler here to
 * make waitpid() observable.
 */
int modprobe_load(const char *modalias)
{
	struct sigaction sa_dfl, sa_old;
	pid_t pid;
	int   status = 0;

	if (!modalias)
		return -1;

	logit(LOG_DEBUG, "Loading module for %s", modalias);

	sigemptyset(&sa_dfl.sa_mask);
	sa_dfl.sa_flags   = 0;
	sa_dfl.sa_handler = SIG_DFL;
	sigaction(SIGCHLD, &sa_dfl, &sa_old);

	pid = fork();
	if (pid < 0) {
		logit(LOG_ERR, "fork failed: %s", strerror(errno));
		sigaction(SIGCHLD, &sa_old, NULL);
		return -1;
	}

	if (pid == 0) {
		execl("/sbin/modprobe", "modprobe", "-bq", modalias, NULL);
		_exit(127);
	}

	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;
	sigaction(SIGCHLD, &sa_old, NULL);

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return -1;
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
