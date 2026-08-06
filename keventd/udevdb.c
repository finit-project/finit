/* udev-compatible per-device database in /run/udev/data/
 *
 * Copyright (c) 2025  Joachim Wiberg <troglobit@gmail.com>
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
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <syslog.h>
#include <unistd.h>

#ifdef _LIBITE_LITE
# include <libite/lite.h>
#else
# include <lite/lite.h>
#endif

#include "keventd.h"
#include "sysfs.h"
#include "udevdb.h"

/* Forward declaration from keventd.c */
void logit(int prio, const char *fmt, ...);

/*
 * Compute the database file path for a device.
 *
 * udev's keying scheme:
 *   b<maj>:<min>            block device
 *   c<maj>:<min>            character device
 *   n<ifindex>              network interface
 *   +<subsystem>:<sysname>  everything else
 *
 * This matches the layout that udevadm info, libudev, and eudev expect.
 */
static void udevdb_path(const struct uevent *ev, char *buf, size_t len)
{
	const char *sysname = uevent_sysname(ev);
	const char *ifindex = NULL;

	if (ev->subsystem && !strcmp(ev->subsystem, "net"))
		ifindex = uevent_getenv(ev, "IFINDEX");

	if (ev->major >= 0 && ev->minor >= 0) {
		const char *t = (ev->subsystem && !strcmp(ev->subsystem, "block"))
				? "b" : "c";
		snprintf(buf, len, UDEVDB_PATH "/%s%d:%d", t, ev->major, ev->minor);
	} else if (ifindex) {
		snprintf(buf, len, UDEVDB_PATH "/n%s", ifindex);
	} else {
		snprintf(buf, len, UDEVDB_PATH "/+%s:%s",
			 ev->subsystem ? ev->subsystem : "unknown",
			 sysname       ? sysname       : "unknown");
	}
}

/*
 * Write device properties to the database.
 *
 * Called after devnode_add() and symlink_add() so that all S: records
 * can be captured via symlink_write_db().
 */
int udevdb_write(const struct uevent *ev)
{
	char path[PATH_MAX];
	struct timeval tv;
	FILE *fp;
	int i;

	if (!ev->devpath)
		return -1;

	if (mkpath(UDEVDB_PATH, 0755) && errno != EEXIST)
		return -1;

	udevdb_path(ev, path, sizeof(path));

	fp = fopen(path, "w");
	if (!fp) {
		logit(LOG_DEBUG, "udevdb: cannot write %s: %s", path, strerror(errno));
		return -1;
	}

	/* Timestamp in microseconds since epoch */
	gettimeofday(&tv, NULL);
	fprintf(fp, "I:%llu\n",
		(unsigned long long)(tv.tv_sec * 1000000ULL + tv.tv_usec));

	/* All environment variables / device properties */
	for (i = 0; i < ev->nenv; i++)
		fprintf(fp, "E:%s=%s\n", ev->env_key[i], ev->env_val[i]);

	/* Symlinks created for this device */
	symlink_write_db(ev->devpath, fp);

	/* Tags */
	for (i = 0; i < ev->ntags; i++) {
		fprintf(fp, "G:%s\n", ev->tags[i]);
		fprintf(fp, "Q:%s\n", ev->tags[i]);
	}

	fprintf(fp, "V:1\n");
	fclose(fp);

	return 0;
}

/*
 * Read E: records from a database file into ev's env store.
 */
static int udevdb_load(const char *path, struct uevent *ev)
{
	char line[1024];
	FILE *fp;

	fp = fopen(path, "r");
	if (!fp)
		return -1;

	while (fgets(line, sizeof(line), fp)) {
		char *val;

		chomp(line);

		if (line[0] != 'E' || line[1] != ':')
			continue;

		val = strchr(line + 2, '=');
		if (!val)
			continue;
		*val++ = 0;

		uevent_setenv(ev, line + 2, val);
	}

	fclose(fp);
	return 0;
}

/*
 * Read device properties back from the database into ev's env store.
 *
 * Used by IMPORT{db} in the rules engine (Phase 4) to recover properties
 * that were set during a previous event for the same device.
 */
int udevdb_read(struct uevent *ev)
{
	char path[PATH_MAX];

	if (!ev->devpath)
		return -1;

	udevdb_path(ev, path, sizeof(path));

	return udevdb_load(path, ev);
}

/*
 * Read the parent device's properties into ev's env store, for
 * IMPORT{parent} in the rules engine.  The parent has no uevent to key
 * from, so its device ID is composed from sysfs (see udevdb_path()).
 */
int udevdb_read_parent(struct uevent *ev)
{
	char ppath[PATH_MAX], syspath[PATH_MAX], dbfile[PATH_MAX];
	char subsys[64] = "unknown";
	char attr[64];
	const char *sn;
	char *slash;

	if (!ev->devpath)
		return -1;

	snprintf(ppath, sizeof(ppath), "%s", ev->devpath);
	slash = strrchr(ppath, '/');
	if (!slash || slash == ppath)
		return -1;
	*slash = 0;

	sn = strrchr(ppath, '/');
	sn = sn ? sn + 1 : ppath;

	snprintf(syspath, sizeof(syspath), "/sys%s", ppath);
	sysfs_read_subsystem(syspath, subsys, sizeof(subsys));

	snprintf(dbfile, sizeof(dbfile), "%s/dev", syspath);
	if (!sysfs_read_file(dbfile, attr, sizeof(attr))) {
		snprintf(dbfile, sizeof(dbfile), UDEVDB_PATH "/%s%s",
			 strcmp(subsys, "block") ? "c" : "b", attr);
	} else if (!strcmp(subsys, "net")) {
		snprintf(dbfile, sizeof(dbfile), "%s/ifindex", syspath);
		if (sysfs_read_file(dbfile, attr, sizeof(attr)))
			return -1;
		snprintf(dbfile, sizeof(dbfile), UDEVDB_PATH "/n%s", attr);
	} else {
		snprintf(dbfile, sizeof(dbfile), UDEVDB_PATH "/+%s:%s",
			 subsys, sn);
	}

	return udevdb_load(dbfile, ev);
}

/*
 * Remove a device's database entry on ACT_REMOVE.
 */
void udevdb_delete(const struct uevent *ev)
{
	char path[PATH_MAX];

	if (!ev->devpath)
		return;

	udevdb_path(ev, path, sizeof(path));

	if (unlink(path) && errno != ENOENT)
		logit(LOG_DEBUG, "udevdb: cannot remove %s: %s", path, strerror(errno));
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
