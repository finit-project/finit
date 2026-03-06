/* System condition event monitor for the Finit condition engine
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

#include <dirent.h>
#include <fnmatch.h>
#include <glob.h>
#include <limits.h>
#include <paths.h>

#include "finit.h"
#include "cond.h"
#include "pid.h"
#include "plugin.h"
#include "iwatch.h"
#include "log.h"

static struct iwatch iw_sys;


static int sys_add_path(struct iwatch *iw, char *path)
{
	return iwatch_add(iw, path, IN_ONLYDIR | IN_CLOSE_WRITE);
}

/*
 * unlink conditions with no active task/service, otherwise they may
 * trigger inadvertently when calling `initctl reload` to activate
 * a new configuration.
 */
static void sys_update_conds(char *dir, char *name, uint32_t mask)
{
	char path[256];
	char *cond;
	char *ptr;

	ptr = strrchr(name, '/');
	if (ptr)
		snprintf(path, sizeof(path), "%s/%s", dir, ++ptr);
	else
		snprintf(path, sizeof(path), "%s/%s", dir, name);

	cond = strstr(path, COND_BASE);
	if (!cond)
		return;

	cond += strlen(COND_BASE) + 1;
	dbg("cond: %s set: %d", cond, (mask & IN_CREATE) ? 1 : 0);
	if (!cond_update(cond))
		unlink(path);
}

/* synthesize events in case of new run dirs */
static void sys_scandir(struct iwatch *iw, char *dir, int len)
{
	glob_t gl;
	size_t i;
	char path[len + 6];
	int rc;

	snprintf(path, sizeof(path), "%s/*", dir);
	rc = glob(path, GLOB_NOSORT, NULL, &gl);
	if (rc && rc != GLOB_NOMATCH)
		return;

	for (i = 0; i < gl.gl_pathc; i++) {
		dbg("scan found %s", gl.gl_pathv[i]);
		sys_update_conds(dir, gl.gl_pathv[i], IN_CREATE);
	}
	globfree(&gl);
}

/*
 * create/remove sub-directory in monitored directory
 */
static void sys_handle_dir(struct iwatch *iw, char *dir, char *name, int mask)
{
	char path[strlen(dir) + strlen(name) + 2];
	struct iwatch_path *iwp;

	paste(path, sizeof(path), dir, name);
	dbg("path: %s", path);

	iwp = iwatch_find_by_path(iw, path);

	if (mask & IN_CREATE) {
		if (!iwp) {
			if (!sys_add_path(iw, path))
				sys_scandir(iw, path, sizeof(path));
		}
	} else if (mask & IN_DELETE) {
		if (iwp)
			iwatch_del(&iw_sys, iwp);
	}
}

static void sys_callback(void *arg, int fd, int events)
{
	static char ev_buf[8 *(sizeof(struct inotify_event) + NAME_MAX + 1) + 1];
	struct inotify_event *ev;
	ssize_t sz;
	size_t off;

	sz = read(fd, ev_buf, sizeof(ev_buf) - 1);
	if (sz <= 0) {
		err(1, "invalid inotify event");
		return;
	}
	ev_buf[sz] = 0;

	for (off = 0; off < (size_t)sz; off += sizeof(*ev) + ev->len) {
		struct iwatch_path *iwp;

		if (off + sizeof(*ev) > (size_t)sz)
			break;

		ev = (struct inotify_event *)&ev_buf[off];
		if (off + sizeof(*ev) + ev->len > (size_t)sz)
			break;

		dbg("name %s, event: 0x%08x", ev->name, ev->mask);
		if (!ev->mask)
			continue;

		/* Find base path for this event */
		iwp = iwatch_find_by_wd(&iw_sys, ev->wd);
		if (!iwp)
			continue;

		if (ev->mask & IN_ISDIR) {
			sys_handle_dir(&iw_sys, iwp->path, ev->name, ev->mask);
			continue;
		}

		if (ev->mask & (IN_CREATE | IN_DELETE))
			sys_update_conds(iwp->path, ev->name, ev->mask);
	}
}

static void sys_init(void *arg)
{
	char sysdir[MAX_ARG_LEN];
	char *path;

	mkpath(_PATH_COND, 0755);
	if (mkpath(pid_runpath(_PATH_CONDSYS, sysdir, sizeof(sysdir)), 0755) && errno != EEXIST) {
		err(1, "Failed creating %s condition directory, %s", COND_SYS, _PATH_CONDSYS);
		return;
	}

	path = realpath(_PATH_CONDSYS, NULL);
	if (!path) {
		err(1, "Cannot figure out real path to %s, aborting", _PATH_CONDSYS);
		return;
	}

	if (iwatch_add(&iw_sys, path, IN_ONLYDIR))
		iwatch_exit(&iw_sys);

	free(path);
}

static plugin_t plugin = {
	.name = "sys",
	.hook[HOOK_BASEFS_UP]  = { .cb = sys_init },
	.depends = { "bootmisc", },
};

PLUGIN_INIT(__init)
{
	int fd;

	fd = iwatch_init(&iw_sys);
	if (fd < 0)
		return;

	plugin.io.fd = fd;
	plugin.io.cb = sys_callback;
	plugin.io.flags = PLUGIN_IO_READ;

	plugin_register(&plugin);
}

PLUGIN_EXIT(__exit)
{
	plugin_unregister(&plugin);
	iwatch_exit(&iw_sys);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
