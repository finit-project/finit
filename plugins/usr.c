/* User-defined condition event monitor for the Finit condition engine
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

static struct iwatch iw_usr;


static void usr_cond(char *name, uint32_t mask)
{
	char cond[MAX_COND_LEN] = COND_USR;

	strlcat(cond, name, sizeof(cond));
	cond_update(cond);
}

static void usr_callback(void *arg, int fd, int events)
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
		if (off + sizeof(*ev) > (size_t)sz)
			break;

		ev = (struct inotify_event *)&ev_buf[off];
		if (off + sizeof(*ev) + ev->len > (size_t)sz)
			break;

		dbg("name %s, event: 0x%08x", ev->name, ev->mask);
		if (!ev->mask)
			continue;

		if (ev->mask & IN_ISDIR)
			continue;	/* unsupported */

		if (ev->mask & IN_DELETE)
			sync();		/* dont ask */

		usr_cond(ev->name, ev->mask);
	}
}

static void usr_init(void *arg)
{
	char usrdir[MAX_ARG_LEN];
	char *path;

	mkpath(_PATH_COND, 0755);
	if (mkpath(pid_runpath(_PATH_CONDUSR, usrdir, sizeof(usrdir)), 0755) && errno != EEXIST) {
		err(1, "Failed creating %s condition directory, %s", COND_USR, _PATH_CONDUSR);
		return;
	}

	path = realpath(_PATH_CONDUSR, NULL);
	if (!path) {
		err(1, "Cannot figure out real path to %s, aborting", _PATH_CONDUSR);
		return;
	}

	if (iwatch_add(&iw_usr, path, IN_ONLYDIR))
		iwatch_exit(&iw_usr);

	free(path);
}

static plugin_t plugin = {
	.name = "usr",
	.hook[HOOK_BASEFS_UP]  = { .cb = usr_init },
	.depends = { "bootmisc", },
};

PLUGIN_INIT(__init)
{
	int fd;

	fd = iwatch_init(&iw_usr);
	if (fd < 0)
		return;

	plugin.io.fd = fd;
	plugin.io.cb = usr_callback;
	plugin.io.flags = PLUGIN_IO_READ;

	plugin_register(&plugin);
}

PLUGIN_EXIT(__exit)
{
	plugin_unregister(&plugin);
	iwatch_exit(&iw_usr);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
