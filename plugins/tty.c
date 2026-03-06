/* Optional TTY Watcher, used to catch new TTYs that are discovered, e.g., USB
 *
 * Copyright (c) 2013  Mattias Walström <lazzer@gmail.com>
 * Copyright (c) 2013-2025  Joachim Wiberg <troglobit@gmail.com>
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
#include <fcntl.h>		/* O_RDONLY et al */
#include <unistd.h>		/* read() */
#include <sys/inotify.h>
#include <sys/stat.h>
#ifdef _LIBITE_LITE
# include <libite/lite.h>
#else
# include <lite/lite.h>
#endif

#include "finit.h"
#include "helpers.h"
#include "plugin.h"
#include "service.h"
#include "tty.h"
#include "log.h"

static void tty_watcher(void *arg, int fd, int events);

static plugin_t plugin = {
	.name = "tty",
	.io = {
		.cb    = tty_watcher,
		.flags = PLUGIN_IO_READ,
	},
};

static void setup(void)
{
	if (plugin.io.fd > 0)
		close(plugin.io.fd);

	plugin.io.fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (-1 == plugin.io.fd || inotify_add_watch(plugin.io.fd, "/dev", IN_CREATE | IN_DELETE) < 0)
		err(1, "Failed starting TTY watcher");
}

static void do_tty(char *tty, size_t len, int creat)
{
	char name[len + 6];
	svc_t *svc;

	snprintf(name, sizeof(name), "/dev/%s", tty);
	svc = svc_find_by_tty(name);
	if (svc) {
		if (svc_is_blocked(svc) && creat) {
			dbg("%s: blocked, re-enabling", svc_ident(svc, NULL, 0));
			svc_start(svc);
		} else if (svc->pid) {
			dbg("%s: missing ...", svc_ident(svc, NULL, 0));
			svc_missing(svc);
		}

		service_step_all(SVC_TYPE_TTY);
	}
}

static void tty_watcher(void *arg, int fd, int events)
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

		if (!ev->mask)
			continue;

		dbg("tty %s, event: 0x%08x", ev->name, ev->mask);
		do_tty(ev->name, ev->len, ev->mask & IN_CREATE);
	}
}

PLUGIN_INIT(__init)
{
	setup();
	plugin_register(&plugin);
}

PLUGIN_EXIT(__exit)
{
	plugin_unregister(&plugin);
	if (plugin.io.fd)
		close(plugin.io.fd);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
