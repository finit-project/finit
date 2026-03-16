/* Setup and start system message bus, D-Bus
 *
 * Copyright (c) 2012-2025  Joachim Wiberg <troglobit@gmail.com>
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

#include <sys/types.h>
#ifdef _LIBITE_LITE
# include <libite/lite.h>
#else
# include <lite/lite.h>
#endif

#include "finit.h"
#include "config.h"
#include "helpers.h"
#include "plugin.h"
#include "service.h"
#include "util.h"
#include "conf.h"
#include "log.h"

#define DBUS_DAEMON "dbus-daemon"
#define DBUS_ARGS   "--nofork --system --syslog-only"
#define DBUS_DESC   "D-Bus message bus daemon"

#ifndef DBUS_DAEMONUSER
#define DBUS_DAEMONUSER "messagebus"
#endif

#ifndef DBUS_DAEMONGROUP
#define DBUS_DAEMONGROUP "messagebus"
#endif

/*
 * Dumnpster diving for the D-Bus main configuration file
 * where <pidfile> is defined.
 */
static char *dbus_pidfn(void)
{
	char *alt[] = {
		"/usr/share/dbus-1/system.conf",
		"/etc/dbus-1/system.conf",
		NULL
	};
	int i;

	for (i = 0; alt[i]; i++) {
		char *fn = alt[i];
		char buf[256];
		FILE *fp;

		fp = fopen(fn, "r");
		if (!fp)
			continue;

		fn = NULL;
		while (fgets(buf, sizeof(buf), fp)) {
			char *pos;

			pos = strstr(buf, "<pidfile>");
			if (!pos)
				continue;
			fn = pos + strlen("<pidfile>");
			pos = strstr(fn, "</pidfile>");
			if (!pos) {
				fn = NULL;
				break;
			}
			*pos = 0;
			break;
		}

		fclose(fp);
		if (fn)
			return strdup(fn);
	}

	return NULL;
}

static void setup(void *arg)
{
	char *group = DBUS_DAEMONGROUP;
	char *user = DBUS_DAEMONUSER;
	char line[256];
	char *pidfn;
	mode_t prev;
	char *cmd;

	if (rescue) {
		dbg("Skipping %s plugin in rescue mode.", "dbus");
		return;
	}

	cmd = which(DBUS_DAEMON);
	if (!cmd) {
		dbg("Skipping plugin, %s is not installed.", DBUS_DAEMON);
		return;
	}

	if (getuser(user, NULL) == -1) {
		if (getuser("dbus", NULL) == -1)
			user = "root"; /* fallback */
		else
			user = "dbus"; /* e.g., Buildroot */
	}

	if (getgroup(group) == -1) {
		if (getgroup("dbus") == -1)
			group = "root"; /* fallback */
		else
			group = "dbus"; /* e.g., Buildroot */
	}

	/* Clean up from any previous pre-bootstrap run */
	pidfn = dbus_pidfn();
	if (pidfn)
		remove(pidfn);

	dbg("Creating D-Bus Required Directories ...");
	prev = umask(0);
	mksubsys("/var/run/dbus", 0755, user, group);
	mksubsys("/var/run/lock/subsys", 0755, user, group);
	mksubsys("/var/lib/dbus", 0755, user, group);
	mksubsys("/tmp/dbus", 0755, user, group);
	umask(prev);

	/* Generate machine id for dbus */
	if (whichp("dbus-uuidgen"))
		run_interactive("dbus-uuidgen --ensure", "Verifying D-Bus machine UUID");

	/*
	 * Register service with Finit
	 * Note: dbus drops privs after starting up.
	 */
	if (pidfn) {
		snprintf(line, sizeof(line), "[S123456789] cgroup.system notify:none name:dbus pid:!%s %s %s -- %s",
			 pidfn, cmd, DBUS_ARGS, DBUS_DESC);
		free(pidfn);
	} else
		snprintf(line, sizeof(line), "[S123456789] cgroup.system notify:none name:dbus %s %s -- %s",
			 cmd, DBUS_ARGS, DBUS_DESC);

	conf_save_service(SVC_TYPE_SERVICE, line, "dbus.conf");
	free(cmd);
}

static plugin_t plugin = {
	.name = "dbus",
	.hook[HOOK_SVC_PLUGIN] = { .cb  = setup },
};

PLUGIN_INIT(__init)
{
	plugin_register(&plugin);
}

PLUGIN_EXIT(__exit)
{
	plugin_unregister(&plugin);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
