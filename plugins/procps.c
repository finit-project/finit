/* Set kernel variables from /etc/sysctl.conf et al
 *
 * Copyright (c) 2016-2025  Joachim Wiberg <troglobit@gmail.com>
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

#include <glob.h>
#ifdef _LIBITE_LITE
# include <libite/lite.h>
#else
# include <lite/lite.h>
#endif

#include "finit.h"
#include "helpers.h"
#include "plugin.h"
#include "conf.h"
#include "log.h"

#ifndef SYSCTL_PATH
#define SYSCTL_PATH "/sbin/sysctl"
#endif

static void setup(void *arg)
{
	glob_t gl;

	if (rescue) {
		dbg("Skipping %s plugin in rescue mode.", "procps");
		return;
	}

	glob("/run/sysctl.d/*.conf",           0, NULL, &gl);
	glob("/etc/sysctl.d/*.conf",           GLOB_APPEND, NULL, &gl);
	glob("/usr/local/lib/sysctl.d/*.conf", GLOB_APPEND, NULL, &gl);
	glob("/usr/lib/sysctl.d/*.conf",       GLOB_APPEND, NULL, &gl);
	glob("/lib/sysctl.d/*.conf",           GLOB_APPEND, NULL, &gl);
	glob("/mnt/sysctl.d/*.conf",           GLOB_APPEND, NULL, &gl);
	glob("/etc/sysctl.conf",               GLOB_APPEND, NULL, &gl);
	if (gl.gl_pathc > 0) {
		size_t i;

		for (i = 0; i < gl.gl_pathc; i++) {
			char cmd[160];

			snprintf(cmd, sizeof(cmd), "%s -e -p %s >/dev/null", SYSCTL_PATH, gl.gl_pathv[i]);
			run(cmd, "sysctl");
		}
		globfree(&gl);
	}

}

static plugin_t plugin = {
	.name = "procps",
	.hook[HOOK_BASEFS_UP] = {
		.cb  = setup
	},
	.depends = { "bootmisc", },
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
