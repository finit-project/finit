/* Setup necessary files for resolvconf
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

#ifdef _LIBITE_LITE
# include <libite/lite.h>
#else
# include <lite/lite.h>
#endif

#include "finit.h"
#include "helpers.h"
#include "plugin.h"
#include "log.h"

/*
 * No need to clean up files in /etc/resolvconf/run/interface/
 * this is already taken care of by bootclean
 */
static void setup(void *arg)
{
	dbg("Setting up the resolver ...");
	mkpath("/etc/resolvconf",               0755);
	mkpath("/etc/resolvconf/run",           0755);
	mkpath("/var/run/resolvconf",           0755);
	mkpath("/var/run/resolvconf/interface", 0755);

	touch("/etc/resolvconf/run/enable-updates");
	chdir("/etc/resolvconf/run/interface");
	run_parts("/etc/resolvconf/update.d", "-i", NULL, 0, 0);
	chdir("/");
}

static plugin_t plugin = {
	.name = "resolvconf",
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
