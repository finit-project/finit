/* Save and restore ALSA sound settings using alsactl
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

#include "conf.h"
#include "finit.h"
#include "helpers.h"
#include "plugin.h"
#include "log.h"

#define ALSACTL "alsactl"

static void save(void *arg)
{
	if (rescue) {
		dbg("Skipping %s plugin in rescue mode.", "alsa-utils");
		return;
	}

	if (whichp(ALSACTL)) {
		dbg("Saving sound settings ...");
		run_interactive(ALSACTL " -g store", "Saving sound settings");
	}
}

static void restore(void *arg)
{
	if (rescue) {
		dbg("Skipping %s plugin in rescue mode.", "alsa-utils");
		return;
	}

	if (whichp(ALSACTL)) {
		dbg("Restoring sound settings ...");
		run_interactive(ALSACTL " -g restore", "Restoring sound settings");
	}
}

static plugin_t plugin = {
	.name = "alsa-utils",
	.hook[HOOK_BASEFS_UP] = { .cb  = restore },
	.hook[HOOK_SHUTDOWN]  = { .cb  = save    }
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
