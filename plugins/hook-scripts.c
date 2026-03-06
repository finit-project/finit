/* Trigger scripts to run from finit's hooks
 *
 * Copyright (c) 2022  Tobias Waldekranz <tobias@waldekranz.com>
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

#include "finit.h"
#include "helpers.h"
#include "plugin.h"
#include "config.h"

extern void plugin_script_run(hook_point_t no);

static void hscript_run_parts(hook_point_t no)
{
	plugin_script_run(no);
}

static void hscript_banner(void *arg)
{
	hscript_run_parts(HOOK_BANNER);
}

static void hscript_rootfs_up(void *arg)
{
	hscript_run_parts(HOOK_ROOTFS_UP);
}

static void hscript_mount_error(void *arg)
{
	hscript_run_parts(HOOK_MOUNT_ERROR);
}

static void hscript_mount_post(void *arg)
{
	hscript_run_parts(HOOK_MOUNT_POST);
}

static void hscript_basefs_up(void *arg)
{
	hscript_run_parts(HOOK_BASEFS_UP);
}

static void hscript_network_up(void *arg)
{
	hscript_run_parts(HOOK_NETWORK_UP);
}

static void hscript_svc_up(void *arg)
{
	hscript_run_parts(HOOK_SVC_UP);
}

static void hscript_system_up(void *arg)
{
	hscript_run_parts(HOOK_SYSTEM_UP);
}

static void hscript_shutdown(void *arg)
{
	hscript_run_parts(HOOK_SHUTDOWN);
}

static plugin_t plugin = {
	.name = "hook-scripts",
	.hook[HOOK_BANNER]      = { .cb  = hscript_banner      },
	.hook[HOOK_ROOTFS_UP]   = { .cb  = hscript_rootfs_up   },
	.hook[HOOK_MOUNT_ERROR] = { .cb  = hscript_mount_error },
	.hook[HOOK_MOUNT_POST]  = { .cb  = hscript_mount_post  },
	.hook[HOOK_BASEFS_UP]   = { .cb  = hscript_basefs_up   },
	.hook[HOOK_NETWORK_UP]  = { .cb  = hscript_network_up  },
	.hook[HOOK_SVC_UP]      = { .cb  = hscript_svc_up      },
	.hook[HOOK_SYSTEM_UP]   = { .cb  = hscript_system_up   },
	.hook[HOOK_SHUTDOWN]    = { .cb  = hscript_shutdown    },
/*
 * We have exited here, so these are handled a bit differently by Finit,
 * when hook scripts are enabled, just to provide the user with the same
 * interface:
 *
 *	.hook[HOOK_SVC_DN]      = { .cb  = hscript_svc_down    },
 *	.hook[HOOK_SYS_DN]      = { .cb  = hscript_system_down },
 */
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
