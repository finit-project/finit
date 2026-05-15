/* Private header file for main finit daemon, not for plugins
 *
 * Copyright (c) 2008-2010  Claudio Matsuoka <cmatsuoka@gmail.com>
 * Copyright (c) 2008-2025  Joachim Wiberg <troglobit@gmail.com>
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

#ifndef FINIT_PRIVATE_H_
#define FINIT_PRIVATE_H_

#include "svc.h"
#include "plugin.h"

#define SERVICE_INTERVAL_DEFAULT 300000 /* 5 mins */
#define MATCH_CMD(l, c, x) \
	(!strncasecmp(l, c, strlen(c)) && (x = (l) + strlen(c)))

#define IS_RESERVED_RUNLEVEL(l) (l == 0 || l == 6 || l == INIT_LEVEL)

extern char *finit_conf;
extern char *finit_rcsd;
extern svc_t *wdog;
extern int   service_interval;
extern char *fsck_mode;
extern char *fsck_repair;

extern uev_ctx_t *ctx;

int          api_init         (uev_ctx_t *ctx);
int          api_exit         (void);

#ifdef HAVE_DBUS
int          dbus_init        (uev_ctx_t *ctx);
int          dbus_exit        (void);
void         dbus_register_service     (svc_t *svc);
void         dbus_unregister_service   (svc_t *svc);
void         dbus_notify_service_state (svc_t *svc, int old_state, int new_state);
void         dbus_notify_condition_change(const char *name, const char *state);
#endif
void         conf_flush_events(void);

void         service_monitor  (pid_t lost, int status);

const char  *plugin_hook_str  (hook_point_t no);
int          plugin_exists    (hook_point_t no);

void         plugin_run_hook  (hook_point_t no, void *arg);
void         plugin_run_hooks (hook_point_t no);
void         plugin_script_run(hook_point_t no);

int          plugin_init      (uev_ctx_t *ctx);
void         plugin_exit      (void);

void         iterate_proc     (int (*cb)(int, void *), void *data);
int          switch_root      (const char *newroot, const char *newinit);

#endif /* FINIT_PRIVATE_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
