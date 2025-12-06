/* Parser for /etc/finit.conf and /etc/finit.d/<SVC>.conf
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

#ifndef FINIT_CONF_H_
#define FINIT_CONF_H_

#include "cgroup.h"
#include "svc.h"

extern int   runlevel;
extern int   cfglevel;
extern int   cmdlevel;
extern int   prevlevel;
extern int   debug;
extern int   rescue;
extern int   single;
extern int   bootstrap;
extern int   kerndebug;
extern int   syncsec;
extern int   wdtreboot;
extern int   readiness;
extern char *fstab;
extern char *sdown;
extern char *network;
extern char *hostname;
extern char *runparts;
extern char *osheading;

extern int logfile_size_max;
extern int logfile_count_max;

extern struct rlimit global_rlimit[];
extern char cgroup_current[];

int   str2rlim(char *str);
char *rlim2str(int rlim);

int  conf_init            (uev_ctx_t *ctx);
void conf_reload          (void);
int  conf_any_change      (void);
int  conf_changed         (char *file);
int  conf_monitor         (void);

void conf_reset_env       (void);
void conf_saverc          (void);
void conf_save_exec_order (svc_t *svc, char *cmdline, int result);
void conf_save_service    (int type, char *cfg, char *file);
void conf_parse_cmdline   (int argc, char *argv[]);
char *conf_parse_env      (char *line, char **val);
int  conf_parse_runlevels (char *runlevels);
void conf_parse_cond      (svc_t *svc, char *cond);

#endif	/* FINIT_CONF_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
