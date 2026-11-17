/* Finit control group support functions
 *
 * Copyright (c) 2019-2025  Joachim Wiberg <troglobit@gmail.com>
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

#ifndef FINIT_CGROUP_H_
#define FINIT_CGROUP_H_

#include <uev/uev.h>

#define CGROUP_NAME_SIZE     16
#define CGROUP_SETTINGS_SIZE 128

/* Forward declaration */
typedef struct svc svc_t;

struct cgroup {
	char name[16];
	char cfg[128];
	char leafname[128];
	char delegate;
};

void  cgroup_mark_all(void);
void  cgroup_cleanup (void);

int   cgroup_add     (char *name, char *cfg, int is_protected);
int   cgroup_del     (char *dir);
int   cgroup_del_svc (svc_t *svc, const char *name);
void  cgroup_config  (void);

void  cgroup_init    (uev_ctx_t *ctx);

int   cgroup_user    (const char *name, int pid);
int   cgroup_service (const char *name, int pid, struct cgroup *cg, char *username, char *group);

char *cgroup_svc_name(svc_t *svc, char *buf, size_t len);
int   cgroup_prepare (svc_t *svc, const char *name);
int   cgroup_watch   (const char *group, const char *name);

int   cgroup_move_pid(const char *group, const char *name, int pid, int delegate);
int   cgroup_move_svc(svc_t *svc);
int   cgroup_svc_has (svc_t *svc);
int   cgroup_signal_svc(svc_t *svc, int sig);

void  cgroup_prune   (void);

#endif /* FINIT_CGROUP_H_ */
