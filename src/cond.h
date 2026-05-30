#ifndef FINIT_COND_H_
#define FINIT_COND_H_

#include <paths.h>

#include "svc.h"

#define COND_BASE      "finit/cond"
#define COND_DEV       "dev/"
#define COND_BIND      "bind/"
#define COND_CLASS     "class/"
#define COND_PID       "pid/"
#define COND_SYS       "sys/"
#define COND_USR       "usr/"

#define _PATH_COND     _PATH_VARRUN COND_BASE "/"
#define _PATH_CONDDEV  _PATH_COND   COND_DEV
#define _PATH_CONDBIND _PATH_COND   COND_BIND
#define _PATH_CONDCLASS _PATH_COND  COND_CLASS
#define _PATH_CONDPID  _PATH_COND   COND_PID
#define _PATH_CONDSYS  _PATH_COND   COND_SYS
#define _PATH_CONDUSR  _PATH_COND   COND_USR
#define _PATH_RECONF   _PATH_COND   "reconf"

typedef enum cond_state {
	COND_OFF = 0,
	COND_FLUX,
	COND_ON
} cond_state_t;

char           *mkcond       (svc_t *svc, char *buf, size_t len);
const char     *condstr      (enum cond_state s);
const char     *cond_path    (const char *name);
unsigned int    cond_get_gen (const char *path);
enum cond_state cond_get_path(const char *path);
enum cond_state cond_get     (const char *name);
enum cond_state cond_get_agg (const char *names);
int             cond_affects (const char *name, const char *names);

void cond_boot_parse  (char *arg);
int  cond_update      (const char *name);
int  cond_set_path    (const char *path, enum cond_state new);
void cond_set         (const char *name);
void cond_set_oneshot (const char *name);
void cond_clear       (const char *name);
void cond_reload      (void);

int  cond_set_noupdate(const char *name);
int  cond_set_oneshot_noupdate(const char *name);
int  cond_clear_noupdate(const char *name);

void cond_reassert    (const char *pat);
void cond_deassert    (const char *pat);

int  cond_is_available(void);

void cond_init        (void);
void cond_exit        (void);

#endif	/* FINIT_COND_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
