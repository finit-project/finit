/* Condition engine (write)
 *
 * Copyright (c) 2015-2017  Tobias Waldekranz <tobias@waldekranz.com>
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

#include <dirent.h>
#include <ftw.h>
#include <libgen.h>
#include <stdio.h>
#ifdef _LIBITE_LITE
# include <libite/lite.h>
#else
# include <lite/lite.h>
#endif

#include "finit.h"
#include "cond.h"
#include "pid.h"
#include "service.h"
#include "sm.h"

#ifdef HAVE_DBUS
/* Forward-declared locally to keep cond-w.c independent of the
 * daemon's private.h (which pulls in svc/plugin headers).  The full
 * prototype lives in private.h for callers in finit's main loop. */
void dbus_notify_condition_change(const char *name, const char *state);
#endif

struct cond_boot {
	TAILQ_ENTRY(cond_boot) link;
	char *name;
};
static TAILQ_HEAD(, cond_boot) cond_boot_list = TAILQ_HEAD_INITIALIZER(cond_boot_list);


/*
 * Parse finit.cond=cond[,cond[,...]] from command line.  It creates a
 * temporary linked list of conds which are freed when finit reaches
 * cond_init(), which calls cond_boot_strap() to realize the conditions
 * in the file system as regular static conditions.  Policy, however,
 * dictates that these are read-only and should not be possible to
 * manage from initctl.
 */
void cond_boot_parse(char *arg)
{
	struct cond_boot *node;

	if (!arg)
		return;

	node = malloc(sizeof(*node));
	if (!node) {
		err(1, "Out of memory cannot track boot conditions");
		return;
	}

	node->name = strdup(arg);
	TAILQ_INSERT_HEAD(&cond_boot_list, node, link);
}

/*
 * Convert all conditions read from the kernel command line (above) into
 * proper finit conditions.
 */
static void cond_boot_strap(void)
{
	struct cond_boot *node, *tmp;

	TAILQ_FOREACH_SAFE(node, &cond_boot_list, link, tmp) {
		TAILQ_REMOVE(&cond_boot_list, node, link);
		if (node->name) {
			char *ptr;

			ptr = strtok(node->name, ",");
			while (ptr) {
				char cond[strlen(ptr) + 6];

				if (strncmp(ptr, "boot/", 5))
					snprintf(cond, sizeof(cond), "boot/%s", ptr);
				else
					snprintf(cond, sizeof(cond), "%s", ptr);
				cond_set_oneshot_noupdate(cond);

				ptr = strtok(NULL, ",");
			}

			free(node->name);
		}
		free(node);
	}
}

/*
 * The service condition name is constructed from the 'pid/' prefix and
 * the unique NAME:ID tuple that identify each process in Finit.  Here
 * are a few examples:
 *
 * The Linux aggregate helper teamd creates PID files in a subdirectory,
 * /run/teamd/lag1.pid:
 *
 *    service teamd -f /etc/teamd/lag1.conf -- Aggregate lag1
 *
 *    => 'pid/' + 'teamd' + '' = condition <pid/teamd>
 *
 * When you add a second aggregate you need to tell Finit it's a different
 * instance usugin the :ID syntax:
 *
 *    service :lag2 teamd -f /etc/teamd/lag2.conf -- Aggregate lag2
 *
 *    => 'pid/' + 'teamd' + ':lag2' = condition <pid/teamd:lag2>
 *
 * The next example is for the dbus-daemon.  It also use a subdirectory,
 * /run/dbus/pid:
 *
 *    service dbus-daemon -- DBus daemon
 *
 *    => 'pid/' + 'dbus-daemon' = condition <pid/dbus-daemon>
 *
 * The last example uses lxc-start to start container foo, again in a
 * subdirectory, /run/lxc/foo.pid.  We set an ID to be user-friendly to
 * ourselves and override the name usually derivedd using the basename
 * of the path:
 *
 *    service name:lxc :foo lxc-start -n foo -F -p /run/lxc/foo.pid -- Container foo
 *
 *    => 'pid/' + 'lxc' + ':foo' = condition <pid/lxc:foo>
 */
char *mkcond(svc_t *svc, char *buf, size_t len)
{
	char ident[sizeof(svc->name) + sizeof(svc->id) + 2];

	snprintf(buf, len, "pid/%s", svc_ident(svc, ident, sizeof(ident)));

	return buf;
}

/*
 * Assert or clear every condition a service owns: its own pid/<ident>
 * and anything it declares with provides.  Each site that owns a
 * service's conditions goes through these, so the two cannot drift.
 */
void svc_cond_set(svc_t *svc)
{
	char buf[MAX_COND_LEN];
	const char *cond;
	int i = 0;

	while ((cond = svc_cond_nth(svc, i++, buf, sizeof(buf))))
		cond_set(cond);
}

void svc_cond_clear(svc_t *svc)
{
	char buf[MAX_COND_LEN];
	const char *cond;
	int i = 0;

	while ((cond = svc_cond_nth(svc, i++, buf, sizeof(buf))))
		cond_clear(cond);
}

static int cond_set_gen(const char *file, unsigned int gen)
{
	char *ptr, path[256];
	FILE *fp;
	int ret;

	/* /var/run --> /run symlink may not exist (yet) */
	ptr = pid_runpath(file, path, sizeof(path));

	fp = fopen(ptr, "w");
	if (!fp)
		return -1;

	ret = fprintf(fp, "%u\n", gen);
	fclose(fp);

	return (ret > 0) ? 0 : ret;
}

static void cond_bump_reconf(void)
{
	unsigned int rgen;

	/*
	 * If %_PATH_RECONF does not exist, cond_get_gen() returns 0
	 * meaning that rgen++ is always what we want.
	 */
	rgen = cond_get_gen(_PATH_RECONF);
	rgen++;

	if (cond_set_gen(_PATH_RECONF, rgen))
		err(1, "Failed setting %s to gen %d", _PATH_RECONF, rgen);
}

static int cond_checkpath(const char *path)
{
	char buf[MAX_COND_LEN + sizeof(_PATH_COND)], *dir;

	strlcpy(buf, path, sizeof(buf));
	dir = dirname(buf);
	if (!dir) {
		errx(1, "Invalid path '%s' for condition", path);
		return 1;
	}

	if (mkpath(dir, 0755) && errno != EEXIST) {
		err(1, "Failed creating dir '%s' for condition '%s'", dir, path);
		return 1;
	}

	return 0;
}

static int do_delete(const char *fpath, const struct stat *sb, int tflag, struct FTW *ftw)
{
	const char *cond, *ptr;

	(void)sb;
	(void)tflag;

	if (ftw->level == 0)
		return 1;

	ptr = strstr(fpath, COND_BASE);
	if (!ptr) {
		warnx("%s does not seem to be a Finit condition, skipping", fpath);
		return 0;
	}

	if (remove(fpath))
		err(1, "Failed removing condition %s", fpath);

	cond = ptr + strlen(COND_BASE) + 1;
	if (sm_in_reload())
		cond_clear_noupdate(cond);
	else
		cond_update(cond);

	return 0;
}

static void cond_delpath(const char *path)
{
	nftw(path, do_delete, 20, FTW_DEPTH);
	if (remove(path)) {
		switch (errno) {
		case ENOENT:	/* Ignore */
		case ENOTEMPTY:	/* Only at shutdown and for directories */
			break;
		default:
			err(1, "Failed removing condition path %s", path);
			break;
		}
	}
}

int cond_set_path(const char *path, enum cond_state next)
{
	enum cond_state prev;
	unsigned int rgen;

	dbg("%s <= %d", path, next);
	prev = cond_get_path(path);

	switch (next) {
	case COND_ON:
		if (cond_checkpath(path))
		    return 0;

		rgen = cond_get_gen(_PATH_RECONF);
		if (!rgen) {
			errx(1, "Unable to read configuration generation (%s)", path);
			return -1;
		}
		cond_set_gen(path, rgen);
		break;

	case COND_OFF:
		if (unlink(path)) {
			switch (errno) {
			case ENOENT:
				break;
			case EISDIR:
				cond_delpath(path);
				break;
			default:
				err(1, "Failed removing condition '%s'", path);
				break;
			}
		}
		break;

	default:
		errx(1, "Invalid condition state");
		return 0;
	}

	return next != prev;
}

/* Should only be used by cond_set*(), cond_clear(), and usr/sys plugins! */
int cond_update(const char *name)
{
	svc_t *svc, *iter = NULL;
	int affects = 0;

//	dbg("%s", name);
	for (svc = svc_iterator(&iter, 1); svc; svc = svc_iterator(&iter, 0)) {
		if (!svc_has_cond(svc) || !cond_affects(name, svc->cond))
			continue;

		affects++;
		dbg("%s: match <%s> %s(%s)", name ?: "nil", svc->cond, svc->desc, svc->cmd);
		/* Fix bug #314: race condition between crashing services and conditions */
		if (svc_is_restart(svc) && cond_get_agg(svc->cond) == COND_OFF) {
			dbg("%s: cancel timer & unblock => WAITING state.", name ?: "nil");
			service_timeout_cancel(svc);
			svc_unblock(svc);
		}
		service_step(svc);
	}

	return affects;
}

int cond_set_noupdate(const char *name)
{
	dbg("%s", name);
	if (string_compare(name, "nop"))
		return 1;

	if (!cond_set_path(cond_path(name), COND_ON))
		return 1;

	return 0;
}

void cond_set(const char *name)
{
//	dbg("%s", name);
	if (cond_set_noupdate(name))
		return;

#ifdef HAVE_DBUS
	dbus_notify_condition_change(name, "on");
#endif
	cond_update(name);
}

int cond_set_oneshot_noupdate(const char *name)
{
	const char *path;

	if (string_compare(name, "nop"))
		return 1;

	path = cond_path(name);
	dbg("%s => %s", name, path);

	if (cond_checkpath(path))
		return 1;

	if (symlink(_PATH_RECONF, path) && errno != EEXIST) {
		err(1, "Failed creating onshot cond %s", name);
		return 1;
	}

	return 0;
}

void cond_set_oneshot(const char *name)
{
	dbg("%s", name);
	if (cond_set_oneshot_noupdate(name))
		return;

#ifdef HAVE_DBUS
	dbus_notify_condition_change(name, "on");
#endif
	cond_update(name);
}

int cond_clear_noupdate(const char *name)
{
	dbg("%s", name);
	if (string_compare(name, "nop"))
		return 1;

	if (!cond_set_path(cond_path(name), COND_OFF))
		return 1;

	return 0;
}

void cond_clear(const char *name)
{
//	dbg("%s", name);
	if (cond_clear_noupdate(name))
		return;

#ifdef HAVE_DBUS
	dbus_notify_condition_change(name, "off");
#endif
	cond_update(name);
}

void cond_reload(void)
{
	dbg("");

	cond_bump_reconf();
}

static int do_assert(const char *fpath, const struct stat *sb, int tflg, struct FTW *ftw, int set)
{
	char *nm;

	(void)sb;

	if (ftw->level == 0)
		return 1;

	if (tflg != FTW_F)
		return 0;

	nm = strstr((char *)fpath, COND_BASE);
	if (!nm) {
		errx(1, "Incorrect condition path %s, cannot %sassert", fpath, set ? "re" : "de");
		return 1;
	}

	nm += strlen(COND_BASE);
	dbg("%sasserting %s => %s", set ? "Re" : "De", fpath, nm);
	if (set)
		cond_set(nm);
	else
		cond_clear_noupdate(nm); /* important, see netlink plugin! */

	return 0;
}

static int reassert(const char *fpath, const struct stat *sb, int tflg, struct FTW *ftw)
{
	return do_assert(fpath, sb, tflg, ftw, 1);
}

static int deassert(const char *fpath, const struct stat *sb, int tflg, struct FTW *ftw)
{
	return do_assert(fpath, sb, tflg, ftw, 0);
}

/*
 * Used only by netlink plugin atm.
 * type: is a one of pid/, net/, etc.
 */
void cond_reassert(const char *pat)
{
	dbg("%s", pat);
	nftw(cond_path(pat), reassert, 20, FTW_DEPTH);
}

/*
 * Used only by netlink plugin atm.
 */
void cond_deassert(const char *pat)
{
	dbg("%s", pat);
	nftw(cond_path(pat), deassert, 20, FTW_DEPTH);
}

/*
 * Check if we have bootstrapped enough of the system to use conditions.
 * Will answer 'No' before bootstrap done *and* at shutdown/reboot.
 */
int cond_is_available(void)
{
	return fisdir(_PATH_COND);
}

void cond_init(void)
{
	char path[MAX_ARG_LEN];

	if (mkpath(pid_runpath(_PATH_COND, path, sizeof(path)), 0755) && errno != EEXIST) {
		err(1, "Failed creating condition base directory '%s'", _PATH_COND);
		return;
	}

	cond_bump_reconf();
	cond_boot_strap();
}

void cond_exit(void)
{
	cond_delpath(_PATH_COND);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
