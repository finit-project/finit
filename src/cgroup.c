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

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#ifdef _LIBITE_LITE
# include <libite/lite.h>
# include <libite/queue.h>	/* BSD sys/queue.h API */
#else
# include <lite/lite.h>
# include <lite/queue.h>	/* BSD sys/queue.h API */
#endif
#include <sys/mount.h>
#include <sys/sysinfo.h>		/* get_nprocs_conf() */
#include <sys/vfs.h>
#include <linux/magic.h>

#include "cgroup.h"
#include "finit.h"
#include "iwatch.h"
#include "conf.h"
#include "service.h"
#include "log.h"
#include "util.h"

struct cg {
	TAILQ_ENTRY(cg) link;

	char *name;		/* top-level group name */
	char *cfg;		/* kernel settings */

	int  active;		/* for mark & sweep */
	int  is_protected;	/* for init/, user/, & system/ */
};

static TAILQ_HEAD(, cg) cgroups = TAILQ_HEAD_INITIALIZER(cgroups);

static char controllers[256];

static struct iwatch iw_cgroup;
static uev_t cgw;
static int avail;


/*
 * Set up inotify watch on cgroup for automatic cleanup when empty.
 * Should be called after cgroup_prepare() but before process starts.
 */
int cgroup_watch(const char *group, const char *name)
{
	char path[256];
	int rc;

	if (!avail)
		return 0;

	/* Special case: root cgroup has no separate events file to watch */
	if (!strcmp(group, "root"))
		return 0;

	snprintf(path, sizeof(path), "/sys/fs/cgroup/%s/%s/cgroup.events", group, name);
	rc = iwatch_add(&iw_cgroup, path, 0);
	if (rc < 0) {
		warn("Failed setting up inotify watch on %s", path);
		return -1;
	}

	dbg("Watching %s for automatic cleanup", path);
	return 0;
}

/*
 * Derive cgroup name from service (mirrors group_name() in service.c)
 * For use by plugins that need to determine the cgroup path.
 *
 * MUST return the same value that group_name() in service.c returns!
 */
char *cgroup_svc_name(svc_t *svc, char *buf, size_t len)
{
	char *ptr;

	/* Use explicit cgroup leaf name if specified */
	if (svc->cgroup.leafname[0]) {
		strlcpy(buf, svc->cgroup.leafname, len);
		return buf;
	}

	if (!svc->file[0])
		return svc_ident(svc, buf, len);

	ptr = strrchr(svc->file, '/');
	if (ptr)
		ptr++;
	else
		ptr = svc->file;

	strlcpy(buf, ptr, len);

	/* Strip .conf extension - this gives us the cgroup name */
	ptr = strstr(buf, ".conf");
	if (ptr)
		*ptr = 0;

	return buf;
}

/*
 * Helper function to move a PID to a service's cgroup.
 * @group:    Top-level cgroup (e.g., "system", "user", "maint")
 * @name:     Service-specific cgroup name (e.g., "dockerd", "nginx")
 * @pid:      Process ID to move
 * @delegate: If 1, handle potential EBUSY by using supervisor/ subdirectory
 *
 * Useful for forking services where child PIDs need to be moved after they appear.
 *
 * For delegated cgroups, handles the cgroups v2 "no internal processes" rule:
 * if the parent has child cgroups, tries to reuse process-named subdirectory or
 * falls back to supervisor/ subdirectory.
 *
 * Returns: 0 on success, -1 on failure
 */
int cgroup_move_pid(const char *group, const char *name, int pid, int delegate)
{
	int rc = 0, reuse = 0;
	char path[512];

	if (!avail)
		return 0;

	/* Sanity checks */
	if (!group || !name || pid <= 0) {
		errno = EINVAL;
		return -1;
	}

	/* Disallow path traversal */
	if (strstr(group, "..") || strstr(name, "..") ||
	    strchr(group, '/') || strchr(name, '/')) {
		errno = EINVAL;
		warn("Invalid cgroup path components: group=%s name=%s", group, name);
		return -1;
	}

	snprintf(path, sizeof(path), FINIT_CGPATH "/%s/%s", group, name);
	if (!fisdir(path)) {
		warn("Cgroup %s does not exist", path);
		return -1;
	}

	if ((rc = fnwrite(str("%d", pid), "%s/cgroup.procs", path))) {
		/*
		 * EBUSY means the cgroup has children (cgroups v2 "no internal processes" rule).
		 * For delegated cgroups, fall back to subdirectory.
		 */
		if (errno == EBUSY && delegate) {
			char comm[64];

			/* Check if subdirectory matching process name, e.g., conmon, exists */
			readsnf(comm, sizeof(comm), "/proc/%d/comm", pid);
			strlcat(path, "/", sizeof(path));
			strlcat(path, comm, sizeof(path));
			if (fisdir(path))
				reuse = 1;
			else
				snprintf(path, sizeof(path), FINIT_CGPATH "/%s/%s/supervisor", group, name);

			rc = fnwrite(str("%d", pid), "%s/cgroup.procs", path);
		}

		if (rc) {
			if (errno != ESRCH)
				warn("Failed moving pid %d to cgroup %s", pid, path);
			return -1;
		}
	}

	if (reuse) {
		snprintf(path, sizeof(path), FINIT_CGPATH "/%s/%s/supervisor", group, name);
		rmdir(path);
	}

	return 0;
}

int cgroup_move_svc(svc_t *svc)
{
	const char *group = "system";
	char name[MAX_ARG_LEN];

	if (!avail || !svc)
		return 0;

	if (svc->cgroup.name[0])
		group = svc->cgroup.name;

	return cgroup_move_pid(group, cgroup_svc_name(svc, name, sizeof(name)),
			       svc->pid, svc->cgroup.delegate);
}

static void cgset(const char *path, char *ctrl, char *prop)
{
	char *val;

	dbg("path %s, ctrl %s, prop %s", path ?: "NIL", ctrl ?: "NIL", prop ?: "NIL");
	if (!path || !ctrl) {
		errx(1, "Missing path or controller, skipping!");
		return;
	}

	if (!prop) {
		prop = strchr(ctrl, '.');
		if (!prop) {
			errx(1, "Invalid cgroup ctrl syntax: %s", ctrl);
			return;
		}

		*prop++ = 0;
	}

	val = strchr(prop, ':');
	if (!val) {
		errx(1, "Missing cgroup ctrl value, prop %s", prop);
		return;
	}
	*val++ = 0;

	/* unquote value, if quoted */
	if (unquote(&val, NULL)) {
		errx(1, "Syntax error, unterminated quote in %s/%s.%s=%s", path, ctrl, prop, val);
		return;
	}

	/* disallow sneaky relative paths */
	if (strstr(ctrl, "..") || strstr(prop, "..")) {
		errx(1, "Possible security violation; '..' not allowed in cgroup config!");
		return;
	}

	dbg("%s/%s.%s <= %s", path, ctrl, prop, val);
	if (fnwrite(val, "%s/%s.%s", path, ctrl, prop))
		err(1, "Failed setting %s/%s.%s = %s", path, ctrl, prop, val);
}

/*
 * Settings for a cgroup are on the form: cpu.weight:1234,mem.max:4321,...
 * Finit supports the short-form 'mem.', replacing it with 'memory.' when
 * writing the setting to the file system.
 */
static void group_init(char *path, int leaf, const char *cfg)
{
	char *ptr, *s;

	dbg("path %s, leaf %d, cfg %s", path, leaf, cfg ?: "NIL");
	if (!fisdir(path)) {
		if (mkdir(path, 0755)) {
			err(1, "Failed creating cgroup %s", path);
			return;
		}

		/* enable detected controllers on domain groups */
		if (!leaf && fnwrite(controllers, "%s/cgroup.subtree_control", path))
			err(1, "Failed enabling %s for %s", controllers, path);
	}

	if (!cfg || !cfg[0])
		return;

	s = strdupa(cfg);
	if (!s) {
		err(1, "Failed activating cgroup cfg for %s", path);
		return;
	}

	dbg("%s <=> %s", path, s);
	ptr = strtok(s, ",");
	while (ptr) {
		dbg("ptr: %s", ptr);
		if (!strncmp("mem.", ptr, 4))
			cgset(path, "memory", &ptr[4]);
		else
			cgset(path, ptr, NULL);

		ptr = strtok(NULL, ",");
	}
}

static int cgroup_create(const char *group, const char *name, const char *cfg,
			 int delegate, const char *username, const char *grpname,
			 char *pathbuf, size_t pathlen)
{
	char path[256];

	snprintf(path, sizeof(path), "/sys/fs/cgroup/%s/%s", group, name);

	if (delegate) {
		char initpath[PATH_MAX];

		/* For delegation, create as domain group (not leaf) */
		group_init(path, 0, cfg);

		/* Enable controllers for delegation */
		if (fnwrite(controllers, "%s/cgroup.subtree_control", path))
			warn("Failed enabling controllers in %s for delegation", path);

		/* Change ownership of delegation files */
		if (username && username[0] && grpname && grpname[0]) {
			uid_t uid = getuser(username, NULL);
			gid_t gid = getgroup(grpname);

			if (uid != (uid_t)-1 && gid != (gid_t)-1) {
				char filepath[PATH_MAX];
				char *files[] = {
					"cgroup.procs",
					"cgroup.subtree_control",
					"cgroup.threads",
					"cgroup.type",
					NULL
				};

				for (int i = 0; files[i]; i++) {
					snprintf(filepath, sizeof(filepath), "%s/%s", path, files[i]);
					if (chown(filepath, uid, gid))
						warn("Failed chown %s to %d:%d", filepath, uid, gid);
				}
			}
		}

		snprintf(initpath, sizeof(initpath), "%s/supervisor", path);
		group_init(initpath, 1, NULL);
		strlcpy(path, initpath, sizeof(path));
	} else {
		/* Normal leaf cgroup */
		group_init(path, 1, cfg);
	}

	if (!fisdir(path)) {
		warn("Cgroup directory %s doesn't exist after creation", path);
		return -1;
	}

	/* Return the path to caller if they provided a buffer */
	if (pathbuf && pathlen > 0)
		strlcpy(pathbuf, path, pathlen);

	return cgroup_watch(group, name);
}

static int cgroup_leaf_init(const char *group, const char *name, int pid, const char *cfg,
			    int delegate, const char *username, const char *grpname)
{
	dbg("group %s, name %s, pid %d, cfg %s, delegate %d", group, name, pid, cfg ?: "NIL", delegate);
	if (cgroup_create(group, name, cfg, delegate, username, grpname, NULL, 0))
		return -1;

	dbg("Assigning PID %d to cgroup %s/%s", pid, group, name);

	/* Special case: "root" cgroup means the actual cgroup root */
	if (!strcmp(group, "root"))
		return fnwrite(str("%d", pid), FINIT_CGPATH "/cgroup.procs");

	/* Error if error is not "No such process" */
	if (cgroup_move_pid(group, name, pid, delegate) && errno != ESRCH)
		err(1, "Failed moving pid %d to group %s/%s", pid, group, name);

	/* Set up inotify watch for cgroup cleanup */
	return cgroup_watch(group, name);
}

int cgroup_user(const char *name, int pid)
{
	if (!avail)
		return 0;

	return cgroup_leaf_init("user", name, pid, NULL, 0, NULL, NULL);
}

int cgroup_service(const char *name, int pid, struct cgroup *cg, char *username, char *grpname)
{
	char *group = "system";
	int delegate = 0;

	if (!avail)
		return 0;

	if (cg && cg->name[0]) {
		char path[256];

		if (!strcmp(cg->name, "root"))
			return fnwrite(str("%d", pid), FINIT_CGPATH "/cgroup.procs");

		if (!strcmp(cg->name, "init"))
			return fnwrite(str("%d", pid), FINIT_CGPATH "/init/cgroup.procs");

		snprintf(path, sizeof(path), "/sys/fs/cgroup/%s", cg->name);
		if (fisdir(path))
			group = cg->name;

		delegate = cg->delegate;
	}

	return cgroup_leaf_init(group, name, pid, cg ? cg->cfg : NULL, delegate, username, grpname);
}

/* Create cgroup for the requested type of service, return fd to cgroup for clone3() */
int cgroup_prepare(svc_t *svc, const char *name)
{
	const char *group;
	const char *cfg = NULL;
	const char *username = NULL;
	const char *grpname = NULL;
	int delegate = 0;
	char path[256];
	int fd = -1;

	if (!avail)
		return -1;

	if (!name) {
		errno = EINVAL;
		return -1;
	}

	if (!svc) {
		/* Helper process (e.g., networking) */
		group = "system";
	} else if (svc_is_tty(svc)) {
		/* TTY/getty services go in user cgroup */
		group = "user";
	} else if (svc->cgroup.name[0] && !strcmp(svc->cgroup.name, "root")) {
		/* Special case: SCHED_RR processes go in root cgroup */
		fd = open("/sys/fs/cgroup", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (fd < 0)
			warn("Failed opening root cgroup");

		return fd;
	} else {
		/* Regular service */
		group = svc->cgroup.name[0] ? svc->cgroup.name : "system";
		cfg = svc->cgroup.cfg;
		delegate = svc->cgroup.delegate;
		username = svc->username;
		grpname = svc->group;
	}

	/* Create the cgroup and get the path back */
	if (cgroup_create(group, name, cfg, delegate, username, grpname, path, sizeof(path)))
		return -1;

	/* Open and return fd for clone3() */
	fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		warn("Failed opening cgroup %s", path);

	return fd;
}

static void append_ctrl(char *ctrl)
{
	if (controllers[0])
		strlcat(controllers, " ", sizeof(controllers));

	strlcat(controllers, "+", sizeof(controllers));
	strlcat(controllers, ctrl, sizeof(controllers));
}

static void cgroup_handle_event(char *event, uint32_t mask)
{
	char path[strlen(event) + 1];
	char buf[80];
	char *ptr;
	FILE *fp;

	dbg("event: '%s', mask: %08x", event, mask);
	if (!(mask & IN_MODIFY))
		return;

	fp = fopen(event, "r");
	if (!fp) {
		dbg("Failed opening %s, skipping ...", event);
		return;
	}

	while (fgets(buf, sizeof(buf), fp)) {
		if (strncmp(buf, "populated", 9))
			continue;

		chomp(buf);
		if (atoi(&buf[10]))
			break;

		strlcpy(path, event, sizeof(path));
		ptr = strrchr(path, '/');
		if (ptr) {
			*ptr = 0;
			if (!cgroup_del(path)) {
				/*
				 * try with parent, top-level group, we
				 * may get events out-of-order *sigh*
				 */
				ptr = strrchr(path, '/');
				if (!ptr)
					break;
				*ptr = 0;
				cgroup_del(path);
			}
		}

		break;
	}

	fclose(fp);
}

static void cgroup_events_cb(uev_t *w, void *arg, int events)
{
	static char ev_buf[8 *(sizeof(struct inotify_event) + NAME_MAX + 1) + 1];
	struct inotify_event *ev;
	ssize_t sz;
	size_t off;

	(void)arg;
	if (UEV_ERROR == events) {
		dbg("%s(): inotify socket %d invalid.", __func__, w->fd);
		return;
	}

	sz = read(w->fd, ev_buf, sizeof(ev_buf) - 1);
	if (sz <= 0) {
		err(1, "invalid inotify event");
		return;
	}
	ev_buf[sz] = 0;

	for (off = 0; off < (size_t)sz; off += sizeof(*ev) + ev->len) {
		struct iwatch_path *iwp;

		if (off + sizeof(*ev) > (size_t)sz)
			break;

		ev = (struct inotify_event *)&ev_buf[off];
		if (off + sizeof(*ev) + ev->len > (size_t)sz)
			break;

		if (!ev->mask)
			continue;

		/* Find base path for this event */
		iwp = iwatch_find_by_wd(&iw_cgroup, ev->wd);
		if (!iwp || !iwp->path)
			continue;

		cgroup_handle_event(iwp->path, ev->mask);
	}

#ifdef AUTO_RELOAD
	if (conf_any_change())
		sm_reload();
#endif
}

static struct cg *cgroup_find(char *name)
{
	struct cg *cg;

	TAILQ_FOREACH(cg, &cgroups, link) {
		if (strcmp(cg->name, name))
			continue;

		return cg;
	}

	return NULL;
}

/*
 * Marks all unprotected cgroups for deletion (during reload)
 */
void cgroup_mark_all(void)
{
	struct cg *cg;

	if (!avail)
		return;

	TAILQ_FOREACH(cg, &cgroups, link) {
		if (cg->is_protected)
			continue;

		cg->active = 0;
	}
}

/*
 * Remove (try to) all unused cgroups
 */
void cgroup_cleanup(void)
{
	struct cg *cg, *tmp;
	char path[256];

	if (!avail)
		return;

	TAILQ_FOREACH_SAFE(cg, &cgroups, link, tmp) {
		if (cg->active)
			continue;

		snprintf(path, sizeof(path), FINIT_CGPATH "/%s", cg->name);
		cgroup_del(path);
	}
}

/*
 * Add, or update, settings for top-level cgroup
 */
int cgroup_add(char *name, char *cfg, int is_protected)
{
	struct cg *cg;

	if (!avail)
		return 0;

	if (!name)
		return -1;
	if (!cfg)
		cfg = "";

	cg = cgroup_find(name);
	if (!cg) {
		cg = malloc(sizeof(struct cg));
		if (!cg) {
			err(1, "Failed allocating 'struct cg' for %s", name);
			return -1;
		}
		cg->name = strdup(name);
		if (!cg->name) {
			err(1, "Failed setting cgroup name %s", name);
			free(cg);
			return -1;
		}
		TAILQ_INSERT_TAIL(&cgroups, cg, link);
	} else
		free(cg->cfg);

	cg->cfg = strdup(cfg);
	if (!cg->cfg) {
		err(1, "Failed add/update of cgroup %s", name);
		TAILQ_REMOVE(&cgroups, cg, link);
		free(cg->name);
		free(cg);
		return -1;
	}
	cg->is_protected = is_protected;
	cg->active = 1;

	return 0;
}

/*
 * Walk a cgroup directory and remove all empty subdirectories recursively.
 */
static void cgroup_prune_recursive(const char *path)
{
	struct dirent *d;
	DIR *dir;

	dir = opendir(path);
	if (!dir)
		return;

	while ((d = readdir(dir)) != NULL) {
		char subpath[PATH_MAX];

		if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
			continue;
		if (d->d_type != DT_DIR)
			continue;

		snprintf(subpath, sizeof(subpath), "%s/%s", path, d->d_name);
		cgroup_prune_recursive(subpath);
	}
	closedir(dir);

	/*
	 * Try to remove this directory. If it still has children or processes,
	 * rmdir() will fail with ENOTEMPTY/EBUSY - that's fine.
	 */
	if (rmdir(path) && errno != ENOTEMPTY && errno != EBUSY)
		warn("Failed to prune %s", path);
}

/*
 * Housekeeping: prune all empty cgroup subdirectories.
 * Called after runlevel transitions to clean up finished run/task cgroups.
 */
void cgroup_prune(void)
{
	struct dirent *entry;
	struct cg *cg;
	char path[256];
	DIR *dir;

	if (!avail)
		return;

	dbg("Pruning empty cgroup directories...");

	/* Walk through each top-level cgroup (init, system, user) */
	TAILQ_FOREACH(cg, &cgroups, link) {
		snprintf(path, sizeof(path), FINIT_CGPATH "/%s", cg->name);

		dir = opendir(path);
		if (!dir)
			continue;

		/* Check each subdirectory */
		while ((entry = readdir(dir)) != NULL) {
			char subpath[512];

			if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
				continue;
			if (entry->d_type != DT_DIR)
				continue;

			snprintf(subpath, sizeof(subpath), "%s/%s", path, entry->d_name);
			cgroup_prune_recursive(subpath);
		}
		closedir(dir);
	}
}

/*
 * Remove inactive top-level cgroup
 */
int cgroup_del(char *dir)
{
	struct cg *cg;
	char path[256];

	if (!avail)
		return 0;

	TAILQ_FOREACH(cg, &cgroups, link) {
		snprintf(path, sizeof(path), FINIT_CGPATH "/%s", cg->name);
		if (strcmp(path, dir))
			continue;

		if (cg->active)
			return -1;

		break;
	}

	if (rmdir(dir) && errno != ENOENT) {
		if (errno != EBUSY)
			warn("Failed rmdir(%s): %s", dir, strerror(errno));
		return -1;
	}

	if (cg) {
		TAILQ_REMOVE(&cgroups, cg, link);
		free(cg->name);
		free(cg->cfg);
		free(cg);
	}

	return 0;
}

/*
 * Delete cgroup for a service (convenience wrapper)
 */
int cgroup_del_svc(svc_t *svc, const char *name)
{
	const char *group;
	char path[256];

	if (!avail)
		return 0;

	/* Determine group from service */
	if (svc_is_tty(svc)) {
		group = "user";
	} else if (svc->cgroup.name[0] && !strcmp(svc->cgroup.name, "root")) {
		/* Root cgroup - nothing to delete */
		return 0;
	} else {
		group = svc->cgroup.name[0] ? svc->cgroup.name : "system";
	}

	snprintf(path, sizeof(path), "/sys/fs/cgroup/%s/%s", group, name);
	return cgroup_del(path);
}

/* the top-level init cgroup is a leaf, that's ensured in cgroup_init() */
void cgroup_config(void)
{
	struct cg *cg;

	if (!avail)
		return;

	TAILQ_FOREACH(cg, &cgroups, link) {
		char path[256];
		int leaf = 0;

		if (!cg->active)
			continue;
		if (!strcmp(cg->name, "init"))
			leaf = 1;	/* reserved */

		snprintf(path, sizeof(path), "%s/%s", FINIT_CGPATH, cg->name);
		group_init(path, leaf, cg->cfg);

		strlcat(path, "/cgroup.events", sizeof(path));
		iwatch_add(&iw_cgroup, path, 0);
	}
}

/*
 * Called by Finit at early boot to mount initial cgroups
 */
void cgroup_init(uev_ctx_t *ctx)
{
	int opts = MS_NODEV | MS_NOEXEC | MS_NOSUID;
	int mounted = 0;
	char buf[80];
	FILE *fp;
	int fd;

#ifndef CGROUP2_ENABLED
	avail = 0;
	return;
#endif

	if (mount("none", FINIT_CGPATH, "cgroup2", opts, NULL)) {
		if (errno == EBUSY) {
			/*
			 * Already mounted - this happens after switch_root
			 * when cgroups were moved from the initramfs.
			 * Verify it's actually cgroup2 before proceeding.
			 */
			struct statfs sfs;

			if (statfs(FINIT_CGPATH, &sfs) || sfs.f_type != CGROUP2_SUPER_MAGIC) {
				logit(LOG_ERR, "Mount point %s busy but not cgroup2", FINIT_CGPATH);
				avail = 0;
				return;
			}
			dbg("cgroup2 already mounted at %s, reusing", FINIT_CGPATH);
		} else if (errno == ENOENT) {
			logit(LOG_INFO, "Kernel does not support cgroups v2, disabling.");
			avail = 0;
			return;
		} else if (errno == EPERM) {
			/* Probably inside an unprivileged container */
			logit(LOG_INFO, "Not allowed to mount cgroups v2, disabling.");
			avail = 0;
			return;
		} else {
			err(1, "Failed mounting cgroup v2");
			avail = 0;
			return;
		}
	} else {
		mounted = 1;
	}
	avail = 1;

	/* Find available controllers */
	fp = fopen(FINIT_CGPATH "/cgroup.controllers", "r");
	if (!fp) {
		err(1, "Failed opening %s", FINIT_CGPATH "/cgroup.controllers");
	abort:
		if (mounted)
			umount(FINIT_CGPATH);
		avail = 0;
		return;
	}

	if (fgets(buf, sizeof(buf), fp)) {
		char *cgroup;

		cgroup = strtok(chomp(buf), "\t ");
		while (cgroup) {
			append_ctrl(cgroup);
			cgroup = strtok(NULL, "\t ");
		}
	}

	fclose(fp);

	/* Check for cpu controller, abort if missing */
	if (!strstr(controllers, "+cpu")) {
		logit(LOG_NOTICE, "Missing CPU controller, disabling cgroup support.");
		goto abort;
	}

	/* Enable all controllers */
	if (fnwrite(controllers, FINIT_CGPATH "/cgroup.subtree_control")) {
		err(1, "Failed enabling %s for %s", controllers, FINIT_CGPATH "/cgroup.subtree_control");
		goto abort;
	}

	/* prepare cgroup.events watcher */
	fd = iwatch_init(&iw_cgroup);
	if (fd == -1)
		goto abort;

	if (uev_io_init(ctx, &cgw, cgroup_events_cb, NULL, fd, UEV_READ)) {
		err(1, "Failed setting up cgroup.events watcher");
		iwatch_exit(&iw_cgroup);
		close(fd);
		goto abort;
	}

	/* Default (protected) groups, PID 1, services, and user/login processes */
	cgroup_add("init",   "cpu.weight:100",  1);
	cgroup_add("system", "cpu.weight:9800", 1);
	cgroup_add("user",   "cpu.weight:100",  1);
	cgroup_config();

	/* Move ourselves to init (best effort, otherwise run in 'root' group */
	if (fnwrite("1", FINIT_CGPATH "/init/cgroup.procs")) {
		err(1, "Failed moving PID 1 to cgroup %s", FINIT_CGPATH "/init");
		uev_io_stop(&cgw);
		iwatch_exit(&iw_cgroup);
		close(fd);
		goto abort;
	}
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
