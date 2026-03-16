/* Scans /etc/modules-load.d for modules to load.
 *
 * Copyright (c) 2018  Robert Andersson <robert.m.andersson@se.atlascopco.com>
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

/*
 * This plugin scans files in /etc/modules-load.d/, for each line in the
 * file it assumes the name of a kernel module, with optional arguments.
 * Each module is loaded when entering runlevel 2, 3, 4, or 5, using the
 * modprobe tool.
 *
 * Loading is done by inserting a `task` stanza in Finit, ensuring all
 * modules are loaded in parallel, with other modules and programs.
 * Each `task` stanza is by default given the name:modprobe.module and
 * indexed with `:ID`, starting with 1.
 *
 * Indexing can be disabled per file in /etc/modules-load.d/, anywwhere
 * in a file, by putting the keyword `noindex` on a line of its own.  A
 * noindex command can appear anywhere in the file, and up to the point
 * it is read, tasks will be indexed with an incrementing `:ID`.  When
 * `noindex` is read indexing is disabled and all subseequent tasks will
 * not have any `:ID` at all.
 *
 * Please note, the :ID is there for your benefit, it ensures that tasks
 * in Finit are unique.  If you have two tasks with the same name and ID
 * (or no ID), the last one read replaces any preceding one!
 */

#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#ifdef _LIBITE_LITE
# include <libite/lite.h>
#else
# include <lite/lite.h>
#endif

#include "finit.h"
#include "helpers.h"
#include "plugin.h"
#include "service.h"
#include "conf.h"
#include "log.h"

#ifndef MODULES_LOAD_PATH
#define MODULES_LOAD_PATH "/etc/modules-load.d"
#endif
#define MODPROBE_PATH     "/sbin/modprobe"
#define SERVICE_LINE \
	"cgroup.init name:modprobe.%s :%d [%s] %s %s %s --"
#define SERVICE_LINE_NOINDEX \
	"cgroup.init name:modprobe.%s [%s] %s %s %s --"

static int modules_load(const char *file, int index)
{
	char module_path[PATH_MAX];
	char *modprobe_path;
	int num = 0;
	char *line;
	char *lvl;
	FILE *fp;

	strlcpy(module_path, MODULES_LOAD_PATH "/", sizeof(module_path));
	strlcat(module_path, file, sizeof(module_path));

	fp = fopen(module_path, "r");
	if (!fp) {
		warnx("failed opening %s for reading, skipping ...", module_path);
		return 0;
	}

	modprobe_path = strdup(MODPROBE_PATH);
	if (!modprobe_path) {
	fail:
		warnx("failed allocating memory in modules-load plugin.");
		fclose(fp);
		return -1;
	}

	lvl = strdup("S");
	if (!lvl) {
		free(modprobe_path);
		goto fail;
	}

	while ((line = fparseln(fp, NULL, NULL, NULL, 0))) {
		char cmd[CMD_SIZE], *mod, *args, *set;

		/*
		 * fparseln() skips regular UNIX comments only.
		 * This is for modules-load.d(5) compat.
		 */
		if (line[0] == ';')
			goto next;

		/* trim whitespace */
		mod = strip_line(line);
		if (!mod[0])
			goto next;

		/* Finit extension 'set foo bar' */
		if ((set = fgetval(mod, "set", "= \t"))) {
			char *val = mod;

			if (!strcmp(set, "noindex")) {
				index = 0;
				free(set);
				goto next;
			}

			if ((val = fgetval(set, "index", "= \t"))) {
				index = atoi(val);
				free(set);
				free(val);
				goto next;
			}

			if ((val = fgetval(set, "runlevel", "= \t"))) {
				free(lvl);
				lvl = val;
				free(set);
				goto next;
			}

			if ((val = fgetval(set, "modprobe", "= \t"))) {
				if (access(val, X_OK)) {
					warn("%s: cannot use %s", module_path, val);
					free(set);
					free(val);
					free(line);
					goto skip;
				} else {
					free(modprobe_path);
					modprobe_path = val;
				}
				free(set);
				goto next;
			}

			/* unknown 'set' command, ignore. */
			goto next;
		}

		mod = strtok_r(mod, " ", &args);
		if (!mod)
			goto next;

		if (!index)
			snprintf(cmd, sizeof(cmd), SERVICE_LINE_NOINDEX, mod, lvl, modprobe_path, mod, args);
		else
			snprintf(cmd, sizeof(cmd), SERVICE_LINE, mod, index++, lvl, modprobe_path, mod, args);

		dbg("task %s", cmd);
		service_register(SVC_TYPE_TASK, cmd, global_rlimit, NULL);
		num++;
	next:
		free(line);
	}
skip:
	free(modprobe_path);
	free(lvl);
	fclose(fp);

	return num;
}

/* XXX: check here for .conf only? */
static int module_filter(const struct dirent *d)
{
	if (d->d_type == DT_DIR)
		return 0;
	if (d->d_name[0] == '.')
		return 0;	/* skip dot files */
	if (d->d_name[strlen(d->d_name) - 1] == '~')
		return 0;	/* skip backup files */

	return 1;
}

static void load(void *arg)
{
	struct dirent **dentry;
	int index = 1;
	int i, num;

	dbg("Scanning " MODULES_LOAD_PATH " for config files ...");
	num = scandir(MODULES_LOAD_PATH, &dentry, module_filter, alphasort);
	if (num > 0) {
		for (i = 0; i < num; i++) {
			index += modules_load(dentry[i]->d_name, index);
			free(dentry[i]);
		}
		free(dentry);
	}
}

static plugin_t plugin = {
	.name = "modules-load",
	.hook[HOOK_SVC_PLUGIN] = { .cb  = load },
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
