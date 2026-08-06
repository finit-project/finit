/* udev rules file parser for keventd
 *
 * Copyright (c) 2025  Joachim Wiberg <troglobit@gmail.com>
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

#ifndef KEVENTD_RULES_H_
#define KEVENTD_RULES_H_

#ifdef _LIBITE_LITE
# include <libite/queue.h>
#else
# include <lite/queue.h>
#endif

#include "keventd.h"

/* Operators from udev rules syntax */
typedef enum {
	OP_INVALID = 0,
	OP_MATCH_EQ,		/* == */
	OP_MATCH_NE,		/* != */
	OP_ASSIGN,		/* = */
	OP_ASSIGN_ADD,		/* += */
	OP_ASSIGN_DEL,		/* -= */
	OP_ASSIGN_FINAL,	/* := */
} rule_op_t;

/* All udev match and assignment key types */
typedef enum {
	KEY_UNKNOWN = 0,
	/* Match keys — current device */
	KEY_ACTION,
	KEY_DEVPATH,
	KEY_KERNEL,
	KEY_NAME,
	KEY_SUBSYSTEM,
	KEY_DRIVER,
	KEY_ATTR,		/* ATTR{filename} */
	KEY_SYSCTL,		/* SYSCTL{parameter} */
	KEY_ENV,		/* ENV{variable} */
	KEY_CONST,		/* CONST{key} */
	KEY_TAG,
	KEY_TEST,		/* TEST{mode} */
	KEY_PROGRAM,
	KEY_RESULT,
	/* Match keys — parent-chain walk */
	KEY_KERNELS,
	KEY_SUBSYSTEMS,
	KEY_DRIVERS,
	KEY_ATTRS,		/* ATTRS{filename} */
	KEY_TAGS,
	/* Assignment keys */
	KEY_SYMLINK,
	KEY_OWNER,
	KEY_GROUP,
	KEY_MODE,
	KEY_SECLABEL,		/* SECLABEL{module} */
	KEY_RUN,		/* RUN{type} */
	KEY_LABEL,
	KEY_GOTO,
	KEY_IMPORT,		/* IMPORT{type} */
	KEY_OPTIONS,
} rule_key_class_t;

/* Pattern matching strategy for match-op keys */
typedef enum {
	PAT_PLAIN = 0,		/* literal strcmp */
	PAT_GLOB,		/* fnmatch */
	PAT_SPLIT,		/* pipe-separated alternatives */
} pat_type_t;

/* IMPORT{type} subtypes */
typedef enum {
	IMPORT_PROGRAM = 0,	/* run program, parse KEY=VALUE output */
	IMPORT_FILE,		/* read KEY=VALUE from file */
	IMPORT_DB,		/* restore properties from udev database */
	IMPORT_BUILTIN,		/* run builtin, parse output */
	IMPORT_PARENT,		/* copy from parent device's database entry */
	IMPORT_CMDLINE,		/* import matching key from /proc/cmdline */
} import_type_t;

/* One key–operator–value triplet within a rule */
struct rule_key {
	rule_key_class_t  cls;
	rule_op_t         op;
	char             *attr;		/* ATTR{x}/ENV{x}/… — heap-allocated, may be NULL */
	char             *value;	/* pattern or assignment value — heap-allocated */
	pat_type_t        pat_type;
	import_type_t     import_type;
	run_type_t        run_type;
};

#define RULE_KEY_MAX  32

/* One parsed rule (a single non-empty, non-comment line) */
struct rule {
	TAILQ_ENTRY(rule)  link;
	char              *filename;	/* heap-allocated source path */
	int                lineno;
	int                nkeys;
	struct rule_key    keys[RULE_KEY_MAX];
};

TAILQ_HEAD(rule_list, rule);

/*
 * Load rules from a single .rules file, appending to list.
 * Returns the number of rules loaded, or -1 on open failure.
 */
int  rules_load    (struct rule_list *list, const char *path);

/*
 * Load all *.rules files from the standard udev directories
 * (/lib/udev/rules.d, /run/udev/rules.d, /etc/udev/rules.d)
 * plus extra_dir if non-NULL.  Files are loaded in alphanumeric
 * order within each directory; directories are processed in order.
 * Returns total number of rules loaded.
 */
int  rules_load_all(struct rule_list *list, const char *extra_dir);

/*
 * Free all rules and release their resources.
 */
void rules_free    (struct rule_list *list);

/*
 * Apply all matching rules from list to ev, updating ev->applied,
 * ev->result, env store, and tag list.
 */
int  rules_apply   (struct rule_list *list, struct uevent *ev);

/*
 * Execute the RUN+= commands accumulated in ev->applied.run_cmds.
 * Call after all device handling (nodes, symlinks) is complete.
 */
void rules_run_cmds(struct uevent *ev);

#endif /* KEVENTD_RULES_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
