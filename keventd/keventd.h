/* Unified device manager for Finit - uevent handling, device nodes, symlinks
 *
 * Copyright (c) 2021-2025  Joachim Wiberg <troglobit@gmail.com>
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

#ifndef FINIT_KEVENTD_H_
#define FINIT_KEVENTD_H_

#ifdef _LIBITE_LITE
# include <libite/queue.h>	/* BSD sys/queue.h API */
#else
# include <lite/queue.h>	/* BSD sys/queue.h API */
#endif
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

/* Maximum uevent buffer size (kernel uses 8192 internally) */
#define UEVENT_BUFFER_SIZE  8192

/* Capacity of the generic env store on struct uevent */
#define UEVENT_ENV_MAX  64

/* Maximum TAG+= entries per device event */
#define UEVENT_TAG_MAX  16

/* Maximum SYMLINK+= and RUN+= entries set by the rules engine */
#define RULE_SYMLINK_MAX  8
#define RULE_RUN_MAX      8

/* RUN{type} subtypes — also used in struct rule_ctx below */
typedef enum {
	RUN_PROGRAM = 0,	/* execute external program */
	RUN_BUILTIN,		/* call builtin function */
} run_type_t;

/* Uevent actions from kernel */
typedef enum {
	ACT_UNKNOWN = 0,
	ACT_ADD,
	ACT_REMOVE,
	ACT_CHANGE,
	ACT_MOVE,
	ACT_ONLINE,
	ACT_OFFLINE,
	ACT_BIND,
	ACT_UNBIND,
} uevent_action_t;

/*
 * Rule-applied permissions and context, set by the rules engine.
 * Zero-initialised means "nothing set by rules", fall back to built-in table.
 */
struct rule_ctx {
	/* Device permissions */
	mode_t  mode;
	uid_t   uid;
	gid_t   gid;
	int     has_mode;
	int     has_owner;
	int     has_group;
	int     final_mode;		/* := operator locks against further overrides */
	int     final_owner;
	int     final_group;
	/* NAME= override for device node path (heap-allocated) */
	char   *name;
	/* SYMLINK+= accumulator (heap-allocated strings) */
	int     nsymlinks;
	char   *symlinks[RULE_SYMLINK_MAX];
	/* RUN+= command list (heap-allocated strings, executed post-event) */
	int     nruncmds;
	char   *run_cmds[RULE_RUN_MAX];
	run_type_t run_types[RULE_RUN_MAX];
};

/*
 * Parsed uevent structure.
 * Named field pointers point into the receive buffer (zero-copy).
 * The env store holds all KEY=VALUE pairs plus any rule-set variables.
 */
struct uevent {
	uevent_action_t  action;
	char            *devpath;	/* /devices/pci0000:00/... */
	char            *subsystem;	/* block, input, net, power_supply */
	char            *devname;	/* sda, event0, ttyUSB0 */
	char            *devtype;	/* disk, partition */
	int              major;
	int              minor;
	char            *modalias;	/* module alias for auto-loading */
	char            *firmware;	/* firmware file name request */
	char            *seqnum;	/* kernel sequence number */
	char            *driver;	/* driver name */

	/* Generic env store: all KEY=VALUE from the netlink buffer + rule-set vars */
	int     nenv;
	char   *env_key[UEVENT_ENV_MAX];
	char   *env_val[UEVENT_ENV_MAX];
	uint8_t env_key_alloc[UEVENT_ENV_MAX];	/* 1 if heap-allocated, 0 if buf ptr */
	uint8_t env_val_alloc[UEVENT_ENV_MAX];

	/* PROGRAM= output, stored for subsequent RESULT== matching */
	char   *result;

	/* TAG+= accumulator */
	int     ntags;
	char   *tags[UEVENT_TAG_MAX];

	/* Rule-applied permissions from the rules engine */
	struct rule_ctx applied;
};

/* Tracked symlink for cleanup on device removal */
struct dev_symlink {
	TAILQ_ENTRY(dev_symlink) link;
	char    *devpath;	/* sysfs devpath (key for removal) */
	char    *linkpath;	/* /dev/disk/by-id/... */
};

/* Function prototypes - uevent.c */
void            rule_ctx_free    (struct rule_ctx *ctx);

int             uevent_parse     (char *buf, size_t len, struct uevent *ev);
const char     *uevent_action_str(uevent_action_t action);
const char     *uevent_sysname   (const struct uevent *ev);

const char     *uevent_getenv    (const struct uevent *ev, const char *key);
int             uevent_setenv    (struct uevent *ev, const char *key, const char *val);
void            uevent_env_free  (struct uevent *ev);

int             devnode_add      (struct uevent *ev);
int             devnode_del      (struct uevent *ev);
int             netdev_add       (struct uevent *ev);

int             symlink_add      (struct uevent *ev);
int             symlink_del      (struct uevent *ev);
void            symlink_write_db (const char *devpath, FILE *fp);

int             firmware_load    (struct uevent *ev);
int             modprobe_load    (const char *modalias);

int             coldplug         (void);

#endif /* FINIT_KEVENTD_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
