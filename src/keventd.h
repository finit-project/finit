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
#include <sys/types.h>

/* Maximum uevent buffer size (kernel uses 8192 internally) */
#define UEVENT_BUFFER_SIZE  8192

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
 * Parsed uevent structure.
 * Pointers are into the receive buffer, zero-copy.
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
};

/* Tracked symlink for cleanup on device removal */
struct dev_symlink {
	TAILQ_ENTRY(dev_symlink) link;
	char    *devpath;	/* sysfs devpath (key for removal) */
	char    *linkpath;	/* /dev/disk/by-id/... */
};

/* Function prototypes - uevent.c */
int             uevent_parse    (char *buf, size_t len, struct uevent *ev);
const char     *uevent_action_str(uevent_action_t action);

int             devnode_add     (struct uevent *ev);
int             devnode_del     (struct uevent *ev);

int             symlink_add     (struct uevent *ev);
int             symlink_del     (struct uevent *ev);

int             firmware_load   (struct uevent *ev);
int             modprobe_load   (const char *modalias);

int             coldplug        (void);

#endif /* FINIT_KEVENTD_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
