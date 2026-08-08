/* Finit - Fast /sbin/init replacement w/ I/O, hook & service plugins
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

#ifndef FINIT_H_
#define FINIT_H_

#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef _LIBITE_LITE
# include <libite/lite.h>
#else
# include <lite/lite.h>
#endif
#include <uev/uev.h>

/* just in case */
#ifndef _PATH_STDPATH
#define _PATH_STDPATH           "/usr/bin:/bin:/usr/sbin:/sbin"
#endif

#ifndef _PATH_VARRUN
#define _PATH_VARRUN            "/var/run/"
#endif

#ifndef FINIT_CGPATH
#define FINIT_CGPATH            "/sys/fs/cgroup"
#endif

/* Prevent users from logging in at critical stages */
#ifndef FINIT_NOLOGIN_PATH
#define FINIT_NOLOGIN_PATH      _PATH_NOLOGIN
#endif

/* To use these, include config.h, or define FINIT_EXECPATH_ */
#define _PATH_LOGIT             FINIT_EXECPATH_ "/logit"
#define _PATH_RUNPARTS          FINIT_EXECPATH_ "/runparts"
#define _PATH_SULOGIN           FINIT_EXECPATH_ "/sulogin"
#define _PATH_GETTY             FINIT_EXECPATH_ "/getty"
#define _PATH_TMPFILES          FINIT_EXECPATH_ "/tmpfiles"

#define CMD_SIZE                1024
#define LINE_SIZE               1024
#define BUF_SIZE                4096

#define INIT_SOCKET             _PATH_VARRUN "finit/socket"
#define FINIT_BUS_SOCKET        _PATH_VARRUN "finit/bus"
#define INIT_MAGIC              0x03091969
#define INIT_LEVEL              10

/* We extend the INIT_CMD_ range for the new initctl tool. */
#define INIT_CMD_START          0
#define INIT_CMD_RUNLVL         1
#define INIT_CMD_POWERFAIL      2
#define INIT_CMD_POWERFAILNOW   3
#define INIT_CMD_POWEROK        4
#define INIT_CMD_BSD            5
#define INIT_CMD_SETENV         6
#define INIT_CMD_UNSETENV       7

/* Finit extensions over std SysV */
#define INIT_CMD_DEBUG          8    /* Toggle Finit debug */
#define INIT_CMD_RELOAD         9    /* Reload *.conf in /etc/finit.d/ */
#define INIT_CMD_START_SVC      10   /* START service */
#define INIT_CMD_STOP_SVC       11
#define INIT_CMD_RELOAD_SVC     12   /* SIGHUP service */
#define INIT_CMD_RESTART_SVC    13   /* START service, clearing blocks */
#define INIT_CMD_GET_PLUGINS    14   /* Fill data[] with loaded plugins */
#define INIT_CMD_PLUGIN_DEPS    15   /* Fill data[] with plugin deps */
#define INIT_CMD_GET_RUNLEVEL   16
#define INIT_CMD_REBOOT         20
#define INIT_CMD_HALT           21
#define INIT_CMD_POWEROFF       22
#define INIT_CMD_SUSPEND        23
#define INIT_CMD_SWITCH_ROOT    24   /* Switch to new root filesystem */
#define INIT_CMD_WDOG_HELLO     128  /* Watchdog register and hello */
#define INIT_CMD_SVC_ITER       129
#define INIT_CMD_SVC_QUERY      130
#define INIT_CMD_SVC_FIND       131
#define INIT_CMD_SVC_FIND_BYC   132
#define INIT_CMD_SIGNAL         133
#define INIT_CMD_NACK           254
#define INIT_CMD_ACK            255

/* Traditionally aligned on 384 bytes */
struct init_request {
	int	magic;		/* Magic number			*/
	int	cmd;		/* What kind of request		*/
	int	runlevel;	/* Runlevel to change to	*/
	int	sleeptime;	/* Time between TERM and KILL	*/
	char	data[368];
};

#endif /* FINIT_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
