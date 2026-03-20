/* Plymouth boot splash plugin for Finit
 *
 * Copyright (c) 2012-2026  Aaron Andersen <troglobit@gmail.com>
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
 * This plugin integrates the Plymouth boot splash screen with Finit.
 * It manages the plymouthd lifecycle across the full boot process:
 *
 *  - HOOK_BANNER:      Start plymouthd early, before console output.
 *                      In initramfs, starts fresh.  In stage 2, reuses
 *                      the daemon carried over from initramfs if alive.
 *  - HOOK_ROOTFS_UP .. HOOK_SYSTEM_UP: Display status messages.
 *  - HOOK_SVC_UP:      Tear down plymouth once boot is complete.
 *  - HOOK_SWITCH_ROOT: Notify plymouth of root filesystem change so
 *                      the daemon survives the initramfs -> rootfs
 *                      transition.
 *  - HOOK_SHUTDOWN:    Restart plymouthd in shutdown mode for a
 *                      splash during poweroff/reboot.
 *
 * The plugin is only activated when "splash" is present on the kernel
 * command line.  Plymouth requires devpts for VT takeover; fs_init()
 * mounts it early enough for HOOK_BANNER.
 *
 * NOTE: The initramfs must include /etc/initrd-release.  Plymouth
 * checks for this file and, when present, prefixes its argv[0] with
 * '@' so that the process is not killed during switch_root.  Without
 * it, plymouthd will not survive the initramfs-to-rootfs transition.
 */

#include "config.h"
#include "finit.h"
#include "helpers.h"
#include "conf.h"
#include "pid.h"
#include "plugin.h"
#include "sig.h"
#include "util.h"
#include "log.h"

#ifndef PLYMOUTH_PATH
#define PLYMOUTH_PATH "/sbin/plymouth"
#endif
#ifndef PLYMOUTHD_PATH
#define PLYMOUTHD_PATH "/sbin/plymouthd"
#endif

#define PLYMOUTH_PIDFILE  "/run/plymouthd.pid"

static pid_t daemon_pid;
static int   switching_root;
static int   in_initramfs;

static int plymouth_cmd(const char *action)
{
	char cmd[256];

	snprintf(cmd, sizeof(cmd), PLYMOUTH_PATH " %s", action);
	return run(cmd, NULL);
}

static void plymouth_message(const char *msg)
{
	pid_t pid;

	pid = fork();
	if (pid == 0) {
		sig_unblock();
		execl(PLYMOUTH_PATH, PLYMOUTH_PATH,
		      "display-message", "--text", msg, NULL);
		_exit(EX_OSERR);
	}
}

static int plymouth_alive(void)
{
	return daemon_pid > 0 && pid_alive(daemon_pid);
}

/* Start plymouthd in the given mode ("boot" or "shutdown"). */
static void plymouth_start(const char *mode)
{
	char cmd[256];
	int rc;

	if (plymouth_alive())
		return;

	snprintf(cmd, sizeof(cmd),
		 PLYMOUTHD_PATH " --attach-to-session --mode %s --pid-file %s",
		 mode, PLYMOUTH_PIDFILE);
	rc = run(cmd, NULL);
	if (rc) {
		warnx("plymouthd failed to start (exit %d)", rc);
		return;
	}

	daemon_pid = pid_file_read(PLYMOUTH_PIDFILE);
	if (daemon_pid <= 0) {
		warnx("plymouthd started but no PID in %s", PLYMOUTH_PIDFILE);
		return;
	}

	rc = plymouth_cmd("show-splash");
	if (rc)
		warnx("plymouth show-splash failed (exit %d)", rc);
}

static void plymouth_stop(void)
{
	if (!plymouth_alive())
		return;

	plymouth_cmd("quit");

	/*
	 * Don't poll -- we're in a finit hook, so finit's event loop
	 * is blocked and can't reap children.  Trust that plymouthd
	 * exits after receiving the quit command.
	 */
	daemon_pid = 0;
	unlink(PLYMOUTH_PIDFILE);
}

/*
 * HOOK_BANNER - earliest possible hook, before any console output.
 *
 * In initramfs: start plymouthd fresh.
 * In stage 2:   reuse plymouthd from initramfs if still alive,
 *               otherwise start a new instance.
 */
static void plymouth_boot(void *arg)
{
	in_initramfs = fexist("/etc/initrd-release");

	if (rescue)
		return;

	enable_progress(0);

	if (!in_initramfs) {
		if (plymouth_cmd("--ping") == 0) {
			daemon_pid = pid_file_read(PLYMOUTH_PIDFILE);
			if (daemon_pid <= 0)
				daemon_pid = 1; /* alive but unknown pid */
			return;
		}
	}

	plymouth_start("boot");
}

/*
 * HOOK_SVC_UP - all services launched.
 *
 * In initramfs: keep splash alive for switch_root.
 * In stage 2:   boot is done, tear down plymouth.
 */
static void plymouth_boot_done(void *arg)
{
	if (in_initramfs)
		return;

	plymouth_stop();
	enable_progress(1);
}

/* HOOK_SWITCH_ROOT - initramfs transitioning to real root. */
static void plymouth_switchroot(void *arg)
{
	switching_root = 1;

	plymouth_message("Switching to root filesystem...");

	if (plymouth_alive())
		run(PLYMOUTH_PATH " update-root-fs --new-root-dir=/sysroot", NULL);

	enable_progress(1);
}

/* HOOK_SHUTDOWN - entering runlevel 0 or 6. */
static void plymouth_shutdown(void *arg)
{
	if (rescue || switching_root)
		return;

	enable_progress(0);
	plymouth_start("shutdown");
}

static void on_rootfs_up(void *arg)
{
	plymouth_message("Root filesystem mounted");
}

static void on_mount_post(void *arg)
{
	plymouth_message("Mounting filesystems...");
}

static void on_basefs_up(void *arg)
{
	plymouth_message("All filesystems mounted");
}

static void on_network_up(void *arg)
{
	plymouth_message("Network is up");
}

static void on_system_up(void *arg)
{
	plymouth_message("System ready");
}

static plugin_t plugin = {
	.name = "plymouth",
	.hook[HOOK_BANNER]      = { .cb  = plymouth_boot       },
	.hook[HOOK_ROOTFS_UP]   = { .cb  = on_rootfs_up        },
	.hook[HOOK_MOUNT_POST]  = { .cb  = on_mount_post       },
	.hook[HOOK_BASEFS_UP]   = { .cb  = on_basefs_up        },
	.hook[HOOK_NETWORK_UP]  = { .cb  = on_network_up       },
	.hook[HOOK_SYSTEM_UP]   = { .cb  = on_system_up        },
	.hook[HOOK_SVC_UP]      = { .cb  = plymouth_boot_done  },
	.hook[HOOK_SWITCH_ROOT] = { .cb  = plymouth_switchroot },
	.hook[HOOK_SHUTDOWN]    = { .cb  = plymouth_shutdown   },
};

/*
 * Check kernel command line for "splash" argument.  Plymouth should
 * only be activated when the user explicitly requests it.
 */
static int has_splash_arg(void)
{
	char line[LINE_SIZE], *tok, *saveptr;
	FILE *fp;

	fp = fopen("/proc/cmdline", "r");
	if (!fp)
		return 0;

	if (!fgets(line, sizeof(line), fp)) {
		fclose(fp);
		return 0;
	}
	fclose(fp);

	for (tok = strtok_r(line, " \t\n", &saveptr); tok;
	     tok = strtok_r(NULL, " \t\n", &saveptr)) {
		if (!strcmp(tok, "splash"))
			return 1;
	}

	return 0;
}

PLUGIN_INIT(__init)
{
	if (!has_splash_arg())
		return;

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
