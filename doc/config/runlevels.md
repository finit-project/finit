Runlevels
=========

Finit supports runlevels, but unlike other init systems runlevels are
declared per service/run/task/sysv command.  When booting up a system
Finit pass through three phases:

 1. Setting up the console, parsing any command line options, and other
    housekeeping tasks like mounting all filesystems, and calling `fsck`
 2. Starting all run/task/services in runlevel S, then waiting for all
    services to have started, and all run/tasks to have completed
 3. Go to runlevel 2, or whatever the user has set in the configuration

Available runlevels:

 - `  S`: bootStrap
 - `  1`: Single user mode
 - `2-5`: traditional multi-user mode
 - `  6`: reboot
 - `7-9`: multi-user mode (extra)
 - `  0`: shutdown

Runlevel S (bootStrap), is for tasks supposed to run once at boot, and
services like `syslogd`, which need to start early and run throughout
the lifetime of your system.

Example:

    task [S] /lib/console-setup/console-setup.sh
    service [S12345] env:-/etc/default/rsyslog rsyslogd -n $RSYSLOGD_ARGS

When bootstrap has completed, Finit moves to runlevel 2.  This can be
changed in `/etc/finit.conf` using the `runlevel N` directive, or by a
script running in runlevel S that calls, e.g., `initctl runlevel 9`.
The latter is useful if startup scripts detect problems outside of
Finit's control, e.g., critical services/devices missing or hardware
problems.

Each runlevel must be allowed to "complete".  Meaning, all services in
runlevel S must have started and all run/tasks have been started and
collected (exited).  Finit waits 120 seconds for all run/tasks in S to
complete before proceeding to 2.

Finit first stops everything that is not allowed to run in 2, and then
brings up networking.  Networking is expected to be available in all
runlevels except: S, 1 (single user level), 6, and 0.  Networking is
enabled either by the `network script` directive, or if you have an
`/etc/network/interfaces` file, Finit calls `ifup -a` -- at the very
least the loopback interface is brought up.

> [!NOTE]
> When moving from runlevel S to 2, all run/task/services that were
> constrained to runlevel S only are dropped from bookkeeping.  So when
> reaching the prompt, `initctl` will not show these run/tasks.  This is
> a safety mechanism to prevent bootstrap-only tasks from accidentally
> being run again.  E.g., `console-setup.sh` above.

Runlevel Configuration
----------------------

**Syntax:** `runlevel <N>`

The system runlevel to go to after bootstrap (S) has completed.  `N` is
the runlevel number 0-9, where 6 is reserved for reboot and 0 for halt.
Completed in this context means all services have been started and all
run/tasks have been started and collected.

It is recommended to keep runlevel 1 as single-user mode, because
Finit disables networking in this mode.

*Default:* 2

> [!NOTE]
> Only read and executed in runlevel S (bootstrap).

Networking
----------

**Syntax:** `network <PATH>`

Script or program to bring up networking, with optional arguments.

Deprecated.  We recommend using dedicated task/run stanzas per runlevel,
or `/etc/network/interfaces` if you have a system with `ifupdown`, like
Debian, Ubuntu, Linux Mint, or an embedded BusyBox system.

> [!NOTE]
> Only read and executed in runlevel S (bootstrap).

System Hostname
---------------

**Syntax:** `host <NAME>`, or `hostname <NAME>`

Set system hostname to NAME, unless `/etc/hostname` exists in which case
the contents of that file is used.

Deprecated.  We recommend using `/etc/hostname` instead.

> [!NOTE]
> Only read and executed in runlevel S (bootstrap).

Kernel Modules
--------------

**Syntax:** `module <MODULE> [ARGS]`

Load a kernel module, with optional arguments.  Similar to `insmod`
command line tool.

Deprecated, there is both a `modules-load.so` and a `modprobe.so` plugin
that can handle module loading better.  The former supports loading from
`/etc/modules-load.d/`, the latter uses kernel modinfo to automatically
load (or coldplug) every required module.  For hotplug we recommend the
BusyBox mdev tool, add to `/etc/mdev.conf`:

    $MODALIAS=.*  root:root       0660    @modprobe -b "$MODALIAS"

> [!NOTE]
> Only read and executed in runlevel S (bootstrap).

Resource Limits
---------------

**Syntax:** `rlimit [hard|soft] RESOURCE <LIMIT|unlimited>`

Set the hard or soft limit for a resource, or both if that argument is
omitted.  `RESOURCE` is the lower-case `RLIMIT_` string constants from
`setrlimit(2)`, without prefix.  E.g. to set `RLIMIT_CPU`, use `cpu`.
  
LIMIT is an integer that depends on the resource being modified, see
the man page, or the kernel `/proc/PID/limits` file, for details.
Finit versions before v3.1 used `infinity` for `unlimited`, which is
still supported, albeit deprecated.

    # No process is allowed more than 8MB of address space
    rlimit hard as 8388608

    # Core dumps may be arbitrarily large
    rlimit soft core infinity

    # CPU limit for all services, soft & hard = 10 sec
    rlimit cpu 10

`rlimit` can be set globally, in `/etc/finit.conf`, or locally per
each `/etc/finit.d/*.conf` read.  I.e., a set of task/run/service
stanzas can share the same rlimits if they are in the same .conf.

Miscellaneous Settings
----------------------

**Syntax:** `reboot-delay <0-60>`

Optional delay at reboot (or shutdown or halt) to allow kernel
filesystem threads to complete after calling `sync(2)` before
rebooting.  This applies primarily to filesystems that do not
have a reboot notifier implemented.  At the point of writing,
the only known filesystems affected are: ubifs, jffs2.

*Default:* 0 (disabled)

When enabled (non-zero), this delay runs after file systems have been
unmounted and the root filesystem has been remounted read-only, and
sync(2) has been called, twice.

> "On Linux, sync is only guaranteed to schedule the dirty blocks for
> writing; it can actually take a short time before all the blocks are
> finally written.

**Syntax:** `reboot-watchdog <on|off|true|false|1|0>`

Controls whether the system should reboot via the watchdog timer (WDT)
or directly via the SoC/kernel.  When enabled, Finit will:

 1. Send `SIGPWR` to the registered watchdog daemon before shutdown
 2. Send `SIGTERM` to the watchdog daemon and wait up to 10 seconds
    for the watchdog to trigger a hardware reset

When disabled (default), Finit skips the watchdog reboot logic and
calls the kernel's `reboot(2)` syscall directly for a clean SoC reboot.

*Default:* off (reboot via SoC)

> [!NOTE]
> This setting only affects reboots.  The watchdog daemon will still
> run and monitor the system during normal operation.
