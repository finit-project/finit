Change Log
==========

All relevant changes are documented in this file.

[4.16][] - Unreleased
---------------------

### Changes

- Add `initctl switch-root` command and plugin hook point.  Useful for
  systems requiring early boot tasks like LUKS unlock, LVM activation,
  or network boot before mounting the real root, by Aaron Andersen
- Set USER and LOGNAME environment variables when dropping privileges.
  Fixes issues with software like rootless Podman that determines user
  identity from environment variables, by Aaron Andersen
- Add `remain:yes` option for run/task oneshot commands, similar to the
  systemd `RemainAfterExit=yes`, by Aaron Andersen
- Clear service conditions on `initctl reload NAME` to ensure dependent
  services are properly updated

### Fixes
- Fix #464: invalid user:group examples in cgroups.md
- Fix #466: elogind path for Debian-based distros, by Jackie Liu
- Fix #467: TTY services stuck in restart state after non-zero exit.
  Throttling logic introduced in v4.15 had duplicate checks causing
  infinite timer loop, and TTYs lacked default restart timeout
- Fix handling of already-mounted cgroups in `cgroup_init()`, can occur
  after switch_root or in container environments
- Improve cgroups documentation clarity, grammar, and examples


[4.15][] - 2026-01-01
---------------------

The Finit project now has a new home page: <https://finit-project.github.io>

### Changes
- Change default reboot to SOC reset from WDT reset, issue #460
- Bump required versions of libite (v2.6.2) and libuev (v2.4.1)
- Allow longer service identifiers (`:id`), up to 64 characters
- Allow skipping bootstrap wait (180 sec) with Ctrl-C
- Unlock `initctl` commands start/stop/restart/reload service during bootstrap,
  shutdown, and reboot.  Also, allow `initctl reload` in bootstrap. This makes
  it possible to start manual:yes type services at botostrap, for example, which
  has been a common feature request
- Add support for `clone3()` syscall with atomic cgroup assignment, from Linux
  kernel 5.3+.  Eliminates race conditions where forked processes (e.g., logger
  processes) ended up in wrong cgroups. Falls back to `fork()` on older kernels
- Add support for cgroup delegation, useful for, e.g., container runtimes
  creating sub-groups for the container instance's processes
- Add cgroup leaf name override: `cgroup.system,name:udevd` allows using
  descriptive names like `/system/udevd/` instead of filename derived names
  like `/system/10-hotplug/`.  Syntax supports combining with other options:
  `cgroup.system,name:foo,delegate,cpu.max:10000`
- Add support for Linux capabilities, allowing services to run with minimal
  required privileges instead of running as root.  Uses the modern IAB API
  (Inheritable, Ambient, Bounding) from libcap.  By Aaron Andersen
- Add support for supplementary groups for services.  Uses the syntax
  `@user:group,sup1,sup2` to explicitly specify supplementary groups, in
  addition to reading group membership from `/etc/group`.  By Aaron Andersen
- Add CPU throttled information to `initctl` output, showing when a service
  has been throttled due to reaching its CPU quota
- Add memory field to `initctl --json` status output for cgroup-enabled
  services
- Default to user and group `root` (UID 0) for services
- Always check that service user and group resolve to valid UID/GID pairs,
  otherwise log error and refuse to start service
- Hide cursor at boot and shutdown for cleaner visual experience
- Rename `tty` services early from `init` -> `getty` even though no getty
  process has been started yet.  This to aid in boot timing detection using
  tools like `bootchartd` (BusyBox version or bootchart2 project) when Finit
  only shows *"Please press Enter to activate this console."*
- Services with `respawn` option (including TTYs) now delay retry on non-zero
  exit codes instead of immediate respawn.  Prevents busy-loop when service
  fails repeatedly, which on some systems may have a crippling effect

### Fixes
- Fix #453: RTC plugin fixes by Ming Liu, Atlas Copco
- Fix #455: ANSI escape sequences logged by tools using glib logging,
  caused by use of PTY instead of pipe for stdout/stderr redirection
- Fix #462: `/dev/pts` mounted with wrong mode (400 instead of 620), causing
  permission issues with pseudo-terminals
- getty: fix terminal scrollback issues after login on console TTY.  Mouse
  scroll wheel and Shift+PgUp/PgDn sometimes would not work properly
- Fix flickering and artifacts in `initctl top`
- Fix file descriptor leak in `initctl top`
- Fix incorrect "max" limit reporting in `initctl [top|cgroup|--json]` output
  for child cgroups.  Resolves effective limits by walking the cgroup hierarchy
- Fix issue with running Finit under `bootchartd` (bootchart2 project), always
  set `PATH` and `SHELL` envs early, before attempting to mount `/proc` et al
- Always reset ownership and permissions on TTY device nodes before launching getty
- Ensure mount/unmount skips `noauto` entries


[4.14][] - 2025-08-29
---------------------

Minor bug fix release.

### Changes
 - Add exit status/signal info when a process dies, by Mattias Berthel
 - Extend `service kill:SEC` to support up to 300 sec.
 - Extend `norespawn` debug to cover `service_retry()`
 - Build *without* libsystemd replacement by default

### Fixes
 - Fix #449: ALSA plugin fail-to-build-from-source
 - Fix `sysv` stop command process environment, should be same as start
 - Fix state machine ordering issue: enter new config generation *after*
   services disabled in previous generation have been stopped


[4.13][] - 2025-07-10
---------------------

> [!NOTE]
> This release introduce a bare bones `libsystemd` replacement with an
> `<systemd/sd-daemon>.h` include file.  Other systemd features are the
> `reload:script` and `stop:script`, mimicking ExecReload and ExecStop.

### Changes
 - `initctl signal` command has been renamed to `initctl kill`
 - Drop xz tarballs from distribution, gzip is good enough
 - New `tmpfiles` stand-alone program, refactored from the existing
   tmpfiles.d support in Finit, by Aaron Andersen, PR #439
    - `--remove` command runs only the `r` and `R` rules
    - `--create` is used for all other cases (bootstrap)
 - All `notify:systemd` services now log with `logit` by default.  This
   because it supports systemd style log severity, leading `"<NUM>"`
 - Support for quoted arguments to run/task/service options, issue #441
 - Clear command line arguments after bootstrap, issue #442
 - Support for `stop:'script [args]'` to stop a sysv/service instead of
   the common `foo-stop-start.sh stop`, or `SIGTERM`, issue #412
 - Support for `reload:'script [args]'` to trigger a configuration
   reload in a service, issue #446

### Fixes
 - Fix #437: buffer overflow in `initctl status`
 - Fix #438: support very long command lines in `initctl ps/top`
 - Fix #440: broken systemd and s6 readiness notification
 - Fix #443: build warnings, by Ming Liu, Atlas Copco
 - Fix #444: handle loooooong arguments, by Aaron Andersen
 - Fix service's redirected stdout/stderr log priority in fallback mode,
   when neither `logger` or `logit` is available.  This fix also checks
   for systemd style log severity, leading `"<NUM>"` in log messages
 - Ensure API socket used by `initctl` is non-blocking (event loop)


[4.12][] - 2025-04-28
---------------------

### Changes
 - Improve notify:s6 readiness compatibility, by Aaron Andersen
 - Update `runparts` usage text

### Fixes
 - Fix variable overloading in urandom plugin
 - Fix buffer overwrite in urandom plugin, reported by Aaron Andersen


[4.11][] - 2025-03-27
---------------------

### Changes
 - Update documentation regarding transition from runlevel S to 2, how
   run/tasks must "complete" before Finit can move to the next runlevel
 - Improve argument handling in bundled getty when launching login

### Fixes
 - Fix #432: allow services in `setup` state to be stopped.  This fixes
   a serious blocker introduced in 4.10 that prevented systems from
   being rebooted when any service was in this state
 - Fix fallback `SIGKILL` when stopping a service with `SIGTERM` does
   not work.  This fixes a serious issue with services not responding to
   the default `SIGTERM`
 - Fix pre/post/ready/cleanup script execution if service has an
   optional `env:file` (leading `-`)
 - Fix blocked signals for pre/post/ready/cleanup scripts preventing
   normal shutdown when a service/sysv is stopped in its setup state
 - Fix issue where a pre:script creates a PID file in `/run` cause the
   service to move from setup state to running.  Any `svc_t` in setup,
   teardown, or cleanup state should be ignored in the pidfile plugin


[4.10][] - 2025-03-03
---------------------

### Changes
 - Add support for `cleanup:[0-3600,]script`, runs before service is
   removed, unlike `post:script` that runs when service is stopped
 - Improved entropy gathering in tertiary fallback of urandom plugin
 - Reclassify `sysv` from run/task class to `service`

### Fixes
 - Fix #427: using an external getty with custom login program cause
   Finit to use login program as the getty command
 - Fix #428: allow `sysctl` path to be set at build time
 - Fix #429: regression in v4.9 causing Finit to segfault at shutdown
 - Fix possible memory leak when sourcing a service `env:file`
 - Finit now waits until all `post:scripts` have run before returning
   OK to `initctl <reload|runlevel>`.  This also applies to the new
   `cleanup:scripts` introduced in this release
 - RFC3154 conformance formatting fix for `/dev/kmsg` fallback logging


[4.9][] - 2025-02-15
--------------------

> [!CAUTION]
> This release changes how Finit reacts to the exit status of `pre:`
> scripts.  Finit will now no longer start the main process if its
> `pre:` script fails for any reason.  So, if you have pre scripts that,
> e.g., create directories, make sure they are idempotent.

### Changes
 - Add individual timeout (optional) support for pre/post/ready scripts
 - Add support for systems with broken RTC, i.e., those that at power-on
   may reset the RTC to a random date instead of zero, issue #418
 - Add support for detecting "in-container" when in `systemd-nspawn`
 - Check exit status of `pre:` scripts, on failure drive service/sysv to
   `crashed` state.  (The exit code of `post:` scripts remain ignored)
 - All pre/post/ready scripts are now also searched for in `$PATH`
 - Reset color attributes and clear screen when starting up.  This is
   for boot loaders like GRUB, which leave background color artifacts

### Fixes
 - Fix #415: only mark reverse-dependencies "dirty" if the main service
   does not support SIGHUP.  This helps avoid unnecessary restarts of
   services that depend on a service that supports SIGHUP
 - Fix #417: leaking inotify watchers in the cgroup subsystem
 - Fix #421: add support for `nofail` mount option in `/etc/fstab`
 - Fix #425: ordering bug in detecting .conf file changes to services
   and `initctl reload`, or runlevel changes
 - Fix `initctl touch` of template services, previously marking a
   service created from a template as "dirty" did not take
 - Fix unintended restart of template "siblings".  I.e., `initctl touch`
   of instantiated template service A affected B from same template
 - Fix buggy `--with-rtc-date=DATE` configure option
 - Fix kill on timeout of pre/post/ready scripts


[4.8][] - 2024-10-13
--------------------

### Changes
 - Avoid remounting already mounted `/run` and `/tmp` directories.  This
   extends the existing support for detecting mounted directories to
   include complex mount hierarchies are in use, overlayfs and tmpfs
   mounts.  Feature by Mathias Thore, Atlas Copco
 - getty: trigger /etc/issue compat mode for Alpine Linux
 - tmpfiles.d: skip `x11.conf` unless X11 common plugin is enabled
 - tmpfiles.d: ignore x/X command, nos support for cleanup at runtime
 - Drop debug mode `-D` from `udevd` in `hotplug.conf.in`, allow the
   user to set this in `/etc/default/udevd` instead
 - Certain initctl APIs at bootstrap are not supported, update warning
   log to include command (number) for troubleshooting, issue #398
 - Add support for hwrng to urandom plugin and check for empty seed
 - Add `runparts -b` (batch mode) support, disables escape sequences
 - New configure `--without-rc-local`, disables `/etc/rc.local` support
 - New configure `--disable-cgroup` option, disables cgroup v2 detection
 - `initctl show template@foo.conf` now shows how an enabled template
   service has been evaluated by Finit, issue #411
 - Extend `initctl` timeout connecting and waiting for Finit reply.  The
   previous 2 + 2 second poll timeout has proved to be too short on more
   complex systems.  Now a 15 + 15 second timeout is applied which should
   be more resistant to temporary overload scenarios, issue #407

### Fixes
 - Fix #397: system shutdown/reboot can block on console input if action
   is started remotely (ssh).  Caused by legacy TTY screen size probing,
   removed from both bootstrap and shutdown/reboot
 - Fix #400: both `HOOK_MOUNT_ERROR` and `sulogin()` fail to trigger on
   either mount or `fsck` errors.  Problem caused by unresolved status
   from pipe, calling `pclose()` without extracting exit status
 - Fix #402: `initctl touch` does not respect `-n` (no error) flag
 - Fix #403: `initctl touch` does not support template services
 - Fix #404: possible undefined behavior when `--with-fstab=no` is set
 - Fix #405: `@console` getty does not work with `tty0 ttyS0`
 - Fix #409: prevent tmpfiles from following symlinks for `L+` and `R`,
   otherwise symlink targets would also be removed.  Found and fixed by
   Mathias Thore and Ming Liu, Atlas Copco
 - Fix #414: Frr Zebra immediately restarts on `initctl stop zebra`.
   The fix likely works for all Frr/Quagga services due to the way they
   create and delete their pid file
 - Cosmetic issue with `[ OK ]` messages being printed out of order at
   shutdown/reboot.  Caused by nested calls to `service_stop()`
 - Cosmetic issue with duplicate "Restoring RTC" message at bootstrap


[4.7][] - 2024-01-07
--------------------

### Changes
- Silence "not available" messages for run/task/service with `nowarn`
- Update docs, `cgroup.root` workaround for `SCHED_RR` tasks
- Drop runlevels 0 and 6 from `keventd`, not needed at reboot/poweroff
- Mount `/dev/shm` with mode 1777 (sticky bit)
- Mount `/dev/mqueue` if available, inspiration from Alpine Linux
- Update Alpine Linux installer and configuration files, tested on
  Alpine v3.19, some assembly still required

### Fixes
- Fix confusing warning message when tmpfiles.d fails to install symlink
- Fix tmpfiles.d legacy `/run/lock/subsys`, ordering
- Add missing `/var/tmp` and `/var/lock -> /run/lock` (tmpfiles.d)
- Fix #388: log redirection broken unless Finit runs in debug mode.
  Found and fixed by Ryan Rorison
- Fix #389: must libc requires `libgen.h` for `basename()` function.
  Reported and worked around with new `basenm()` function by Stargirl
- Fix #392: `service/foo/ready` condition reasserted on pidfile removal


[4.6][] - 2023-11-13
--------------------

### Changes
- Add support for service `notify:pid` and `readiness none` global
  option to change how Finit expects readiness notification, issue #386

### Fixes
- Fix #383: dbus and runparts regression in Finit v4.5.  The configure
  script must expand `FINIT_RUNPATH_` before defining it in `config.h`
- Fix #384: service environment variables drop everything but the first
  argument, e.g., `VAR="foo bar qux"` drops everything but `foo`
- Fix #385: internal conditions, e.g., `<int/bootstrap>` turn into flux
  when leaving bootstrap, causing depending services to stop
- Fix #387: global environment variables declared with `set VAR=NAME` do
  not drop leading `set `, causing `'set VAR'='NAME'` in env.
- Sanity check environment variables, for services and globally.  Ensure
  the variable name (key) does not contain spaces, or a leading `set `


[4.5][] - 2023-10-30
--------------------

### Changes
- Refactor `runparts` and `/etc/rc.local` to no longer block the main
  loop, allowing `initctl` calls to interact with Finit.  Issue #356
- Refactor the `run` stanza to no longer block the main loop, issue #362
- Allow `sulogin` with a user different from `root`, issue #357
- Allow disabling invocation of rescue mode from kernel command line
- Add `initctl -f` to force-skip asking Finit for existing services
  when creating new services during bootstrap, e.g. `/etc/rc.local`
- `initctl runlevel` now returns `N S` instead of `N 10` in bootstrap
- `initctl runlevel N` during bootstrap is now allowed.  It changes
  the next runlevel to go to when bootstrap has completed.  Effectively
  overriding the `runlevel N` statement in `/etc/finit.conf`
- Improved logging on failure to `execvp()` a run/task/service, now
  with `errno`, e.g., "No such file or directory" when the command
  is missing from `$PATH`
- Add Bash completion support for `initctl`, configurable, issue #360
- Handle absolute path to `initctl [enable|disable]`, not supported
- Update `finit.conf(5)` man page with the recommended directory
  hierarchy in `/etc/finit.d/`
- The `runparts` code has been split into `/libexec/finit/runparts`
- The `runparts` command now takes two options: `sysv` and `progress`.
  The former ensures only `SNNfoo` and `KNNfoo` scripts are run.
- Add SysV Init Compatibility section to documentation
- Increased MAX path for commands, and arguments: 64 -> 256
- The bundled watchdog daemon no longer tries to log at startup, because
  syslog is not available yet, any startup message leak to console
- Extend `if:` option with runtime evaluation of conditions.  E.g., start
  a task only `if:<run/foo/failure>` (here the run task 'foo' failed)
- Document new `if:`, `conflict:`, `nowarn` options for run/task/service
  first introduced in v4.4
- Failure to open fstab should log to console, not just log to `/dev/kmsg`
- Rename `/lib/finit/system/*.conf`, added numbered prefix to ensure
  proper execution order, e.g., `udevd` should always run first
- Plugins and bundled services: dbus, keventd, watchdogd, and runparts,
  are now loaded *after* all services in `/lib/finit/system/`.  A new
  runtime-only path (for inspection) in `/run/finit/system/` is used
- Redirect `log*` output to console when `finit.debug` is enabled
- Assert `<int/container>` condition if we detect running in container
- Add support for mdev's netlink daemon mode, issue #367
- Add support for mdevd in `10-hotplug.conf`, preferred over plain mdev
- Disable modprobe plugin by default, udevd and mdev/mdevd loads modules
- Update documentation for run/task shell limitations, issue #376
- Update documentation regarding automount of `/run` and `/tmp`
- Update plugin documentation, add section about limited tmpfiles.d(5) support
- Skip registering service when `if:!name` matches a known service.
  This allows conditional loading of alternative services, e.g. if udevd
  is already loaded we do not need mdevd
- Drop `doc/bootstrap.md`, inaccurate and confusing to users

### Fixes
- Fix #227: believed to have been fixed in v4.3, the root cause was
  actually that Finit was waiting for a process that was no longer in
  the system.  The fix is to ask the kernel on process-stop-timeout and
  replay the lost PID so that Finit can continue with reboot/shutdown
- Fix #358: fix inotify events for `/etc/finit.conf`, improved log
  messages and error handling
- Fix #361: cgroup move fail if run/task/services start as non-root.
  Regression in the v4.4 release cycle while adding support for the
  pre:/post:/ready: scripts.  Now the latter scripts also properly run
  in their correct cgroup
- Fix #366: document `fsck.*` kernel command line options and simplify
  the configure flags `--enable-fsckfix` and `--enable-fastboot` to
  only adjust the default values for the `fsck.*` options.
- Fix #371: swap load order of `/lib/finit/system/*` vs `/etc/finit.d/*`
  We must run `10-hotplug.conf` first to ensure devices and modules are
  up and loaded before the user's run/task/services are called.  The order
  at bootstrap is now saved in `/run/finit/conf.order` for inspection,
  `/run/finit/exec.order` shows the start order of each process
- Fix #372: lost `udevadm` calls due to overloading
- Adjust final `udevadm settle` timeout: 5 -> 30 sec
- Fixed dbus plugin, the function that located `<pidfile> ...` in the
  `dbus/system.conf` caused spurious line breaks which led to the
  service not being loaded properly
- The `runparts` executor now skips backup files (`foo~`)
- The `runparts` stanza now properly appends ` start` to scripts that
  start with `S[0-9]+`.  This has been broken for a very long time.
- Fix #377: expand service `env:file` variables, allow constructs like:

        RUNDIR=/var/run/somesvc
        DAEMON_ARGS=--workdir $RUNDIR --other-args...
- Fix #378: warn on console if run/task times out during bootstrap
- Fix #378: add run/task support for `<!>` to allow transition from
  bootstrap to multi-user runlevel even though task has not run yet.
- Fix #382: do not clear `<service/foo/STATE>` conditions on reload.  
  Introduced back in v4.3-rc2, 82cc10be8, the support for automatic
  service conditions have had a weird and unintended behavior.  Any
  change in state (see `doc/svc-machine.png`) caused Finit to clear
  out *all* previously acquired service conditions.

  However, when moving between RUNNING and PAUSED states, a service
  should not have its conditions cleared.  The PAUSED state, seen
  also by all conditions moving to FLUX, is only temporary while an
  `initctl reload` is processed.  If a service has no changes to be
  applied it will move back to RUNNING.

  Also, we cannot clear the service conditions because other run/task
  or services may depend on it and clearing them would cause Finit to
  `SIGTERM` these processes (since they are no longer eligible to run).


[4.4][] - 2023-05-15
--------------------

> **Note 1:** this release contains changes to the `.conf` parser.  If you
> have .conf file statements with comment character (`#`) in the command
> options or description, you must now escape them (`\#`).  Issue #186
>
> **Note 2:** prior to this release, runlevel `S` and `0` were after
> boot treated as the same runlevel.  This caused `task [06] ...`  to
> also run at bootstrap instead of just at shutdown and reboot.  The
> changes made to Finit to separate `S` from `0` require you to update
> the allowed runlevels for services that are allowed to continue
> running at shutdown.  I.e., change `[S123456789]` to `[S0123456789]`
> for, e.g., `sysklogd`.  Issue #352

### Changes
* Add limited tmpfiles.d(5) support

  This change adds very basic `tmpfiles.d/` support to Finit.  Most of
  the basic types are supported, but not all, so for now, please check
  the code and examples for details on what is working.

* If a run/task/service command does not exist, skip registering it

  This changes the semantics of Finit a bit by checking for the command
  to run when registering it, skipping commands that cannot be found in
  the absolute path provided in the command, or in `$PATH`

  This change includes a new `nowarn` flag that can be used to prevent
  Finit from warning for missing commands.  See below for an example.

* Add run/task/service support for `conflict:foo` handling
* Add run/task/service support for `if:[!]ident` and `if:<[!]cond>`

  Conditional loading of stanza depending on ident is already loaded (or
  not), or condition satisfied (or not).  E.g., do not run `mdev` if we
  found and registered `udevd`, or load service only if `<boot/testing>`
  condition is set.

  The optional leading `!` negates the comparison, if NOT foo then ...

* Add support for static services in `/lib/finit/system/*.conf`

  Slowly migrating away from hard-coded services in plugins.  This way
  it's possible for the user to both inspect and override as needed.

* Migrate hotplug plugin to a conditional `/lib/finit/system/hotplug.conf`

  This is the first example of the just minted advanced stanza syntax with
  `if:`-statements, `conflict:` handling, and `nowarn` flags.

* Initial support for template services, `foo@.conf`, similar to systemd

        $ initctl show avahi-autoipd@
        service :%i avahi-autoipd --syslog %i -- ZeroConf for %i

  To enable ZeroConf for, e.g., `eth0`, use

        $ initctl enable avahi-autoipd@eth0.conf

  The enabled symlink will be set up to `avahi-autoipd@.conf` and every
  instance of `%i` will in the instantiated directive be replaced with
  `eth0`.  Inspect the result with:

        $ initctl status avahi-autoipd:eth0

* Add `devmon`, a `<dev/foo>` condition provider, issue #185
* Support for line continuation character `\` in .conf files, issue #186

        service name:sysklogd [S123456789]   \
            env:-/etc/default/sysklogd       \
            syslogd -F $SYSLOGD_ARGS         \
            -- System log daemon

* `HOOK_BASEFS_UP` has been moved!  External plugins that need to call
  `service_register()`, please use `HOOK_SVC_PLUGIN` from now on.  
  Apologies for any inconveniences this might cause!
* getty: add support for `/etc/os-release` to replace `uname` output  
  This change, which has a fallback to `/usr/lib/os-release`, overrides
  traditional modifiers with the os-release variant.  These values were
  taken from `uname`, which on Linux systems are pretty useless since
  they always return the kernel name and version instead of the
  distro/OS values.

  E.g., \s becomes `PRETTY_NAME` instead of 'Linux' and \v becomes the
  pretty `VERSION`, while \r becomes `VERSION_ID`.
* Support for overriding `/etc/finit.conf` and `/etc/finit.d` issue #235  
  New (kernel) command line option `finit.config=PATH` which can be used
  to redirect Finit to start up with, e.g., `/etc/factory.conf` instead of
  `/etc/finit.conf`.

  For the complete experience a new top-level configuration file directive
  `rcsd PATH` has also been added.  It in turn can be used by `factory.conf`
  as follows to override `/etc/finit.d`:

        rcsd /etc/factory.d

* Support for overriding `/etc/finit.d` from the alternate `finit.conf`
  with a new `rcsd /path/to/dot.d/` .conf file directive
* Support for `fsck_mode=[auto,skip,force]` + `fsck_repair=[preen,no,yes]`
* Add `set` keyword for environment variables set in `/etc/finit.conf`
* Support `finit.cond=foo` cmdline `<boot/foo>` conditions, issue #250
* `initctl` JSON output support for status and conditions, issue #273  
  Example:

        root@infix:~$ initctl status -j resolvconf
        {
          "identity": "resolvconf",
          "description": "Update DNS configuration",
          "type": "task",
          "forking": false,
          "status": "done",
          "exit": { "code": 0 },
          "origin": "/etc/finit.d/enabled/sysrepo.conf",
          "command": "resolvconf -u",
          "restarts": 0,
          "pidfile": "none",
          "pid": 0,
          "user": "root",
          "group": "root",
          "uptime": 0,
          "runlevels": [ 1, 2, 3, 4, 5, 7, 8, 9 ]
        }

  The excellent tool `jq` can be used to extract parts of the output for
  further scripting.  E.g. `initctl status -j foo | jq .exit.status`

* Add JSON support to `initctl ls` command  

  This allows for easy access to the *disabled* services:

        root@anarchy:~# initctl ls --json |jq '.available - .enabled'
        [
          "chronyd.conf",
          "dnsmasq.conf",
          "gdbserver.conf",
          "inadyn.conf",
          "inetd.conf",
          "isisd.conf",
          "lldpd.conf",
          "mstpd.conf",
          "ntpd.conf",
          "ospf6d.conf",
          "ospfd.conf",
          "querierd.conf",
          "ripd.conf",
          "ripng.conf",
          "sshd.conf",
          "syslogd.conf",
          "telnetd.conf",
          "uftpd.conf",
          "wpa_supplicant.conf",
          "zebra.conf"
        ]

* Allow `manual:yes` on sysv/service/run/task stanzas, issue #274
* Add support for `oncrash:script` to call the `post:script` action, if
  defined, for a crashing service.  The `EXIT_CODE` variable sent to the
  script is set to `crashed`. Issue #282
* Search for plugins in `/usr` and `/usr/local` as well, issue #284
* tty: add support for `passenv` flag to `/bin/login`, issue #286
* Add reboot/shutdown/poweroff timeout `-t SEC` to initctl, issue #295
* Add support for s6 and systemd readiness notification, issue #299.  
  Service readiness notification to support daemons employing systemd
  and s6 notification.  Complementing the native Finit readiness support
  using PID files that exist already.

  The two have slightly different ways of implementing readiness:

  - https://www.freedesktop.org/software/systemd/man/sd_notify.html
  - https://skarnet.org/software/s6/notifywhenup.html

  Finit now provides both a `NOTIFY_SOCKET` environment variable, for
  systemd, and a way to start s6 daemons with a descriptor argument.

  For details on the syntax, see the `service` documentation.

  This change also renames internal states for run/task/services to
  avoid any confusion with the introduction of `ready:scripts`:

  - `WAITING -> PAUSED`
  - `READY   -> WAITING`

  A service condition that used, e.g., `<service/foo/ready>` should now
  instead use `<service/foo/waiting>`

* Add `ready:script` for services, called when daemon is ready, issue #300
* Add support for running scripts at shutdown at two new hook points
  during the shutdown process, issue #302. See doc/plugins.md for details:

  - `HOOK_SVC_DN`: after all services and non-reserved processes have been
    killed (and collected)
  - `HOOK_SYS_DN`: after all file systems have been unmounted, *just prior*
    to Finit calling `reboot()` to shut down or reboot the system

* The `modules-load` plugin now default to runlevel `[S]`, in previous
  releases it was `[2345]`.  This breaking change is to align it more
  with what users mostly want (modules loaded before services start) and
  can be changed back to the old behavior with a per-file setting:

        set runlevel 2345

* The `modules-load` plugin now adds silent tasks for modprobe.  This to
  prevent confusing `[ OK ]` boot messages when in fact modprobe failed.
* The `modules-load` plugin now support `set modprobe /path/to/modprobe`
* The header files `finit/conf.h` and `finit/service.h` are now exported
  for external plugins
* Add support for multiple args to `initctl cond set/clr`, issue #329
* Silence confusing `[ OK ]` progress from modules-load plugin, issue #332  

  This change drops the confusing status progress output, which was always
  OK since the actual modprobe operation runs in the background.  No need
  to show status of the "added a task to finit, found modprobe" command.

* dbus plugin: adapt to other operating systems

  Not all Linux systems are based on Debian, and even if they are inspired
  by Debian (Buildroot), they do not necessarily use the same defaults.
  Probes the system at runtime for:

  - dbus user and group
  - dbus PID file

  If the user/group cannot be found we fall back to `root`, if the PID
  file cannot be determined we ignore PID file readiness.

* Improve documentation for runparts and hook scripts.  Issue #315, #320
* Add `HOOK_NETWORK_DN`, called after change to runlevel 6 or 0, issue #319
* Use sysklogd `logger` tool instead of legacy `logit` tool, issue #344

  For log redirection Finit has the legacy `logit` tool.  This change
  allows Finit to use the `sysklogd` project's extended `logger` tool
  instead, when available.  Allowing logging with the process' PID.

* Add `initctl` aliases: `cat -> show`, `kill -> signal`
* Add `initctl -n,--noerr` to return OK(0) if services do not exist, for
  integration with openresolv and scripts with similar requirements
* Add `initctl plugins`, list installed plugins
* Add timestamp to log messages in fallback and logging to `stderr`.  
  When there is no log daemon, and we are running in a container, or we
  cannot log to the kernel ring buffer, then we log to `stderr`.  This
  change improves log output by prefixing each message with a timestamp.

### Fixes
* Fix #254: document limitations in `rc.local` and `runparts` scripts
* Fix #269: add compulsory kernel symlinks in `/dev`
* Fix #275: `initctl status foo` should list all instances, regression
  introduced in v4.3
* Fix #278: enforce conditions also for running `pre:` scripts
* Fix #279: allow `restart:always`, of crashing services.  Similar to
  `respawn` but honors `restart_sec`
* Fix #280: allow calling `initctl restart foo` from within foo
* Fix #283: too quick timeout at bootstrap of lingering tasks
* Fix #285: `initctl restart` should start crashed service
* Fix #288: enable built-in `sulogin` in Alpine and Void Linux builds
* Fix #293: modprobe plugin: support for coldplugging more devices.  It
  turns out, not all buses in Linux add `modalias` attributes to their
  devices in sysfs.  One notable exception are MDIO buses.  The plugin's
  scan routine would thus not pick them up.
* Fix #294: `shutdown --help` mistakenly shuts down system
* Fix #310: Always use configured restart delay for crashing services.
  If no delay is configured, default to an initial 2000 msec for forking
  daemons and start-stop scripts, and 1 msec for non-forking daemons
* Fix #311: document how to combine device tree with conditions
* Fix #312: restart services with respawn set, e.g. ttys, immediately
* Fix #313: Cancel pending restart timer on stop/start/restart/reload
* Fix #314: skip run/task/service restart if conditions are lost
* Fix #315: add environment variables to hook scripts

  All hook scripts are called with at least one environment variable
  set, `FINIT_HOOK_NAME`, useful when reusing the same hook script for
  multiple hook points.  It is set to the string name, also used by the
  path, e.g., `hook/net/up`

  For all hook points from hook/sys/shutdown and later, `FINIT_SHUTDOWN`
  is also set, to one of: `halt`, `poweroff`, `reboot`

* Fix #317: make sure hook scripts don't run twice, also fixes #316
* Fix #318: only show `[ OK ] Calling foo` progress for `runparts ...`
* Fix #320: the API/IPC socket is closed immediately at shutdown/reboot
  to protect hook scripts or services calling initctl.  There is no way
  to service these requests safely at that time
* Fix #333: consider a service dirty if command line args have changed

  This fixes `initctl reload` correctly restarting all daemons that have
  new command line arguments.

  Previously command line arguments changes were only acted upon if the
  service was explicitly reloaded `initctl reload myservice`.

  Found and fixed by Jack Newman

* Fix #338: ensure shutdown hooks are called properly; `hook/sys/down`
  and `hook/svc/down` hook scripts, found and fixed by Jack Newman
* Fix #339: use absolute path in `/etc/finit.d/enabled/` symlinks, for
  use-cases when `/etc` is read-only and `/etc/finit.d/enabled ->
  /mnt/finit.d/enabled`, reported by Jack Newman
* Fix #340: Finit ignores deleted/moved `.conf` file sin `/etc/finit.d`
* Fix #342: in runlevel S (bootstrap), not all `initctl` commands can be
  supported, block the following: runlevel, reload, start/stop, restart,
  reload, halt, poweroff, suspend.  Also, prevent `SIGHUP` and `SIGUSR1`
  signals when in shutdown or reboot
* Fix #352: separate runlevel S from runlevel 0
* Fix #355: regression in v3.2 stopping a process and its group

  In Finit v3.2 a regression was introduced that affects the way Finit
  stops a supervised process and its process group.

  Instead of sending SIGTERM to the process, and thus delegating the
  responsibility to that process to inform any children it may have, as
  of commit 91a9c83 Finit sends SIGTERM to the entire process group.
  For SIGKILL this is fine, SIGKILL only runs as cleanup and as a last
  ditch effort if the process doesn't respond to SIGTERM.

  This regression, introduced in v3.2, directly affects services like
  `avahi-autoipd` that have forked off children that it needs to tell to
  exit cleanly before it returns.  With the patch in question these
  children are never allowed to complete, which in turn causes lingering
  169.254 link-local addresses on interfaces.

* Fix bootmisc plugin: octal permission on `/run/lock` and `/var/lock`

* Ensure `initctl cond get` support the flux state (exit code 255)
* Fix potential socket leak at bootstrap and shutdown
* Fix potential NULL pointer deref in kernel command line parser
* Fix lingering condition in service after reload of service with new
  config that has no condition
* Fix wrong path to command in service after reload, may have changed
* `logit`: fall back to package name if `$LOGNAME` and `$USER` are
  unset.  **Note:** you should probably not use `logit` in your own
  scripts, it is only meant for internal use by Finit.  We recommend
  using `logger` from the `bsdutils` or `sysklogd` packages instead
* Fix issue where `env:`/`pre:`/`post:`/etc. is removed from a service

  The trick is when reloading a service like this:

        service env:/etc/env    serv -np -e foo:bar

  into this:

        service pre:/bin/pre.sh serv -np

  In the second the `env:` has been removed and `pre:` added.  Prior to
  this patch, `env:` was kept leading to unintended behavior.
* Fix parse/diff of command line args, e.g., `nginx -g 'daemon off;'`

  Starting a service like this works fine:

        service [2345789] env:-/etc/default/nginx nginx -g 'daemon off;'

  However, on `initctl reload` (and no change to .conf files) the arg
  list was lost while parsing the .conf files.  Leading to a false
  positive 'diff' in args causing nginx to be unnecessarily restarted.
* Fix issue with disabled "linewrap" on the console TTY after login.
  The root cause is `qemu-system-x86_64 -nographics` disabling it when
  starting up.  The correct `\e[?7h` escape code is now used.


[4.3][] - 2022-05-15
--------------------

Critical bug fix release.  If you run a 32-bit target with GLIBC 2.34
you *need* to upgrade!

> **Note:** system verbosity on console at start and shutdown has been
>           increased.  Now the output of all commands is logged to the
>           system logger, for early services `/dev/kmsg` is used.
>
> **Also:** please notice the updated support for enabling and disabling
>           kernel and Finit debug messages on the system console.  Very
>           useful when debugging either of them, e.g., a kernel module.
>           For details, see [cmdline.md](doc/cmdline.md).

### Changes
* Support for overriding default runlevel from kernel command line.  Any
  runlevel `[1-9]` may be selected, except 6 (reboot).  Issue #261
* New command line option: `finit.fstab=/etc/fstab.custom`, with full
  support for mounting, mount helpers, fsck, and swapon/off, issue #224
* Support for special device `/dev/root`, which may not exist in `/dev`.
  Finit now looks up the matching block device for `/` in `/sys/block/`
* Loading `module`s no longer shows arguments in progress output
* Warning messages in progress output now in yellow, not red, issue #214
* `initctl`, new command line option `-V,--version` for ease of use
* New condition `done` for run task, issue #207 by Ming Liu, Atlas Copco
* Refactor parts of shutdown and reboot sequence for PREEMPT-RT kernels,
  by Robert Andersson, Mathias Thore, and Ming Liu, Atlas Copco
* Conditions for run/task/sysv status, e.g. `run/foo/success` and
  `task/bar/failure`.  Issue #232, by Ming Liu, Atlas Copco
* Conditions for services, can be used to synchronize other stanzas:
  - `service/foo/running`
  - `service/foo/halted`
  - `service/foo/missing`
  - `service/foo/crashed`
  - `service/foo/stopped`
  - `service/foo/busy`
  - `service/foo/restart`
* `initctl signal` support, by Jörgen Sigvardsson, issue #225
* `initctl cond get` support to match `cond [set | clear]`, issue #255
* `[WARN]` messages on console now printed in yellow, issue #214
* Network services now also stopped when going to runlevel 6 (reboot),
  not just runlevel 0 (shutdown) or 1 (single-user)
* When `ifup` is missing on the system, bring at least `lo` up at boot
* Log output from `ifup -a` (and `ifdown -a`), to syslog
* Avoid blocking PID 1 when starting SysV init scripts
* Allow custom `pid:` for SysV init scripts
* Document supported types of forking/non-forking services
* Auto-detect running in some common forms of containers
* Simplify shutdown/reboot when running in a container
* Log to `stderr` when running in a container w/o syslog daemon
* Add support for `type:forking` to services, already supported but
  with a very difficult `pid:` syntax, issue #223.  Docs updated
* Support for setting global environment variables in `finit.conf`,
  please note: this also affects Finit itself, be careful!
* Extended environment variables for pre/post scripts, issue #189
* Document secret service option `respawn`, which bypasses the crash
  semantics, allowing endless restarts
* Document secret `HOOK_BANNER`, the first hook point before the banner
* Document slightly confusing `initctl reload foo` command.  It does
  *not* reload the service's `.conf` file!  Issue #263
* Log changes; all instances where previously the `basename cmd` of a
  service was used to identify the service, now the proper `name:id` is
  used instead.  Meaning, a service without a custom `:ID` or `name:`
  will display the same as before, but with any of those customizations
  the name and name:id will now be shown.  **Note:** this may affect any
  log scrapers out there!
* New plugin: `hook-scripts`, allows [run-parts(8)][] style scripts to
  run on any hook point.  Contributed by Tobias Waldekranz
* `initctl` (`reboot`) falls back to `-f` when it detects it is in
  `sulogin` recovery mode, issue #247
* The bundled `sulogin` is no longer enabled by default, in favor of
  distribution versions.  Enable with `./configure --with-sulogin`
* Support args to sysv-like scripts, e.g. `bridge-stp br0 start`
* The `modules-load` plugin now skips all lines starting with `#` and
  `;`.  Furthermore, files in `/etc/modules-load.d/*.conf` are now read
  in lexicographic order and UNIX backup files (`foo.conf~`) are skipped
* The `name:id` tuple is now more consistently used in all log and debug
  messages instead of the basename of the command
* Simplify error output of `initctl start/stop/restart/signal`, no more
  extra usage help, just a plain error message
* Exit codes of `initctl` have changed to use LSB script standard and BSD
  sysexits.h exit codes.  As before, a non-zero exit is error or missing
* Add support for `initctl -q` to more commands: stop, start, restart,
  reload, signal, etc.

[run-parts(8)]: https://manpages.debian.org/cgi-bin/man.cgi?query=run-parts

### Fixes
* Fix nasty 32/64-bit alignment issue between finit and its plugins,
  applicable to 32-bit targets with GLIBC 2.34 and later.  External
  plugins must make sure to use, at least: `-D_TIME_BITS=64`
* Fix #215: disable cgroup support at runtime if kernel lacks support
  or does not have the required controllers (cpu)
* Fix #217: iwatcher initialization issue, by Ming Liu, Atlas Copco
* Fix #218: initctl matches too many services, by Ming Liu, Atlas Copco
* Fix #219: not all filesystems unmounted at shutdown, by Ming Liu, 
  Mathias Thore, and Robert Andersson, Atlas Copco
* Fix #226: initctl shows wrong PID for crashing services
* Fix #227: reboot stalls if process stopped with `[WARN]`
* Fix #233: initctl shows wrong status for run/task, by Sergio Morlans
  and Ming Liu, Atlas Copco
* Fix #248: source `env:file` also in `pre:` and `post` scripts
* Fix #260: drop limit on device name in `Checking filesystem...` output
* Fix start/stop and monitoring (restart) of SysV init scripts and
  forking services, see the updated documentation for details
* Fix call to `swapoff` at shutdown, does not support `-e` flag
* Fix suspend to RAM issue.  Previously `reboot(RB_SW_SUSPEND)` was
  used, now the modern `/sys/power/state` API is used instead.
* Fix nasty run/task/service matcher bug, triggered by stanzas using the
  same basename of a command but different `:ID`.  Caused Finit to match
  with already registered but different run/task/service


[4.2][] - 2022-01-16
--------------------

### Changes
* Support for non-root users to use `initctl`, e.g. group wheel
* Support for new libite (-lite) header namespace
* RTC plugin now reset an invalid RTC time to the kernel default
  time, 2000-01-01 00:00, prevents errors and is less crazy than
  some systems coming with with <= Jan 1, 1970
* urandom plugin now use RNDADDENTROPY ioctl to seed kernel rng,
  incrementing entropy count.  Also, 32 kiB instead of 512 bytes are
  now saved (and restored) on reboot.  This should greatly improve
  reliability of systems with none or poor HWRNG
* Kernel logging to console (loglevel >= 7, debug, when quiet mode is
  not used) is now honored by Finit, regardless of the finit.debug
  command line option
* Reduced default log level from `LOG_NOTICE` to `LOG_INFO`
* Wrapped all calls to mount(2) to add logging in case of failure
* New configure options to control fastboot (no fsck) and fsck fix
  options, by Ming Liu, Atlas Copco
* Support for overriding default `/etc/nologin` file with an external
  `#define`, by Ming Liu, Atlas Copco
* Support for overriding default `/var/run/dbus/pid` file with an
  external `#define`, by Ming Liu, Atlas Copco
* Support for more service options to control respawn behavior of
  crashing services, by Robert Andersson and Ming Liu, Atlas Copco
* Support for `initctl ident [NAME]` which lists all instances of
  `NAME`, or all enabled system run/tasks and services
* Show number of total restarts and current respawn count for a
  service in `initctl status foo`
* Crashing services no longer have the crash/restart counter reset as
  soon as they have stabilized.  Instead, a background timer will
  slowly (every 300 sec) age (decrement) the counter.  This will still
  catch services that "rage quit", but also those that crash after a
  longer period of activity

### Fixes
* Fix #180: user managed (`manual:yes`) services accidentally started
  by `initctl reload`, regression introduced in Finit v4.0
* Fix #181: lots of typos all over the tree, by David Yang, Debian
* Fix #187: fix typos, incl. small cleanup, in doc/bootstrap.md
* Fix #188: support running on kernels that do not have cgroups v2.
  When this is detect, all functions related to cgroups support in
  Finit are disabled, *except* the .conf file parser.  Hence, you
  may get parse error if you have invalid cgroup configuration in
  your Finit .conf files
* Fix #197: `initctl status foo` now shows a focused overview of all
  matching instances; foo:1, foo:2 -- if only one instance matches the
  command line argument, or if onle one instance exists, the detailed
  view is shown, as before
* Fix #198: a few typos found by Tim Gates
* Fix #199: avoid using C++ reserved keywords
* Fix #201: memory leak in usr condition plugin, by Ming Liu, Atlas Copco
* Fix #203: ensure all filesystems listed in /proc/mounts are properly
  unumounted on shutdown/reboot, by Robert Andersson, Atlas Copco
* Fix #210: resizing terminal (smaller) after boot causes empty lines
  to be inserted between boot progress
* Fix #211: drop hard-coded 32 character limit in getty, now reads
  `_SC_LOGIN_NAME_MAX` from `sysconf(3)`
* Fix #212: service PID file lost after inictl reload, visible from
  the output from `initctl status foo`


[4.1][] - 2021-06-06
--------------------

Bug fix release.  Also disables handlers for `SIGINT` and `SIGPWR`, a
new set of `sys` conditions are instead generated which can be used to
trigger external programs.

### Changes
* Change behavior on SIGUSR1 to be compatible with sysvinit and systemd.
  Previously SIGUSR1 caused Finit to halt, like BusyBox init.  This had
  "interesting" side effects on Debian systems when coexisting with
  sysvinit (upgrading/reinstalling causes scripts to `kill -USR1 1`)
* Change how `contrib/debian/install.sh` sets up a Grub boot entry for
  finit.  We now modify the $SUPPORTED_INITS variable in `10_linux`
* Disable default kernel ctrl-alt-delete handler and let Finit instead
  catch `SIGINT` from kernel to be able to perform a proper reboot.
  There is no default command for this, you need to set up a task that
  triggers on `<sys/key/ctrlaltdel>` to issue `initctl reboot`
* Added keventd to provide `<sys/pwr/ac>` condition to Finit.  keventd
  is currently only responsible for monitoring `/sys/class/power_supply`
  for changes to active AC mains power online status.  Enable keventd
  with `configure --with-keventd`
* For handling power fail events (from UPS and similar) a process may
  send `SIGPWR` to PID 1. Finit no longer redirects this to `SIGUSR1`
  (poweroff).  There is no default command for this, you need to set up
  a task that triggers on `<sys/pwr/fail>` to issue `initctl poweroff`
* Built-in Finit getty is now a standalone program
* Default termios for TTYs now enable `IUTF8` on input
* If `/bin/login` is not found, Finit now tries `sulogin` before it
  falls back to an unauthenticated `/bin/sh`
* Dropped (broken) support for multiple consoles.  Finit now follows
  the default console selected by the kernel, `/dev/console`
* Dropped signal handlers for SIGSTOP/TSTP and SIGCONT
* Added support for `\n`, in addition to `\r`, in "Please press Enter"
  prompt before starting getty
* Finit no longer parses `/proc/cmdline` for its options.  Instead all
  options are by default now read from `argv[]`, like a normal program,
  this is also what the kernel does by default.  Please note, this may
  not work if your systems boots with an initramfs (ymmv), for such
  cases, see `configure --enable-kernel-cmdline`
* The following plugins are now possible to disable (for containers):
  `rtc.so`, `urandom.so`, you may also want to disable `hotplug.so`.
  They are all enabled by default, as in Finit 4.0, but may be moved
  to external tools or entries in `finit.conf` in Finit 5.0
* Added support for reading `PRETTY_NAME` from `/etc/os-release` to use
  as heading in progress output, unless `--with-heading=GREET` is used.
* Added manual pages for finit(8), initctl(8), and finit.conf(5)

### Fixes
* Stricter interface name validation in netlink plugin, modeled after
  the kernel.  Suggested by Coverity Scan
* Fix problem of re-registering a service as a task.  Previously, if a
  fundamental change, like type, was made to an active service/run/task
  it did not take.  Only possible workaround was to remove from config
* initctl: drop warning when removing a non-existing usr condition
* initctl: drop confusing `errno 0` when timing out waiting for reply
* Ensure services in plugins and from Finit main belong to a cgroup
* Ensure init top-level cgroup remains a leaf group
* Fix tty parse error for detecting use of external getty
* Fix default `name:` and `:ID` for tty's, e.g. `ttyS0` now gives
  `tty:S0` as expected.  This was default for built-in getty already
* Fix max username (32 chars) in bundled Finit getty
* The `contrib/*/install.sh` scripts failed to run from tarball
* Finit no longer forcibly mounts; `/dev`, `/proc`, or `/sys`, instead
  it checks first if they are already mounted (devtmpfs or container)
* Fix `/etc/fstab` parser to properly check for 'ro' to not remount the
  root filesystem at boot.  The wrong field was read, so a root mounted
  by an initramfs, or by lxc for a container, had their root remounted
* Fix SIGCHLD handler, `waitpd()` may be interrupted by a signal
* Reset `starting` flag of services being stopped.  When a service
  is started and then stopped before it has created its pid file,
  it could be left forever in the stopping state, unless we reset
  the starting flag.
* Fix #170: detect loss of default route when interfaces go down.  This
  emulates the missing kernel netlink message to remove the condition
  net/default/route to allow stopping dependent services
* Fix #171: restore automatic mount of `/dev/shm`, `/dev/pts`, `/run`
  and `/tmp`, unless mounted already by `/etc/fstab`.  This is what most
  desktop systems expect PID 1 to do.  Here we also make sure to mount
  `/run/lock` as a tmpfs as well, with write perms for regular users,
  this prevents regular users from filling up `/run` and causing DoS.
* Fix #173: netlink plugin runs out of socket buffer space;

        finit[1]: nl_callback():recv(): No buffer space available

  Fixed by adding support for resync with kernel on `ENOBUFS`.  See
  netlink(7) for details.  As a spin-off the plugin now supports any
  number of interfaces and routes on a system.  On resync, the following
  message is now logged, as a warning:

        finit[1]: nl_callback():busy system, resynchronizing with kernel.

* Fix #174: loss of log messages using combo of prio and facility, e.g.,
  `logit(LOG_CONSOLE | LOG_NOTICE, ...)`, by Jacques de Laval, Westermo
* Fix #175: ensure Finit does not acquire a controlling TTY when checking
  if a device is a TTY before starting a getty.  This fixes an old bug
  where Ctrl-C after logout from a shell could cause PID 1 to get SIGINT,
  which in turn could lead to a system reboot


[4.0][] - 2021-04-26
--------------------

This release became v4.0, and not v3.2, because of incompatible changes
to service conditions.  There are other significant changes as well, so
make sure to read the whole change log when upgrading.

### Changes
* The stand-alone `reboot` tool has been replaced with a symlink to
  `initctl`, like its siblings: halt, shutdown, poweroff, and suspend.
  Calling `reboot` & C:o now defaults to the corresponding `initctl cmd`
  with a fallback to sending signals as per traditional SysV init.  The
  `-f` (force) flag remains, where `reboot(2)` is called directly
* Introducing Finit progress 𝓜𝓸𝓭𝓮𝓻𝓷
* The `inictl cond set|clear COND` have changed completely.  Constrained
  to a flat `<usr/...>` namespace and automatically activated by a new
  `usr.so` plugin that checks services for usr condition changes
* Removed built-in inetd super server.  If you need this functionality,
  use an external inetd, like xinetd, instead.  A pull request for a
  stand-alone inetd, like watchdogd and getty, is most welcome!
* Incompatible `configure` script changes, i.e., no guessing `--prefix`
  and other paths.  Also, many options have been changed, renamed, or
  flipped defaults, or even dropped altogether.  There are examples in
  the documentation and the `contrib/` section
* Service conditions change from the non-obvious `<svc/path/to/foo>` to
  `<pid/foo:id>`.  Not only does this give simpler internal semantics,
  it hopefully also makes it clear that one service's `pid:!foo` pidfile
  is another service's `<pid/foo>` condition, issue #143
* Initial support for cgroups v2:
  - services runs in a cgroup named after their respective *.conf file
  - top-level groups are; init, user, and system
  - all top-level groups can be configured from finit *.conf files
  - each service can tweak the cgroup settings
  - Use `initctl [top|ps|cgroup]` commands to inspect runtime state
  - https://twitter.com/b0rk/status/1214341831049252870?s=20
* Major refactor of Finit's `main()` function to be able to start the
  event loop earlier.  This also facilitated factoring out functionality
  previously hard-coded in Finit, e.g., starting the bundled watchdogd,
  various distro packed udevd and other hotplugging tools
* A proper rescue mode has been added.  It is started extremely early
  and is protected with a bundled `sulogin`.  Exiting rescue mode now
  brings up the system as a normal boot, as one expects
* Support for `sysv` start/stop scripts as well as monitoring forking
  services, stared using `sysv` or `service` stanza
* Support for custom `kill:DELAY`, default 3 sec.
* Support for custom `halt:SIGNAL`, default SIGTERM
* Support for `pre:script` and `post:script`, allows for setup and
  teardown/cleanup before and after a service runs, issue #129
* Support for `env:file` in `/etc/default/foo` or `/etc/conf.d/foo`, see
  the contrib section for examples that utilize this feature.  Variables
  expanded from env files, and the env files themselves, are tracked for
  changes to see if a service .conf file is "dirty" and needs restart on
  `initctl reload`
* Support for tracking custom PID files, using `pid:!/path/to/foo.pid`,
  useful with new `sysv` or `service` which fork to background
* Support starting run/task/services without absolute path, trust `$PATH`
* Add support for `--disable-doc` and `--disable-contrib` to speed up
  builds and work around issue with massively parallel builds
* Support for `@console` also for external getty
* Support for `notty` option to built-in getty, for board bring-up
* Support for `rescue` option to built-in getty, for rescue shells
* Add `-b`, batch mode, for non-interactive use to `initctl`
* Prefer udev to handle `/dev/` if mdev is also available
* Redirect dbus daemon output to syslog
* Set `$SHELL`, like `$PATH`, to a sane default value, needed by BusyBox
* Finit no longer automatically reloads its `*.conf` files after running
  `/etc/rc.local` or run-parts.  Use `initctl reload` instead.
* `initctl` without an argument or option now defaults to list services
* Convert built-in watchdog daemon to standalone mini watchdogd, issue #102
* Improved watchdog hand-over, now based on `svc_t` and not PID
* Extended bootstrap, runlevel S, timeout: 10 --> 120 sec. before services
  not allowed in the runtime runlevel are unconditionally stopped
* Removed `HOOK_SVC_START` and `HOOK_SVC_LOST`, caused more problems
  than they were worth.  Users are encouraged to use accounting instead
* Skip displaying "Restarting ..." progress for bootstrap processes
* Added a simple work queue mechanism to queue up work at boot + runtime
  - Postpone deletion of `svc_t` until any `SIGKILL` timer has elapsed
  - As long as a stepped service changes state we queue another step all
    event, because services may depend on each other
* Require new libuEv API: `uev_init1()` to reduce event cache so that
  the kernel can invalidate deleted events before enqueuing to userspace
* Rename `hwclock.so` plugin to `rtc.so` since it now is stand-alone
  from the `hwclock` tool.  Note: the kernel can also be set to load
  and store RTC to/from system clock at boot/halt as well, issue #110
* New plugin to support cold plugging devices, auto-loading of modules
  at boot.  Detects required modules by reading `/sys/devices/*`
* New plugin for `/etc/modules-load.d/` by Robert Andersson, Atlas Copco
* New `name:foo` support for services, by Robert Andersson, Atlas Copco
* New `manual:yes` support for services, by Robert Andersson, Atlas Copco
* New `log:console` support for services, by Robert Andersson, Atlas Copco
* Support for `:ID` as a string, by Jonas Johansson, Westermo
* Support for auto-reload, instead of having to do `initctl reload`,
  when a service configuration has changed.  Disabled by default, but
  can be enabled with `./configure --enable-auto-reload`
* Support for logging security related events, e.g., runlevel change,
  star/stop or failure to start services, by Jonas Holmberg, Westermo
* Mount devtpts with recommended `ptxmode=0666`
* Mount /run tmpfs with nosuid,nodev,noexec for added security
* Support for `console` as alias for `@console` in tty stanzas
* Drop `--enable-rw-roots` configure option, use `rw` for your `/`
  partition in `/etc/fstab` instead to trigger remount at boot
* Drop default tty speed (38400) and use 0 (kernel default) instead
* Make `:ID` optional, use NULL/zero internally this allows ...
* Handle use-cases where multiple services share the same PID filem
  and thus the same condition path, e.g. different instances for
  different runlevels.  Allow custom condition path with `name:foo`
  syntax, creates conditions w/o a path, and ...
* Always append `:ID` qualifier to conditions if set for a service
* The IPC socket has moved from `/run/finit.sock` to `/run/finit/socket`
  officially only supported for use by the `initctl` tool
* The IPC socket now uses `SOCK_SEQPACKET` instead of `SOCK_STREAM`.
  Recommend using watchdogd v3.4, or later, which support this
* Improved support for modern `/etc/network/interfaces`, which has
  include statements.  No more native `ifup` of individual interfaces,
  Finit now calls `ifup -a`, or `ifdown -a`, delegating all details to
  the operating system.  Also, this is now done in the background, by
  popular request

### Fixes

* Fix #96: Start udevd as a proper service
* Ensure we track run commands as well as task/service, once per runlevel
* Ensure run/tasks also go to stopping state on exit, like services,
  otherwise it is unnecessarily hard to restart them
* Fix missing OS/Finit title bug, adds leading newline before banner
* Remove "Failed connecting to watchdog ..." error message on systems
  that do not have a watchdog
* Fix #100: Early condition handling may not work if `/var/run` does
  not yet exist (symlink to `/run`).  Added compat layer for access
* Fix #101: Built-in inetd removed
* Fix #102: Start built-in watchdogd as a regular service
* Fix #103: Register multiple getty if `@console` resolves to >1 TTY,
* Fix #105: Only remove /etc/nologin when moving from runlevel 0, 1, 6
  Fixed by Jonas Johansson, Westermo
* Fix #109: Support for PID files in sub-directories to `/var/run`
* Handle rename of PID files, by Robert Andersson, Atlas Copco
* Fix #110: automatic modprobe of RTC devices, built-in hwclock
* Fix #120: Redirect `stdin` to `/dev/null` for services by default
* Fix #122: Switch to `nanosleep()` to achieve "signal safe" sleep,
  fixed by Jacques de Laval, Westermo
* Fix #124: Lingering processes in process group when session leader
  exits.  E.g., lingering `logit` processes when parent dies
* Fix #127: Show all runparts scripts as they start, like rc.local, fixed
  by Jacques de Laval, Westermo
* Fix service name matching, e.g. for condition handling, may match with
  wrong service, by Jonas Holmberg, Westermo
* Run all run-parts scripts using `/bin/sh -c foo` just like the standard
  run-parts tool.  Found by Magnus Malm, Westermo
* Fix `initctl [start | restart]`, should behave the same for services
  that have crashed.  Found by Mattias Walström, Westermo
* Wait for bootstrap phase to complete before cleaning out any bootstrap
  processes that have stopped, they may be restarted again
* Reassert condition when an unmodified run/task/service goes from
  WAITING back to RUNNING again after a reconfiguration event.  
  Found and fixed by Jonas Johansson, Westermo
* Restore Ctrl-D and Ctrl-U support in built-in getty
* Remove service condition when service is deleted
* Fix C++ compilation issues, by Robert Andersson, Atlas Copco
* Build fixes for uClibc
* Provide service description for built-in watchdog daemon
* Fix #138: Handle `SIGPWR` like `SIGSUR2`, i.e., power off the system
* Drop the '%m' GNUism, for compat with older musl libc
* Fix #139: call `tzset()` on `initctl reload` to activate system
  timezone changes (for logging)


[3.1][] - 2018-01-23
--------------------

Improvements to `netlink.so` plugin, per-service `rlimit` support,
improved integration with `watchdogd`, auto-detect TTY console.  Much
improved debug, rescue and logging support.  Also, many fixes to both
big and small issues, most notably in the condition handling, which no
longer is sensitive to time skips.

This version requires at least libuEv v2.1.0 and libite v2.0.1

### Changes

* Support for more kernel command line settings:
  - splash, enable boot progress
  - debug, like `--debug` but also enable kernel debug
  - single, single user mode (no network)
  - rescue, new rescue mode
* Support for `IFF_RUNNING` to netlink plugin => `net/IFNAME/running`
* Support for restarting `initctl` API socket on `SIGHUP`
* Greatly updated `initctl status <JOB|NAME>` command
* Support for `rlimit` per service/run/task/inetd/tty, issue #45
* Support for setting `hard` and `soft` rlimit for a resource at once
* Support for auto-detecting serial console using Linux SysFS, the new
  `tty @console` eliminates the need to keep track of different console
  devices across embedded platforms: `/dev/ttyS0`, `/dev/ttyAMA0`, etc.
* Add TTY `nologin` option.  Bypasses login and skips immediately to a
  root shell.  Useful during board bringup, in developer builds, etc.
* Support for calling run/tasks on Finit internal HOOK points, issue #18
* Removed support for long-since deprecated `console DEV` setting
* Cosmetic change to login, pressing enter at the `Press enter to ...`
  prompt will now replace that line with the login issue text
* Calling `initctl` without any arguments or options now defaults to
  show status of all enabled services, and run/task/inetd jobs
* Cosmetic change to boot messages, removed `Loading plugins ...`, start
  of inetd services, and `Loading configuration ...`.  No end user knows
  what those plugins and configurations are, i.e. internal state+config
* Change kernel WDT timeout (3 --> 30 sec) for built-in watchdog daemon
* Advise watchdog dawmon on shutdown and reboot using `SIGPWR` and then
  `SIGTERM`.  It is recommended the daemon start a timer on the first
  signal, in case the shutdown process somehow hangs.
* Handle `/etc/` OverlayFS, reload /etc/finit.d/*.conf after `mount -a`
* initctl: Add support for printing previous runlevel
* initctl: Support short forms of all commands
* initctl: Support for `initctl touch <CONF>` to be used with `reload`
* initctl: Improved output of `initctl show <SVC>`
* Support reloading `/etc/finit.conf`.  The main finit.conf file
  previously did not support reloading at runtime, as of v3.1 all
  configuration directives supported in `/etc/finit.d/*.conf` are now
  supported in `/etc/finit.conf`
* Change `.conf` dependency + reload handling.  Finit no longer relies
  on mtime of `.conf` files, instead an inotify handler tracks file
  changes for time *insensitive* dependency tracking
* Change condition handling to not rely on mtime but a generation id.
* New configure script option `--enable-redirect` to automatically
  redirect `stdout` and `stderr` of all applications to `/dev/null`
* New `pid` sub-option to services when a service does not create a PID
  file, or when the PID file has another name.  Issue #95
* Greatly improved `log` sub-option to service/run/tasks, selectively
  redirect `stdout` and `stderr` using the new tool `logit` to either
  syslog or a logfile.  Issue #44
* Support for automatic log rotation of logfiles created by `log`
  option.  Use `configure --disable-logrotate` on systems with a
  dedicated log rotation service.  Issue #44
* Support for disabling service/run/task progress with empty ` --`
  description.  Note: no description separator gives a default desc.
* Create `/etc/mtab` symlink if missing on system (bootmisc plugin)
* New hook: `hook/mount/post` runs after `mount -a` but before the
  `hook/mount/all`, where `bootmisc.so` runs.  This provides the
  possibility of running a second stage mount command before files in
  `/run` and similar are created
* Skip `gdbserver` when unleashing the grim reaper at shutdown
* Distribute and install `doc/` and `contrib/` directories

### Fixes

* Reset TTY before restarting it.  A program may manipulate the TTY in
  various ways before the user logs out, Finit needs to reset the TTY to
  a sane state before restarting it.  Issue #84
* On .conf parse errors, do *not* default to set TTY speed 38400, reuse
  current TTY speed instead
* Fix run/tasks, must be guaranteed to run once per declared runlevel.
  All run/tasks on `[S]` with a condition `<...>` failed to run.  Finit
  now tracks run/tasks more carefully, waiting for them to finish before
  switching to the configured runlevel at boot.  Issue #86
* Allow inetd services to be registered with a unique ID, e.g. `:161`,
  issue #87.  Found by Westermo
* inetd: drop UDP packets from blocked interfaces, issue #88
* Handle obscure inter-plugin dependency issue by calling the netlink
  plugin before the pidfile plugin on `HOOK_SVC_RECONF` events
* Handle event loop failure modes, issue found by Westermo
* Handle API socket errors more gracefully, restart socket
* Do not attempt to load kernel modules more than once at bootstrap
* Remove reboot symlinks properly on uninstall
* Fix regression in condition handling, reconf condition must be kept
  as a reference point to previous reconfiguration, or bootstrap.
* Fix nasty race condition with internal service stop, abort kill if the
  service has already terminated, otherwise we may do `kill(0, SIGKILL)`
* Fix reconfiguration issue with (very quick) systems that don't have
  highres timers
* Fix formatting of runlevel string in `initctl show`
* Allow running `initctl` with `STDOUT` redirected
* Fix regression in `initctl start/stop <ID>`, using name worked not id
* Fix error handling in `initctl start/stop` without any argument
* Fix issue #81 properly, remove use of SYSV shm IPC completely.  Finit
  now use the API socket for all communication between PID 1 and initctl
* Fix segfault on x86_64 when started with kernel cmdline `--debug`
* Normalize condition paths on systems with `/run` instead of `/var/run`


[3.0][] - 2017-10-19
--------------------

Major release, support for conditions/dependencies between services,
optional built-in watchdog daemon, optional built-in getty, optional
built-in standard inetd services like echo server, rdate, etc.

Also, native support for Debian/BusyBox `/etc/network/interfaces`,
overhauled new configure based build system, logging to `/dev/kmsg`
before syslogd has started, massively improved support for Linux
distributions.

### Changes

* Added basic code of conduct covenant to project
* Added contribution guidelines document
* Removed `finit.conf` option `check DEV`, replaced entirely by automated
  call to `fsck` for each device listed in `/etc/fstab`
* Removed deprecated and confusing `startx` and `user` settings.  It is
  strongly recommended to instead use xdm/gdb/lightdm etc.
* Add support for `initctl log <SVC>`, shows last 10 lines from syslog
* Add `initctl cond dump` for debugging conditions
* Ensure plugins always have a default name, file name
* Reorganization, move all source files to a `src/` sub-directory
* Add support for `initctl <list|enable|disable> <SVC>`, much needed by
  distributions.  See [doc/distro.md](doc/distro.md) for details
* Remove `UNUSED()` macro, mentioned here because it may have been used
  by external plugin developers.  Set `-Wno-unused-parameter` instead
* New table headings in `initctl`, using `top` style inverted text
* Allow `initctl show` to use full screen width for service descriptions
* New `HOOK_BANNER` for plugins to override the default `banner()`
* Allow loading TTYs from `/etc/finit.d`
* Improvements to built-in getty, ignore signals like `SIGINT`,
  `SIGHUP`, support Ctrl-U to erase to beginning of line
* Add TTY `nowait` and `noclear` options
* Allow using both built-in getty and external getty:  

        tty [12345] /dev/ttyAMA0    115200              noclear vt220
        tty [12345] /sbin/getty  -L 115200 /dev/ttyAMA0 vt100
        tty [12345] /sbin/agetty -L ttyAMA0 115200      vt100 nowait

* Silent boot is now the default, use `--enable-progress` to get the old
  Finit style process progress.  I.e., `--enable-silent` is no more
* Support for `configure --enable-emergency-shell`, debug-only mode
* Support for a fallback shell on console if none of the configured TTYs
  can be started, `configure --enable-fallback-shell`
* All debug messages to console when Finit `--debug` is enabled
* Prevent login, by touching `/etc/nologin`, during runlevel changes
* A more orderly shutdown.  On reboot/halt/poweroff Finit now properly
  goes to runlevel 0/6 to first stop all processes.
* Perform sync before remounting as read-only, at shutdown
* Clean up `/tmp`, `/var/run`, and `/var/lock` at boot on systems which
  have these directories on persistent storage
* Call udev triggers at boot, on systems with udev
* Add missing `/var/lock/subsys` directory for dbus
* Add support for `poweroff`
* Add support for a built-in miniature watchdog daemon
* Remove GLIBC:isms like `__progname`
* Manage service states based on user defined conditions
* Manage dependencies between services, w/ conditions (pidfile plugin)
* Manage service dependencies on network events (netlink plugin)
* Support for dynamically reloading Finit configuration at runtime
* Refactor to use GNU configure and build system
* New hooks for for detecting lost and started services (lost plugin)
* External libraries, libuEv and libite, now build requirements
* Early logging support to `/dev/kmsg` instead of console
* Support for redirecting stdout/stderr of services to syslog
* Support for managing resource limits for Finit and its processes
* Add optional built-in inetd services: echo server, chargen, etc.
* Add simple built-in getty
* Greatly improved accounting support, both UTMP and WTMP fixes+features
* Improved udev support, on non-embedded systems
* Improved shutdown and file-system unmount support (Debian)
* Support SysV init `/etc/rc.local`
* Inetd protection against UDP looping attacks
* Support systems with `/run` instead of `/var/run` (bootmisc plugin)
* Adopted BusyBox init signals for halt/reboot/poweroff
* SysV init compat support for reboot (setenv)
* Compat support for musl libc
* Add OpenRC-like support for sysctl.d/*.conf
* Add support for Debian/BusyBox `/etc/network/interfaces`
* Add support for running fsck on file systems in `/etc/fstab`
* Added example configs + HowTos for Debian and Alpine Linux
  to support latest releases of both distributions
* Lots of documentation updates

### Fixes

* Fix race-condition at configuration reload due to too low resolution.  
  Thanks to Mattias Walström, Westermo
* Fix to handle long process (PID) dependency chains, re-run reconf
  callback until no more applications are in flux.  
  Thanks to Mattias Walström, Westermo
* Clear `reconf` condition when `initctl reload` has finished
* Skip automatic reload of `/etc/finit.d/*.conf` files when changing
  runlevel to halt or reboot
* Fix issue #54: Allow halt and poweroff commands even if watchdog is enabled
* Fix issue #56: Check existence of device before trying to start getty
* Fix issue #60: `initctl` should display error and return error code
  for non-existing services should the operator try to start/stop them.
* Fix issue #61: Reassert `net/*` conditions after `initctl reload`
* Fix issue #64: Skip `fsck` on already mounted devices
* Fix issue #66: Log rotate and gzip `/var/log/wtmp`, created by Finit
* Fix issue #72: Check `ifup` exists before trying to bring up networking,
  also set `$PATH` earlier to simplify `run()` et al -- no longer any need
  to use absolute paths for system tools called from Finit.  Thanks to crazy
* Fix issue #73: Remove double `ntohl()` in inetd handling, prevents matches.  
  Thanks to Petrus Hellgren, Westermo
* Fix issue #76: Reap zombie processes in emergency shell mode
* Fix issue #80: FTBFS on Arch Linux, missing `stdarg.h` in `helpers.h`,
  thanks to Jörg Krause
* Fix issue #81: Workaround for systems w/o SYSV shm IPC support in kernel
* Always collect bootstrap-only tasks when done, we will never re-run them.
  Also, make sure to never reload bootstrap-only tasks at runtime
* Remove two second block (!) of Finit when stopping TTYs


[2.4][] - 2015-12-04
--------------------

Bug fix release.

### Changes

* Add support for status/show service by `name:id`
* Enforce terse mode after boot, if verbose mode is disabled
* Re-enable verbose mode at reboot, if disabled at boot
* Update section mentioning BusyBox getty
* Update debugging documentation
* Allow debug to override terse mode
* Revert confusing change in service state introduced in [v2.3][2.3].
  As of [v2.4][2.4] services are listed as "halted" and "stopped", when
  they have been halted due to a runlevel changed or stopped by the
  user, respectively.

### Fixes

* Fix system freeze at reconfiguration.  Changed services that
  all support `SIGHUP` caused a freeze due to Finit waiting for
  them to stop.
* Make sure to start and/or `SIGHUP` services after reconfiguration
  when there was no services to stop.


[2.3][] - 2015-11-28
--------------------

Bug fix release.

### Changes

* Add support for stop/start/restart/reload service by `name:id`
* Refactor service status listed in `initctl show`, show actual status

### Fixes

* Remove bootstrap-only tasks/services when leaving runlevel 'S'
* Fix reference counting issue with already stopped and removed services
  when the user performs `initctl reload` to change system configuration
* Revert semantic change in behavior of `initctl restart`: users expect
  service to be stopped/started, not reloaded with `SIGHUP` even if the
  service supports it
* Fix `NULL` pointer dereference causing kernel panic when user calls
  `initctl reload` after change of system configuration
* Fix column alignment in output of `initctl show` for services not in
  current runlevel


[2.2][] - 2015-11-23
--------------------

Lots of fixes to handle static builds, but also fixes for dynamic event
handling and reconfiguration at runtime.

### Changes

* Upgrade to libuEv v1.2.4, to handle static builds
* Upgrade to libite (LITE) v1.2.0, to handle static builds
* Clarify how to select different plugins with the configure script
* Improve urandom plugin for embedded systems w/o random seed
* Add `--debug` flag to `initctl`
* The runlevels listed for services in `initctl show` now highlight the
  active runlevel.
* Clarify in the README and in `initctl help` that the GW event to
  listen for in service declarations is `GW:UP`

### Fixes

* Build fixes for `configure --disable-inetd`
* Fixed issue #14: Improved support for static Finit builds
* Misc. fixes to silence warnings when building a static Finit
* Default to register services as `SIGHUP`'able, regression in v2.0
* Call `HOOK_SVC_RECONF` only when all processes have been stopped
* On reload/reconf we must wait for all services to stop first
* Only trigger on events that matches the service's specification,
  fix by Tobias Waldekranz


[2.1][] - 2015-10-16
--------------------

### Changes

* Add hook point for fstab mount failure
* Set hostname on dynamic reload
* Upgrade to libite v1.1.1

### Fixes

* Fix service callback coredump checks and simplify callback exit
* Do not use `-Os` use `-O2` as default optimization level.  Many cross
  compiler toolchains are known to have problems with `-Os`
* Do not allow build VERSION to be overloaded by an environment variable
* Fix too small MAX arguments and too few arguments in `svc_t` for
  reading currently running services with `initctl show`
* Unblock blocked signals after forking off a child


[2.0][] - 2015-09-20
--------------------

Support for multiple instances and event based services, as well as the
introduction of an `initctl` tool.

**Note:** Incompatible change to syntax for custom `inetd` services,
  c.f. Finit v[1.12][].

### Changes
* The most notable change is the support for multiple instances.  A must
  have when running multiple DHCP clients, OpenVPN tunnels, or anything
  that means using the same command only with different arguments.  Now
  simply add a `:ID` after the `service` keyword, where `ID` is a unique
  instance number for that service.

        service :1 [2345] /sbin/httpd -f -h /http -p 80   -- Web server
        service :2 [2345] /sbin/httpd -f -h /http -p 8080 -- Old web server

* Another noteworthy new feature is support for starting/stopping
  services on Netlink events:

        service :1 [2345] <!IFUP:eth0,GW> /sbin/dropbear -R -F -p 22 -- SSH daemon

  Here the first instance `:1` of the SSH daemon is declared to run in
  runlevels 2-5, but only if eth0 `IFUP:eth0` is up and a gateway `GW`
  is set.  When the configuration changes, a new gateway is set, or if
  somehow a new `IFUP` event for eth0 is received, then dropbear is not
  SIGHUP'ed, but instead stop-started `<!>`.  The latter trick applies
  to all services, even those that do not define any events.
* Support for reloading `*.conf` files in `/etc/finit.d/` on SIGHUP.
  All `task`, `service` and `run` statements can be used in these .conf
  files.  Use the `telinit q` command, `initctl reload` or simply send
  `SIGHUP` to PID 1 to reload them.  Finit automatically does reload of
  these `*.conf` files when changing runlevel.
* Support for a modern `initctl` tool which can stop/start/reload and
  list status of all system services.  Also, the old client tool used
  to change runlevel is now also available as a symlink: `telinit`.

        initctl [-v] <status|stop|start|reload|restart> [JOB]

* Add concept of "jobs".  This is a unique identifier, composed of a
  service and instance number, `SVC:ID`

        initctl <stop|start|reload|restart> JOB

* Support for *deny filters* in `inetd` services.

        inetd service/proto[@iface,!iface,...] </path/to/cmd | internal[.service]>

  Internal services on a custom port must use the `internal.service`
  syntax so Finit can properly bind the inetd service to the correct
  plugin.  Here follows a few examples:

        inetd time/udp                    wait [2345] internal                -- UNIX rdate service
        inetd time/tcp                  nowait [2345] internal                -- UNIX rdate service
        inetd 3737/tcp                  nowait [2345] internal.time           -- UNIX rdate service
        inetd telnet/tcp@*,!eth1,!eth0, nowait [2345] /sbin/telnetd -i -F     -- Telnet service
        inetd 2323/tcp@eth1,eth2,eth0   nowait [2345] /sbin/telnetd -i -F     -- Telnet service
        inetd 222/tcp@eth0              nowait [2345] /sbin/dropbear -i -R -F -- SSH service
        inetd ssh/tcp@*,!eth0           nowait [2345] /sbin/dropbear -i -R -F -- SSH service

  Access to telnet on port `2323` is only possible from interfaces
  `eth0`, `eth1` and `eth2`.  The standard telnet port (`23`) is
  available from all other interfaces, but also `eth2`.  The `*`
  notation used in the ssh stanza means *any* interface, however, here
  `eth0` is not allowed.

  **NOTE:** This change breaks syntax compatibility with Finit v[1.12].
* Support for a more user-friendly configure script rather than editing
  the top Makefile, or setting environment variables at build time.
* Support for building Finit statically, no external libraries.  This
  unfortunately means that some plugins cannot be built, at all.
  Big thanks goes to James Mills for all help testing this out!
* Support for disabling the built-in inetd server with `configure`.
* Support for two new hook points: `HOOK_SVC_RECONF` and
  `HOOK_RUNLEVEL_CHANGE`.  See the source for the exact location.
* The `include <FILE>` option now needs an absolute path to `FILE`.

### Fixes
* Rename `patches/` to `contrib/` to simplify integration in 3rd party
  build systems.
* Fix for unwanted zombies ... when receiving SIGCHLD we must reap *all*
  children.  We only receive one signal, but multiple processes may have
  exited and need to be collected.


[1.12][] - 2015-03-04
---------------------

The inetd release.

### Changes
* Add support for built-in inetd super server -- launch services on
  demand.  Supports filtering per interface and custom Inet ports.
* Upgrade to [libuEv][] v1.1.0 to better handle error conditions.
* Allow mixed case config directives in `finit.conf`
* Add support for RFC 868 (rdate) time plugin, start as inetd service.
* Load plugins before parsing `finit.conf`, this makes it possible to
  extend finit even with configuration commands.  E.g., the `time.so`
  plugin must be loaded for the `inetd time/tcp internal` service to be
  accepted when parsing `finit.conf`.
* Slight change in TTY fallback behavior, if no TTY is listed in the
  system `finit.conf` first inspect the `console` setting and only if
  that too is unset fall back to `/bin/sh`
* When falling back to the `console` TTY or `/bin/sh`, finit now marks
  this fallback as console.  Should improve usability in some use cases.

### Fixes
* Revert "Use vfork() instead of fork() before exec()" from v1.11.  It
  turned out to not work so well after all.  For instance, launching
  TTYs in a background process completely blocked inetd services from
  even starting up listening sockets ... proper fork seems to work fine
  though.  This is the cause for *yanking* the [1.11] release, below.
* Trap segfaults caused by external plugins/callbacks in a sub-process.
  This prevents a single programming mistake in by a 3rd party developer
  from taking down the entire system.
* Fix Coverity CID 56281: dlopen() resource leak by storing the pointer.
  For the time being we do not support unloading plugins.
* Set hostname early, so bootstrap processes like syslog can use it.
* Only restart *lost daemons* when recovering from a SIGSTOP/norespawn.


[1.11][] - 2015-01-24 [YANKED]
------------------------------

The [libuEv][] release.

**Note:** This release has been *yanked* from distribution due to a
  regression in launching background processes and TTY's.  Fixed in
  Finit v[1.12].

### Changes
* Now using the asynchronous libuEv library for handling all events:
  signals, timers and listening to sockets or file descriptors.
* Rename NEWS.md --> CHANGELOG.md, with symlinks for `make install`
* Attempt to align with http://keepachangelog.com/ for this file.
* Travis CI now only invokes Coverity Scan from the 'dev' branch.  This
  means that all development, except documentation updates, must go into
  that branch.

### Fixes
* Fix bug with finit dying when no `tty` is defined in `finit.conf`, now
  even the fallback shell has control over its TTY, see fix in GIT
  commit [dea3ae8] for this.


[1.10][] - 2014-11-27
---------------------

Major bug fix release.

### Changes
* Project now relies on static code analysis from Coverity, so this
  release contains many serious bug fixes.
* Convert to use Markdown for README, NEWS and TODO.
* Serious update to README and slight pruning of finished TODO items.

### Fixes
* Fix serious file descriptor and memory leaks in the following
  functions.  In particular the leaks in `run_interactive()` are very
  serious since that function is called every time a service is started
  and/or restarted!  For details, see the GIT log:
  * `helpers.c:run()`
  * `helpers.c:run_interactive()`
  * `helpers.c:set_hostname()`
  * `helpers.c:procname_kill()`
* `svc.c:svc_start()`: Fix swapped arguments to dup2() and add close(fd)
  to prevent descriptor leak.
* `svc.c:svc_start()`: Fix out of bounds write to local stack variable,
  wrote off-by-one outside array.
* Several added checks for return values to `mknod()`, `mkdir()`,
  `remove()`, etc.


[1.9][] - 2014-04-21
--------------------

### Changes
* Add support for an include directive to `.conf` files
* Fallback to `/bin/sh` if user forgets tty setting
* Initial support for restarting lost services during `norespwan`

### Fixes
* Bug fixes, code cleanup
* Handle `SIGHUP` from service callback properly when switching runlevel
* Misc. major (memleak) and minor fixes and additions to `libite/lite.h`


[1.8][] - 2013-06-07
--------------------

### Changes
* Support for runlevels, with a bootstrap runlevel 'S'
* Support for saving previous and current runlevel to UTMP
* Support for new `finit.conf` commands: run, task, and runlevel
* Support for tty and console commands in `finit.conf`, like services
  but for launching multiple getty logins
* New tty plugin to monitor TTYs coming and going, like USB TTYs

### Fixes
* Bugfixes to libite


[1.7][] - 2012-10-08
--------------------

### Changes
* Show `__FILE__` in `_d()` debug messages, useful for plugins with
  similarly named callbacks. Also, only in debug mode anyway
* Make sure to cleanup recorded PID when a service is lost.  Required by
  service plugins for their callbacks to work.
* Only clear screen when in verbose mode. Maybe this should be removed
  altogether?

### Fixes
* Bugfix: Do not `free()` static string in `finit.conf` parser


[1.6][] - 2012-10-06
--------------------

### Changes
* Skip `.` and `..` in plugin loader and display error when failing to
  load plugins
* Support for overriding `/etc/finit.d` with `runparts DIR` in
  `finit.conf`
* Revoke support for starting services not starting with a slash.
* Prevent endless restart of non-existing services in `finit.conf`
* Support for sysvinit style startstop scripts in `/etc/finit.d`

### Fixes
* Minor fix to alsa-utils plugin to silence on non-existing cards


[1.5][] - 2012-10-03
--------------------

### Changes
* Use bootmisc plugin to setup standard FHS 2.3 structure in `/var`
* Added `FLOG_WARN()` syslog macro, for plugins
* Add plugin dependency resolver. Checks `plugin_t` for `.depends`


[1.4][] - 2012-10-02
--------------------

### Changes
* Start refactoring helpers.c into a libite.so (-lite).  This means
  other user space applications/daemons can make use of the neat toolbox
  available in finit
* Use short-form -s/-w -u to work with BusyBox hwclock as well
* Use RTLD_GLOBAL flag to tell dynamic loader to load dependent .so
  files as well.  Lets other plugins use global symbols.
* Greatly simplify svc hook for external plugins and cleanup plugin API.
* And more ... see the GIT log for more details.

### Fixes
* Fix I/O plugin watcher and load plugins earlier for a new hook


[1.3][] - 2012-09-28
--------------------

### Changes
* Cleanup public plugin API a bit and add new pid/pidfile funcs
* Add plugin hook to end of service startup
* Remove finit.h from svc.h, plugins should not need this.
* Move utility macros etc. to helpers.h
* Make `finit.h` daemon internal, only
* Move defines of FIFO, conf and rcS.d to Makefile => correct paths
* Add support for installing required headers in system include dir
* Better support for distributions and packagers with install-exec,
  install-data, and install-dev targets in Makefile.  Useful if you want
  to call targets with different `$DESTDIR`!
* Makefile fixes for installation, paths encoded wrong
* Strip binaries + .so files, support for `$(CROSS)` toolchain strip
* Default install is now to `/sbin/finit` and `/usr/`
* Note change in `$PLUGIN_DIR` environment variable to `$plugindir`


[1.2][] - 2012-09-27
--------------------

### Changes
* Update README with section on building and environment variables

### Fixes
* Fix installation paths encoded in finit binary


[1.1][] - 2012-09-27
--------------------

### Changes
* Rename signal.[ch]-->sig.[ch] to avoid name clash w/ system headers

### Fixes
* Build fixes for ARM eabi/uClibc


[1.0][] - 2012-09-26
--------------------

### Changes
* New plugin based system for all odd extensions
* New service monitor that restarts services if they die
* New maintainer at GitHub http://github.com/troglobit/finit
* Add standard LICENSE and AUTHORS files
* New focus: embedded systems and small headless servers


[0.6][] - 2010-06-14
--------------------

* Don't start consolekit manually, dbus starts it (rtp)
* Unmount all filesystems before rebooting
* Disable `USE_VAR_RUN_RESOLVCONF` for Mandriva
* Unset terminal type in Mandriva before running X
* Remove extra sleep in finit-alt before calling services.sh (caio)


[0.5][] - 2008-08-21
--------------------

* Add option to start dbus and consolekit before the X server
* finit-alt listens to `/dev/initctl` to work with `reboot(8)` (smurfy)
* Write runlevel to utmp, needed by Printerdrake (Pascal Terjan)
* Fix ownership of `/var/run/utmp` (reported by Pascal Terjan)
* Remove obsolete code to load AGP drivers
* Conditional build of `/etc/resolveconf/run` support
* Add support to `/var/run/resolvconf` in Mandriva (blino)


[0.4][] - 2008-05-16
--------------------

* Default username for finit-alt configurable in Makefile
* Create loopback device node in finit-alt (for squashfs)
* Add option to use built-in run-parts instead of `/bin/run-parts`
* Ignore signal instead of setting to an empty handler (Metalshark)
* Handle pam_console permissions in finit-alt for Mandriva
* Add services.sh example and nash-hotplug patch for Mandriva
* Mount `/proc/bus/usb` in Mandriva
* Add runtime debug to finit-alt if finit_debug parameter is specified
* Read configuration from `/etc/finit.conf`
* Run getty with openvt on the virtual terminal


[0.3][] - 2008-02-23
--------------------

* Change poweroff method to `reboot(RB_POWER_OFF)` (Metalshark)
* Remove duplicate `unionctl()` reimplementation error
* Fix string termination in path creation
* Mount `/var/lock` and `/var/run` as tmpfs


[0.2][] - 2008-02-19
--------------------

* Replace `system("touch")` with `touch()` in finit-mod (Metalshark)
* Disable `NO_HCTOSYS` by default to match stock Eeepc kernel
* Drop `system("rm -f")` to clean `/tmp`, its a fresh mounted tmpfs
* Write ACPI sleep state to `/sys/power/state` instead of
  `/proc/acpi/sleep` (Metalshark)
* Use direct calls to set loopback instead of `system("ifconfig")`
* Replace `system("cat")` and `system("dd")` with C implementation
* Moved finit-mod and finit-alt helpers to `helpers.c`
* Replace `system("echo;cat")` to draw shutdown splash with C calls


0.1 - 2008-02-14
----------------

* Initial release

[UNRELEASED]: https://github.com/finit-project/finit/compare/4.15...HEAD
[4.15]: https://github.com/finit-project/finit/compare/4.14...4.15
[4.14]: https://github.com/finit-project/finit/compare/4.13...4.14
[4.13]: https://github.com/troglobit/finit/compare/4.12...4.13
[4.12]: https://github.com/troglobit/finit/compare/4.11...4.12
[4.11]: https://github.com/troglobit/finit/compare/4.10...4.11
[4.10]: https://github.com/troglobit/finit/compare/4.9...4.10
[4.9]:  https://github.com/troglobit/finit/compare/4.8...4.9
[4.8]:  https://github.com/troglobit/finit/compare/4.7...4.8
[4.7]:  https://github.com/troglobit/finit/compare/4.6...4.7
[4.6]:  https://github.com/troglobit/finit/compare/4.5...4.6
[4.5]:  https://github.com/troglobit/finit/compare/4.4...4.5
[4.4]:  https://github.com/troglobit/finit/compare/4.3...4.4
[4.3]:  https://github.com/troglobit/finit/compare/4.2...4.3
[4.2]:  https://github.com/troglobit/finit/compare/4.1...4.2
[4.1]:  https://github.com/troglobit/finit/compare/4.0...4.1
[4.0]:  https://github.com/troglobit/finit/compare/3.1...4.0
[3.1]:  https://github.com/troglobit/finit/compare/3.0...3.1
[3.0]:  https://github.com/troglobit/finit/compare/2.4...3.0
[2.4]:  https://github.com/troglobit/finit/compare/2.3...2.4
[2.3]:  https://github.com/troglobit/finit/compare/2.2...2.3
[2.2]:  https://github.com/troglobit/finit/compare/2.1...2.2
[2.1]:  https://github.com/troglobit/finit/compare/2.0...2.1
[2.0]:  https://github.com/troglobit/finit/compare/1.12...2.0
[1.12]: https://github.com/troglobit/finit/compare/1.11...1.12
[1.11]: https://github.com/troglobit/finit/compare/1.10...1.11
[1.10]: https://github.com/troglobit/finit/compare/1.9...1.10
[1.9]:  https://github.com/troglobit/finit/compare/1.8...1.9
[1.8]:  https://github.com/troglobit/finit/compare/1.7...1.8
[1.7]:  https://github.com/troglobit/finit/compare/1.6...1.7
[1.6]:  https://github.com/troglobit/finit/compare/1.5...1.6
[1.5]:  https://github.com/troglobit/finit/compare/1.4...1.5
[1.4]:  https://github.com/troglobit/finit/compare/1.3...1.4
[1.3]:  https://github.com/troglobit/finit/compare/1.2...1.3
[1.2]:  https://github.com/troglobit/finit/compare/1.1...1.2
[1.1]:  https://github.com/troglobit/finit/compare/1.0...1.1
[1.0]:  https://github.com/troglobit/finit/compare/0.9...1.0
[0.9]:  https://github.com/troglobit/finit/compare/0.8...0.9
[0.8]:  https://github.com/troglobit/finit/compare/0.7...0.8
[0.7]:  https://github.com/troglobit/finit/compare/0.6...0.7
[0.6]:  https://github.com/troglobit/finit/compare/0.5...0.6
[0.5]:  https://github.com/troglobit/finit/compare/0.4...0.5
[0.4]:  https://github.com/troglobit/finit/compare/0.3...0.4
[0.3]:  https://github.com/troglobit/finit/compare/0.2...0.3
[0.2]:  https://github.com/troglobit/finit/compare/0.1...0.2
[libuEv]: https://github.com/troglobit/libuev
[dea3ae8]: https://github.com/troglobit/finit/commit/dea3ae8
