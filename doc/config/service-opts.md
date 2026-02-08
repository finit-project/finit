Service Options
===============

The run/task/tty/service/sysv directives take modifiers, or options, to
control their behavior.  This section lists them with their limitations.
All modifiers must be placed between the directive and its command.

The name of a service, shown by the `initctl` tool, defaults to the
basename of the service executable. It can be changed with the `name:`
option:

    name:<service-name>

For multiple instances of a service, with the same `name`, set the
identifier `:ID` to prevent Finit from replacing previous instances:

    service name:ssdp :eth1 ssdpd eth1 -- Windows discovery on eth1
    service name:ssdp :eth2 ssdpd eth2 -- Windows discovery on eth2

The [`initctl`](../initctl.md) tool will list these two services as:

 - ssdp:eth1
 - ssdp:eth2

Conflicting services that must be prevented from starting, use the
`conflict:` option:

    service [S12345789] udevd -- Device event management daemon
	run [S] conflict:udevd mdev -s -- Populating device tree

Multiple conflicting services can be separated using `,`:

    service :1 abc
    service :2 abc
	service conflict:abc:1,abc:2 cde

If a service should not be automatically started, it can be configured
as manual with the optional `manual` argument. The service can then be
started at any time by running `initctl start <service>`.

    manual:yes

Other run/task/service options are:

  * `caps:...` -- see the [Linux Capabilities](capabilities.md) section
  * `cgroup.NAME[,opts]` or `cgroup:opts` -- see the [Cgroups](cgroups.md) section
  * `env:[-]/path/to/env` -- see the [Service Environment](service-env.md) section
  * `log:...` -- see [Redirecting Output](logging.md#redirecting-output)
  * `nowarn` -- see [Conditional Loading](services.md#conditional-loading)
  * `notify:...` -- see [Service Synchronization](service-sync.md)
  * `if:...` -- see [Conditional Execution](services.md#conditional-execution)
  * `type:forking` -- see description of the [service](services.md) directive

As mentioned previously, services are automatically started, restarted,
and stopped, depending on the configuration and conditions.  Within the
confines of that the following options are available:

  * `restart:NUM` -- number of times Finit tries to restart a crashing
    service, default: 10, max: 255.  When this limit is reached the
    service is marked *crashed* and must be restarted manually with
    `initctl restart NAME`
  * `restart_sec:SEC` -- number of seconds before Finit tries to restart
    a crashing service, default: 2 seconds for the first five retries,
	then back-off to 5 seconds.  The maximum of this configured value
	and the above (2 and 5) will be used
  * `restart:always` -- no upper limit on the number of times Finit
    tries to restart a crashing service.  Same as `restart:-1`
  * `norestart` -- dont restart on failures, same as `restart:0`
  * `respawn` -- bypasses the `restart` mechanism completely, allows
    endless restarts.  Useful in many use-cases, but not what `service`
    was originally designed for so not the default behavior
  * `remain:yes` -- for `run` and `task` only.  Prevents the task from
    re-running on runlevel re-entry and ensures the `post:` script runs
    when the task is explicitly stopped or leaves its valid runlevels.
    Similar to systemd's `RemainAfterExit=yes`.  See [Task and Run](task-and-run.md)
    for more details
  * `oncrash:reboot` -- when all retries have failed, and the service
    has *crashed*, if this option is set the system is rebooted
  * `oncrash:script` -- similarly, but instead of rebooting, call the
    `post:script` action with exit code `crashed`, see below
  * `reload:'script [args]'` -- some services do not support `SIGHUP` but
    may have other ways to update the configuration of a running daemon.
    When `reload:script` is defined it is preferred over `SIGHUP`.  Like
	systemd, Finit sets `$MAINPID` as a convenience to scripts, which in
	effect also allow `reload:'kill -HUP $MAINPID'`
  * `stop:'script [args]'` -- some services may require alternate methods
    to be stopped.  If a `stop:script` is defined it is preferred over
    `SIGTERM` and `stop`, for `service` and `sysv`, respectively.
	Similar to `reload:script`, Finit sets `$MAINPID`

> [!CAUTION]
> Both `reload:script` and `stop:script` are called as PID 1, without
> any timeout!  Meaning, it is up to you to ensure the script is not
> blocking for seconds at a time or never terminates.

When stopping a service (run/task/sysv/service), either manually or when
moving to another runlevel, Finit starts by sending `SIGTERM`, to allow
the process to shut down gracefully (unless a `stop:'script'` is used).
However, if the process has not been collected within 3 seconds, Finit
will send `SIGKILL`.  To stop the process using a different signal than
`SIGTERM`, use `halt:SIGNAL`, e.g., `halt:SIGPWR`.  To change the delay
between the stop signal and KILL, use the option `kill:<1-60>`, e.g.,
`kill:10` to wait 10 seconds before sending `SIGKILL`.

Services, including the `sysv` variant, support pre/post/ready and
cleanup scripts:

  * `pre:[0-3600,]script` -- called before the sysv/service is stated
  * `post:[0-3600,]script` -- called after the sysv/service has stopped
  * `ready:[0-3600,]script` -- called when the sysv/service is ready
  * `cleanup:[0-3600,]script` -- called when run/task/sysv/service is removed

The optional number (0-3600) is the timeout before Finit kills the
script, it defaults to the kill delay value and can be disabled by
setting it to zero.  These scripts run as the same `@USER:GROUP` as the
service itself, with any `env:file` sourced.  The scripts are executed
from the `$HOME` of the given user.  The scripts are not called with any
argument, but get a set of environment variables:

  * `SERVICE_IDENT=foo:1`
  * `SERVICE_NAME=foo`
  * `SERVICE_ID=1`

The `post:script` is called with an additional set of environment
variables.  Yes, the text is correct, the naming was an accident:

 - `EXIT_CODE=[exited,signal,crashed]`: normal exit, signaled, or
   crashed
 - `EXIT_STATUS=[num,SIGNAME]`: set to one of exit status code from
   the program, if it exited normally, or the signal name (`HUP`,
   `TERM`, etc.) if it exited due to signal

When a run/task/sys/service is removed (disable + reload) it is first
stopped and then removed from the runlevel.  The `post:script` always
runs when the process has stopped, and the `cleanup:script` runs when
the the stanza has been removed from the runlevel.

> [!IMPORTANT]
> These script actions are intended for setup, cleanup, and readiness
> notification.  It is up to the user to ensure the scripts terminate.
