Services
========

**Syntax:** `service [LVLS] <COND> /path/to/daemon ARGS -- Optional description`

Service, or daemon, to be monitored and automatically restarted if it
exits prematurely.  Finit tries to restart services that die, by default
10 times before giving up and marking them as *crashed*.  After which
they have to be manually restarted with `initctl restart NAME`.  The
limits controlling this are configurable, see the options below.

> [!TIP]
> To allow endless restarts, see the [`respawn` option](service-opts.md)
  
For daemons that support it, we recommend appending `--foreground`,
`--no-background`, `-n`, `-F`, or similar command line argument to
prevent them from forking off a sub-process in the background.  This is
the most reliable way to monitor a service.

However, not all daemons support running in the foreground, or they may
start logging to the foreground as well, these are forking daemons and
are supported using the same syntax as forking `sysv` services, using
the `pid:!/path/to/pidfile.pid` syntax.  There is an alternative syntax
that may be more intuitive, where Finit can also guess the PID file
based on the daemon's command name:

    service type:forking ntpd -- NTP daemon

This example lets BusyBox `ntpd` daemonize itself.  Finit uses the
basename of the binary to guess the PID file to watch for the PID:
`/var/run/ntpd.pid`.  If Finit guesses wrong, you have to submit the
full `pid:!/path/to/file.pid`.

**Example:**

In the case of `ospfd` (below), we omit the `-d` flag (daemonize) to
prevent it from forking to the background:

    service [2345] <pid/zebra> /sbin/ospfd -- OSPF daemon

`[2345]` denote the runlevels `ospfd` is allowed to run in, they are
optional and default to level 2-5 if omitted.
  
`<...>` is the condition for starting `ospfd`.  In this example Finit
waits for another service, `zebra`, to have created its PID file in
`/var/run/quagga/zebra.pid` before starting `ospfd`.  Finit watches
*all* files in `/var/run`, for each file named `*.pid`, or `*/pid`,
Finit opens it and find the matching `NAME:ID` using the PID.

The condition can be prefixed with `!` and/or `~`:

 - `<!pid/zebra>` -- `ospfd` does not support `SIGHUP` (noreload)
 - `<~pid/zebra>` -- propagate reload from `zebra` to `ospfd`
 - `<!~pid/zebra>` -- both: noreload and propagate reload

For details, see the [Finit Conditions](../conditions.md) document.

Some services do not maintain a PID file and rather than patching each
application Finit provides a workaround.  A `pid` keyword can be set
to have Finit automatically create (when starting) and later remove
(when stopping) the PID file.  The file is created in the `/var/run`
directory using the `basename(1)` of the service.  The default can be
modified with an optional `pid:`-argument:

    pid[:[/path/to/]filename[.pid]]

For example, by adding `pid:/run/bar.pid` to the service `/sbin/bar`,
that PID file will, not only be created and removed automatically, but
also be used by the Finit condition subsystem.  So a service/run/task
can depend on `<pid/bar>`, like this foo will not be started until bar
has started:

    service pid:/run/bar.pid bar -- Bar Service
    service <pid/bar> foo -- Foo Service

Needless to say, it is better if `bar` creates its own PID file when it
has completed starting up and is ready for service.

As an alternative "readiness" notification, Finit supports both systemd
and s6 style notification.  This can be enabled by using the `notify`
option:

  * `notify:systemd` -- tells Finit the service uses the `sd_notify()`
    API to signal PID 1 when it has completed its startup and is ready
    to service events.  The [sd_notify()][] API expects `NOTIFY_SOCKET`
    to be set to the socket where the application can send `"READY=1\n"`
    when it is starting up or has processed a `SIGHUP`.
  * `notify:s6` -- puts Finit in s6 compatibility mode.  Compared to the
    systemd notification, [s6 expect][] compliant daemons to send `"\n"`
    and then close their socket.  Finit takes care of "hard-wiring" the
    READY state as long as the application is running, events across any
    `SIGHUP`.  Since s6 can give its applications the descriptor number
    (must be >3) on then command line, Finit provides the following
    syntax (`%n` is replaced by Finit with then descriptor number):

        service [S12345789] notify:s6 mdevd -O 4 -D %n

[sd_notify()]: https://www.freedesktop.org/software/systemd/man/sd_notify.html
[s6 expect]:   https://skarnet.org/software/s6/notifywhenup.html

When a service is ready, either by Finit detecting its PID file, or
their respective readiness mechanism has been triggered, Finit creates
then service's ready condition which other services can depend on:

    $ initctl -v cond get service/mdevd/ready
    on

This can be used to synchronize the start of another run/task/service:

    task [S] <service/mdevd/ready> @root:root mdevd-coldplug

Finit waits for `mdevd` to notify it, before starting `mdevd-coldplug`.
Notice how both start in runlevel S, and the coldplug task only runs in
S.  When the system moves to runlevel 2 (the default), coldplug is no
longer part of the running configuration (`initctl show`), this is to
ensure that coldplug is not called more than once.

>  For a detailed description of conditions, and how to debug them,
>  see the [Finit Conditions](../conditions.md) document.


Non-privileged Services
-----------------------

Every `run`, `task`, or `service` can also list the privileges the
`/path/to/cmd` should be executed with.  Prefix the command with
`@USR[:GRP[,SUPP,...]]`, where group and supplementary groups are
optional, like this:

    run [2345] @joe:users logger "Hello world"

Finit reads the user's supplementary group membership from `/etc/group`
automatically.  Any groups the user belongs to will be inherited by
the service.

To specify additional supplementary groups beyond those in `/etc/group`,
append them after the primary group, separated by commas:

    service @caddy:caddy,ssl-cert /usr/bin/caddy run

This runs the `caddy` service as user `caddy`, with primary group
`caddy`, inheriting any groups `caddy` is a member of in `/etc/group`,
plus the additional `ssl-cert` group.  This is useful when a service
needs access to resources owned by groups not listed in `/etc/group`.

For multiple instances of the same command, e.g. a DHCP client or
multiple web servers, add `:ID` somewhere between the `run`, `task`,
`service` keyword and the command, like this:

    service :80  [2345] httpd -f -h /http -p 80   -- Web server
    service :8080[2345] httpd -f -h /http -p 8080 -- Old web server

Without the `:ID` to the service the latter will overwrite the former
and only the old web server would be started and supervised.


Conditional Loading
-------------------

Finit support conditional loading of stanzas.  The following example is
take from the `system/hotplug.conf` file in the Finit distribution.
Here we only show a simplified subset.

Starting with the `nowarn` option.

    service nowarn name:udevd pid:udevd /lib/systemd/systemd-udevd
    service nowarn name:udevd pid:udevd udevd

When loading the .conf file Finit looks for `/lib/systemd/systemd-udevd`
if that is not found Finit automatically logs a warning.  The `nowarn`
option disables this warning so that the second line can be evaluated,
which also provides a service named `udevd`.

    run nowarn if:udevd <pid/udevd> :1 udevadm settle -t 0

This line is only loaded if we know of a service named `udevd`.  Again,
we do not warn if `udevadm` is not found, execution will also stop here
until the PID condition is asserted, i.e., Finit detecting udevd has
started.

    run nowarn conflict:udevd [S] mdev -s -- Populating device tree

If `udevd` is not available, we try to run `mdev`, but if that is not
found, again we do not warn.

Conditional loading statements can also be negated, so the previous stanza
can also be written as:

    run nowarn if:!udevd [S] mdev -s -- Populating device tree

The reason for using `conflict` in this example is that a conflict can be
resolved.  Stanzas marked with `conflict:foo` are rechecked at runtime.


Conditional Execution
---------------------

Similar to conditional loading of stanzas there is conditional runtime
execution.  This can be confusing at first, since Finit already has a
condition subsystem, but this is more akin to the qualification to a
runlevel.  E.g., a `task [123]` is qualified to run only in runlevel 1,
2, and 3.  It is not considered for other runlevels.

Conditional execution qualify a run/task/service based on a condition.
Consider this (simplified) example from the Infix operating system:

    run [S]                       name:startup <pid/sysrepo> confd -b --load startup-config
    run [S] if:<usr/fail-startup> name:failure <pid/sysrepo> confd    --load failure-config

The two run statements reside in the same .conf file so Finit runs them
in true sequence.  If loading the file `startup-config` fails confd sets
the condition `usr/fail-startup`, thus allowing the next run statement
to load `failure-config`.

Notice the critical difference between the `<pid/sysrepo>` condition and
`if:<usr/fail-startup>`.  The former is a condition for starting and the
latter is a condition to check if a run/task/service is qualified to
even be considered.

Conditional execution statements can also be negated, so provided the
file loaded did the opposite, i.e., set a condition on success, the
previous stanza can also be written as:

    run [S] if:<!usr/startup-ok> name:failure <pid/sysrepo> confd ...
