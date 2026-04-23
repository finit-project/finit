TTYs and Consoles
=================

**Syntax:** `tty [LVLS] <COND> DEV [BAUD] [noclear] [nowait] [nologin] [TERM]`  
  `tty [LVLS] <COND> CMD <ARGS> [noclear] [nowait]`  
  `tty [LVLS] <COND> [notty] [rescue]`

The first variant of this option uses the built-in getty on the given
TTY device DEV, in the given runlevels.  DEV may be the special keyword
`@console`, which is expanded from `/sys/class/tty/console/active`,
useful on embedded systems.

The default baud rate is 0, i.e., keep kernel default.

> The `tty` stanza inherits runlevel, condition (and other feature)
> parsing from the `service` stanza.  So TTYs can run in one or many
> runlevels and depend on any condition supported by Finit.  This is
> useful e.g. to depend on `<pid/elogind>` before starting a TTY.

**Example:**

    tty [12345] /dev/ttyAMA0 115200 noclear vt220

The second `tty` syntax variant is for using an external getty, like
agetty or the BusyBox getty.

The third variant is for board bringup and the `rescue` boot mode.  No
device node is required in this variant, the same output that the kernel
uses is reused for stdio.  If the `rescue` option is omitted, a shell is
started (`nologin`, `noclear`, and `nowait` are implied), if the rescue
option is set the bundled `/libexec/finit/sulogin` is started to present
a bare-bones root login prompt.  If the root (uid:0, gid:0) user does
not have a password set, no rescue is possible.  For more information,
see the [Rescue Mode](rescue.md) section.

By default, the first two syntax variants *clear* the TTY and *wait* for
the user to press enter before starting getty.

**Example:**

    tty [12345] /sbin/getty  -L 115200 /dev/ttyAMA0 vt100
    tty [12345] /sbin/agetty -L ttyAMA0 115200 vt100 nowait

The `noclear` option disables clearing the TTY after each session.
Clearing the TTY when a user logs out is usually preferable.
  
The `nowait` option disables the `press Enter to activate console`
message before actually starting the getty program.  On small and
embedded systems running multiple unused getty wastes both memory
and CPU cycles, so `wait` is the preferred default.

The `nologin` option disables getty and `/bin/login`, and gives the
user a root (login) shell on the given TTY `<DEV>` immediately.
Needless to say, this is a rather insecure option, but can be very
useful for developer builds, during board bringup, or similar.

Notice the ordering, the `TERM` option to the built-in getty must be
the last argument.

Embedded systems may want to enable automatic `DEV` by supplying the
special `@console` device.  This works regardless weather the system
uses `ttyS0`, `ttyAMA0`, `ttyMXC0`, or anything else.  Finit figures
it out by querying sysfs: `/sys/class/tty/console/active`.  The speed
can be omitted to keep the kernel default.

> Most systems get by fine by just using `console`, which will evaluate
> to `/dev/console`.  If you have to use `@console` to get any output,
> you may have some issue with your kernel config.

**Example:**

    tty [12345] @console noclear vt220

On really bare bones systems, or for board bringup, Finit can give you a
shell prompt as soon as bootstrap is done, without opening any device
node:

    tty [12345789] notty

This should of course not be enabled on production systems.  Because it
may give a user root access without having to log in.  However, for
board bringup and system debugging it can come in handy.

One can also use the `service` stanza to start a stand-alone shell:

    service [12345] /bin/sh -l

Controlling TTY for Services
----------------------------

The `tty:<dev>` option gives a `run`, `task`, or `service` a controlling
terminal on the given device.  The device is opened, set as the
controlling terminal for the session (after `setsid()`), and connected to
the process's stdin, stdout, and stderr.  A default `TERM` environment
variable is set based on the device type: `vt102` for serial lines and
`linux` for virtual terminals.

`<dev>` may be a device node like `/dev/ttyS0`, or the special keyword
`@console` (see above).  Note that `@console` expands only to the
first console, not all.

When `tty:` is combined with `log:`, stdout and stderr are redirected
to the log sink instead of the TTY, but stdin remains connected to the
TTY device.

> The `tty:<dev>` option is for `run`, `task`, and `service` stanzas only.
> The `tty` directive itself (for getty/login) has its own syntax, see
> above.

**Example:**

    service [2345] tty:/dev/ttyS0 /usr/sbin/foo -- Foo on serial console
    task [S] tty:@console my-setup-script -- Board bringup on console