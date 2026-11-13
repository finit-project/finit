TTYs and Consoles
=================

**Syntax:** `tty NAME { device = DEV }` -- built-in getty  
  `tty NAME { command = "CMD ARGS" }` -- external getty  
  `tty NAME { notty = true }`, or `{ rescue = true }` -- bare shell, no device

The block title NAME is what `initctl` shows.  The three variants differ
in what they open: `device` runs the built-in getty on that TTY, and DEV
may be the special keyword `@console`, expanded from
`/sys/class/tty/console/active`, useful on embedded systems.  `command`
hands the TTY to an external getty.  `notty` opens nothing at all.

`command` may name several candidates, `{ "agetty ...", "getty ..." }`,
and Finit runs the first one it finds.  See [Command
Candidates](service-opts.md#command-candidates).

Settings common to all three:

| Setting | Alias | Description |
|---|---|---|
| `runlevel` | | Runlevels to run in, e.g. `"12345"` |
| `conditions` | `cond` | Conditions to wait for |
| `manual-start` | `manual` | Register without starting automatically |
| `noclear` | | Do not clear the TTY after each session |
| `nowait` | | Do not wait for Enter before the login prompt |
| `nologin` | | Skip login, give a shell straight away |
| `passenv` | | Pass the environment on to `login`, built-in getty only |

The `device` variant takes two more:

| Setting | Description |
|---|---|
| `baud` | Baud rate, default 0, i.e., keep kernel default |
| `term` | `$TERM` value, e.g. `"vt220"` |

> A `tty` block inherits runlevel, condition (and other feature)
> parsing from the `service` block.  So TTYs can run in one or many
> runlevels and depend on any condition supported by Finit.  This is
> useful e.g. to depend on `<pid/elogind>` before starting a TTY.

**Example:**

    tty ttyAMA0 {
        runlevel = "12345"
        device   = "/dev/ttyAMA0"
        baud     = 115200
        term     = "vt220"
        noclear  = true
    }

The second `tty` syntax variant is for using an external getty, like
agetty or the BusyBox getty.

The third variant is for board bringup and the `rescue` boot mode.  No
device node is required, the same output the kernel uses is reused for
stdio.  With `notty` a shell is started (`nologin`, `noclear`, and
`nowait` are implied); with `rescue` the bundled
`/libexec/finit/sulogin` presents a bare-bones root login prompt.  If
the root (uid:0, gid:0) user does not have a password set, no rescue is
possible.  For more information, see the [Rescue Mode](rescue.md)
section.

By default, the first two syntax variants *clear* the TTY and *wait* for
the user to press enter before starting getty.

**Example:**

    tty getty {
        runlevel = "12345"
        command  = "/sbin/getty -L 115200 /dev/ttyAMA0 vt100"
    }

    tty agetty {
        runlevel = "12345"
        command  = "/sbin/agetty -L ttyAMA0 115200 vt100"
        nowait   = true
    }

The `noclear` setting disables clearing the TTY after each session.
Clearing the TTY when a user logs out is usually preferable.
  
The `nowait` setting disables the `press Enter to activate console`
message before actually starting the getty program.  On small and
embedded systems running multiple unused getty wastes both memory
and CPU cycles, so `wait` is the preferred default.

The `nologin` setting disables getty and `/bin/login`, and gives the
user a root (login) shell on the given TTY immediately.
Needless to say, this is a rather insecure option, but can be very
useful for developer builds, during board bringup, or similar.

Embedded systems may want to enable automatic `DEV` by supplying the
special `@console` device.  This works regardless whether the system
uses `ttyS0`, `ttyAMA0`, `ttyMXC0`, or anything else.  Finit figures
it out by querying sysfs: `/sys/class/tty/console/active`.  Leave
`baud` out to keep the kernel default.

> Most systems get by fine by just using `console`, which will evaluate
> to `/dev/console`.  If you have to use `@console` to get any output,
> you may have some issue with your kernel config.

**Example:**

    tty console {
        runlevel = "12345"
        device   = "@console"
        term     = "vt220"
        noclear  = true
    }

On really bare bones systems, or for board bringup, Finit can give you a
shell prompt as soon as bootstrap is done, without opening any device
node:

    tty board {
        runlevel = "12345789"
        notty    = true
    }

This should of course not be enabled on production systems.  Because it
may give a user root access without having to log in.  However, for
board bringup and system debugging it can come in handy.

One can also use a `service` block to start a stand-alone shell:

    service shell {
        runlevel = "12345"
        command  = "/bin/sh -l"
    }

Controlling TTY for Services
----------------------------

The `tty` setting gives a `run`, `task`, or `service` a controlling
terminal on the given device.  The device is opened, set as the
controlling terminal for the session (after `setsid()`), and connected to
the process's stdin, stdout, and stderr.  A default `TERM` environment
variable is set based on the device type: `vt102` for serial lines and
`linux` for virtual terminals.

The value may be a device node like `/dev/ttyS0`, or the special
keyword `@console` (see above).  Note that `@console` expands only to
the first console, not all.

When `tty` is combined with a `log` block, stdout and stderr are
redirected to the log sink instead of the TTY, but stdin remains
connected to the TTY device.

> The `tty` setting is for `run`, `task`, and `service` blocks only.
> A `tty` block (for getty/login) is a different thing entirely, see
> above.

**Example:**

    service foo {
        description = "Foo on serial console"
        runlevel    = "2345"
        tty         = "/dev/ttyS0"
        command     = "/usr/sbin/foo"
    }

    task setup {
        description = "Board bringup on console"
        runlevel    = "S"
        tty         = "@console"
        command     = "my-setup-script"
    }
