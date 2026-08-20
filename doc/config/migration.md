Syntax Migration Guide
======================

Finit reads both configuration formats.  Every file is still `*.conf`,
and the format is detected per file, so a system can be migrated one
file at a time -- a file is one format or the other, never a mix.

This guide maps each part of a line-based stanza to its block key.

The shape of the change:

    service [S12345] <pid/syslogd> env:-/etc/default/klogd name:klogd klogd -n $KLOGD_OPTS -- Kernel log daemon

becomes

    service klogd {
        description = "Kernel log daemon"
        runlevel    = "S12345"
        conditions  = { "pid/syslogd" }
        envfile     = "-/etc/default/klogd"
        command     = "klogd -n $KLOGD_OPTS"
    }

The block title is the service identity, shown by `initctl`.  Multiple
instances spell the ID in the title: `service sshd:1 { ... }`.  The
legacy bare-ID form, `service :80 ...`, has no equivalent -- the title
carries both name and ID.

Positional parts
----------------

| Line-based                       | Block key                                             |
|----------------------------------|-------------------------------------------------------|
| `service`, `task`, `run`, `sysv` | same, as block type                                   |
| `[S12345]`                       | `runlevel = "S12345"`                                 |
| `<pid/a,net/b>`                  | `conditions = { "pid/a", "net/b" }`                   |
| `<!pid/a>` on service/sysv       | `conditions = { "pid/a" }` + `reload-signal = "none"` |
| `<!pid/a>` on run/task           | `conditions = { "pid/a" }` + `required = false`       |
| `@user:group,extra`              | `user`, `group`, `extra-groups = { "extra" }`         |
| `name:foo :1`                    | block title `foo:1`                                   |
| the command and arguments        | `command = "..."`                                     |
| `-- Description text`            | `description = "..."`                                 |

The `!` was a flag on the stanza, not a negation, and meant different
things for daemons and one-shots; each meaning is now its own key.  A
`~` prefix on a condition is unchanged: `conditions = { "~pid/a" }`.

Service options
---------------

| Line-based                       | Block key                                        |
|----------------------------------|--------------------------------------------------|
| `env:[-]/path`                   | `envfile = "[-]/path"`                           |
| `pid:/path`                      | `pidfile = "/path"` + `pidfile-create = true`    |
| `pid:!/path`                     | `pidfile = "/path"`                              |
| `pid`                            | `pidfile = true` + `pidfile-create = true`       |
| `log`                            | `log { }`                                        |
| `log:/path`                      | `log { file = "/path" }`                         |
| `log:null`, `log:console`        | `log { file = "/dev/null" }`, `"/dev/console"`   |
| `log:prio:p,tag:t`               | `log { priority = "p"  identity = "t" }`         |
| `notify:systemd`                 | `notify = "systemd"`                             |
| `type:forking`                   | `type = "forking"`                               |
| `manual:yes`                     | `manual-start = true`                            |
| `remain:yes`                     | `remain-after-exit = true`                       |
| `restart:always` / `restart:NUM` | `restart = "always"` / `restart-max = NUM`       |
| `restart_sec:SEC`                | `restart-sec = SEC`                              |
| `norestart`                      | `restart = "never"`                              |
| `respawn`                        | `respawn = true`                                 |
| `oncrash:reboot`                 | `oncrash = "reboot"`                             |
| `halt:SIG`                       | `stop-signal = "SIG"`                            |
| `kill:SEC`                       | `stop-timeout = SEC`                             |
| `pre:[TMO,]/script`              | `exec-start-pre`, `exec-start-pre-timeout`       |
| `ready:[TMO,]/script`            | `exec-start-ready`, and its `-timeout`           |
| `stop:[TMO,]/script`             | `exec-stop`, and its `-timeout`                  |
| `post:[TMO,]/script`             | `exec-stop-post`, and its `-timeout`             |
| `reload:[TMO,]/script`           | `exec-reload`, and its `-timeout`                |
| `cleanup:[TMO,]/script`          | `exec-cleanup`, and its `-timeout`               |
| `caps:^cap_a,%cap_b`             | `capabilities = { "^cap_a", "%cap_b" }`          |
| `conflict:a,b`                   | `conflicts = { "a", "b" }`                       |
| `if:svc` / `if:<cond>`           | `if = "svc"` / `if = "cond"`, no angle brackets  |
| `tty:/dev/x`                     | `tty = "/dev/x"`                                 |
| `nowarn`                         | leading `-` on `command` or `envfile`            |
| `restarttmo:`                    | dropped, was already an alias for `restart_sec:` |

Repeated stanzas
----------------

The line-based format has no titles, so the same service could be
declared more than once and Finit would sort out which line applied.
A block title *is* the identity, and two blocks sharing one in the
same file are rejected.  The two shapes that relied on the repetition
convert differently.

**Several candidate binaries for one service.**  The daemon is known
under more than one name and the stanzas were repeated once per name,
each with `nowarn` so the ones that were not installed were skipped:

    service nowarn pid:!/run/udevd.pid [S12345789] /lib/systemd/systemd-udevd -- Device event daemon
    service nowarn pid:!/run/udevd.pid [S12345789] udevd -- Device event daemon

The candidates now go in one block, and Finit starts the first one it
finds:

    service udevd {
        description = "Device event daemon"
        runlevel    = "S12345789"
        pidfile     = "/run/udevd.pid"
        command     = { "/lib/systemd/systemd-udevd", "-udevd" }
    }

**One service gated differently per platform.**  The command is the
same every time, only `if:` and the conditions differ, e.g. a syslog
daemon that has to wait for whichever hotplug daemon the system has:

    service if:udevd nowarn env:-/etc/default/sysklogd <run/udevadm:5/success> \
           [S0123456789] syslogd -F $SYSLOGD_ARGS -- System log daemon
    service if:mdev  nowarn env:-/etc/default/sysklogd <run/coldplug/success> \
           [S0123456789] syslogd -F $SYSLOGD_ARGS -- System log daemon

All of these are one service, `syslogd`, and everything downstream
waits for the one `pid/syslogd` barrier it provides.  That barrier is
the reason the repetition existed: the title alone spells it, so
separate titles would rename it.

Give each variant its own title and name the shared barrier with
`provides`:

    service syslogd:udev {
        description = "System log daemon"
        runlevel    = "S0123456789"
        if          = "udevd"
        conditions  = { "run/udevadm:5/success" }
        provides    = "pid/syslogd"
        envfile     = "-/etc/default/sysklogd"
        command     = "-syslogd -F $SYSLOGD_ARGS"
    }
    service syslogd:mdev {
        description = "System log daemon"
        runlevel    = "S0123456789"
        if          = "mdev"
        conditions  = { "run/coldplug/success" }
        provides    = "pid/syslogd"
        envfile     = "-/etc/default/sysklogd"
        command     = "-syslogd -F $SYSLOGD_ARGS"
    }

Whichever variant `if` qualifies asserts `pid/syslogd` on top of its
own `pid/syslogd:udev`, so downstream blocks need no change.  The `if`
statements are meant to be mutually exclusive; if two of them do
qualify, the second claim is refused with a warning and only the first
variant supplies the barrier.  See [Provided
Conditions](service-opts.md#provided-conditions).

`initctl` now knows the variants apart, `initctl status syslogd:udev`,
and a bare `initctl status syslogd` still lists them all.

Splitting the variants across files also works, since the ban on
duplicate titles is per file, as does leaving that one file in the
line-based format.  Neither is needed for this shape any more.

Cgroups
-------

The standalone `cgroup.NAME` line selected a group for every stanza
after it in the file, and `cgroup:opts` applied settings to whichever
group was current.  Neither survives: every block names its own group,
so nothing depends on what came earlier in the file.

    cgroup.maint
    service [2345] cgroup:cpu.weight:250 foo -- Foo daemon

becomes

    service foo {
        description = "Foo daemon"
        runlevel    = "2345"
        cgroup maint { cpu.weight = 250 }
        command     = "foo"
    }

Top-level group declarations keep their name and settings:

    cgroup system cpu.weight:9700 mem.max:10M

becomes

    cgroup system {
        cpu.weight = 9700
        memory.max = 10M
    }

TTYs
----

The three positional variants become three key choices:

    tty [12345] /dev/ttyS0 115200 noclear vt220
    tty [12345] /sbin/getty -L ttyS0 115200 vt100
    tty [12345] notty

become

    tty ttyS0 {
        runlevel = "12345"
        device   = "/dev/ttyS0"
        baud     = 115200
        term     = "vt220"
        noclear  = true
    }
    tty getty {
        runlevel = "12345"
        command  = "/sbin/getty -L ttyS0 115200 vt100"
    }
    tty shell {
        runlevel = "12345"
        notty    = true
    }

The bare flags keep their names as booleans: `noclear`, `nowait`,
`nologin`, `passenv`, `rescue`, e.g. `passenv` becomes
`passenv = true`.

A `tty` block is named by the device, not the title, so all three above
show up as `tty:ttyS0` and the like in `initctl`.  The title still has
to be unique within the file.

Top-level directives
--------------------

| Line-based                       | Block key                                                |
|----------------------------------|----------------------------------------------------------|
| `host NAME`, `hostname NAME`     | `hostname = "NAME"`                                      |
| `module foo args` (repeated)     | `modules = { "foo args", ... }`                          |
| `network script args`            | `network = "script args"`                                |
| `runlevel N`                     | `runlevel = N`                                           |
| `rcsd /path`                     | `rcsd = "/path"`                                         |
| `runparts [progress] [sysv] DIR` | `runparts = "DIR"`, `runparts-progress`, `runparts-sysv` |
| `set KEY=VAL` (repeated)         | `environment { KEY = "VAL" }`                            |
| `log size:100k count:4`          | `log { size = 100k  count = 4 }`                         |
| `rlimit [hard\|soft] RES LIM`    | `rlimit { hard.res = LIM }`                              |
| `readiness none`                 | `readiness = "none"`                                     |
| `reboot-delay N`                 | `reboot-delay = N`                                       |
| `reboot-watchdog on`             | `reboot-watchdog = true`                                 |
| `service-interval SEC`           | `service-interval = SEC`                                 |
| `shutdown script`                | `shutdown = "script"`                                    |
| `mknod /dev/x c 1 2`             | `mknod = { "/dev/x c 1 2" }`                             |
| `include /path`                  | `include("/path")`                                       |

Worth knowing
-------------

  * Templates work unchanged: `%i` is replaced before the file is
    parsed, so `service serv:%i { ... }` in a `serv@.conf` behaves
    exactly like its legacy counterpart.
  * A list cannot hold comments; the lexer reads entries after a `#`
    regardless.  Put commented-out candidates above the list.
  * `${VAR}` in a value is expanded when the file is read, against
    Finit's environment, and `${VAR:-default}` works too.  An unset
    variable expands to nothing.  A plain `$VAR` is left alone and
    reaches the service, which is what keeps `command = "syslogd -F
    $SYSLOGD_ARGS"` working with an `envfile`.
  * New settings only appear in the block format.  The first are the
    [per-service directories](service-opts.md#service-directories),
    `runtime-dir` and friends, and [`pam`](pam.md).

For the full description of every key, see the rest of the
[Configuration](index.md) section.
