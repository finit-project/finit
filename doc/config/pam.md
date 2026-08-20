PAM Sessions
============

`pam = "NAME"` runs a service inside a PAM session set up from
`/etc/pam.d/NAME`.  The `session` stack in that file runs for the
process that goes on to become the daemon, so modules like `pam_limits`,
`pam_env`, or `pam_keyinit` see the service the way they see a login.

## Basic Usage

A display server that needs the session a login would have arranged for
it:

```conf
service weston {
    user    = "weston"
    pam     = "weston-autologin"
    command = "/usr/bin/weston --continue-without-input"
}
```

With `/etc/pam.d/weston-autologin`:

```
auth     required  pam_permit.so
account  required  pam_unix.so
session  required  pam_unix.so
session  required  pam_limits.so
```

The `auth` line is needed even though nothing is ever authenticated.
Opening the session goes through `pam_setcred()`, which consults the
`auth` stack, and an empty stack comes back as a permission denial, so a
pam.d file with only `account` and `session` lines keeps the service
from starting.

The value names a file in `/etc/pam.d`, it is not a path.  A value
holding `/` or `..`, or one too long to fit, is refused, with an error
in the log when the .conf file is read.  The service does not start
either, `initctl status` reports it as missing.  Like the per-service
directory keys, `pam` exists in the block format only.

## No Authentication

Finit runs the account and session stacks, `pam_acct_mgmt()`,
`pam_setcred()`, and `pam_open_session()`, and never
`pam_authenticate()`.  A module that asks a question gets a
conversation error back and its entry in the stack fails.

A service whose account is denied, an expired account say, does not
start, and neither does one naming a pam.d file that is not installed.
The child exits 71 (`EX_OSERR`), `initctl status` shows the service as
crashed, and PAM's own reason is in the log.

## Requirements

PAM support is built by default, see [Building Finit](../build.md).
Without it, e.g. after `--disable-pam`, a service declaring `pam` is
refused rather than started with the stacks skipped:

    weston: pam weston-autologin requires Finit built with --enable-pam

## Which Blocks Take It

`service`, `task`, `run`, and `sysv`.  Not `tty`: `login` opens a
session of its own there.

Every fork gets its own session, so the `pre:`, `post:`, `ready:`, and
`cleanup:` scripts each open and close one too, as do the stop and
reload scripts and the `stop` call on a `sysv` script.

A refused value stops those too.  A `pre:` script forks before the
start-time check runs, so it exits 71 without running instead of the
service being reported missing.

## The User

`user` decides who the session is for.  Without it the session is for
root.

systemd documents the opposite for its equivalent.  `systemd.exec(5)`
says `PAMName=` is "only useful in conjunction with the `User=`
setting, and is otherwise ignored".  That was true of systemd up to and
including v256, v257 changed it to open a session for the manager's own
user, and the man page was never updated.  Finit does what v257 does.

A service with a [controlling tty](tty.md#controlling-tty-for-services)
has it passed to PAM as `PAM_TTY`, for the modules that care which
terminal a session is on.

## Precedence

Three places where PAM and a Finit setting cover the same ground:

- `pam_limits` overrides a per-service `rlimit`.  A block asking for
  `nofile = 4096` under a `limits.conf` that says 512 gets 512.
- `pam_env` overrides Finit's own environment defaults, `PATH`, `USER`,
  `LOGNAME`, and `HOME`, and `envfile` in turn overrides `pam_env`.  A
  `HOME` from the session stack also moves the working directory, which
  otherwise is the home directory from `/etc/passwd`.
- The groups from `/etc/group` and `extra-groups` override `pam_group`.

## The Session Keeper

A helper is forked next to the service to close the session when the
service exits, `(finit-pam)`:

```
     CGroup : /system/weston cpu 0 [100, max] mem [--.--, max]
              |- 312 /usr/bin/weston --continue-without-input
              `- 313 (finit-pam)
```

There is one per fork.  It runs as the service's user, in the service's
cgroup, and stopping the service takes it along.

A daemon that reaps children in its own `wait()` loop will see a child
it never forked.  systemd has the same property, with `(sd-pam)`.

## Limitations

- `type = "forking"` closes the session early.  The initial process
  exits by design, the keeper's parent-death signal fires with it, and
  the session is closed while the real daemon runs on.  Finit warns
  about the combination when it reads the .conf file, and starts the
  service anyway:

        /etc/finit.d/foo.conf: foo: pam with type = forking closes the
        session when the initial process exits

- A daemon whose initial thread exits while the process lives closes the
  session the same way.  The parent-death signal follows the thread that
  forked the keeper, not the process.
- A capability granted by `pam_cap.so` is only kept when the service
  also sets [`capabilities`](capabilities.md).
- The keeper shares the service's cgroup, so an empty cgroup directory
  can outlive a stop until the next start reuses it.  Cosmetic.
- A module that blocks has no time bound.  `pam_open_session()` waits
  for as long as the module does, `pam_ldap` against an unreachable
  server, say, or `pam_mount` on a hung network mount.  The fork has already succeeded by then, so the service
  reaches the running state and stays there with no daemon behind it.
  Nothing crashes and nothing restarts.

## See Also

- [Service Options](service-opts.md) - the other run/task/service keys
- [Linux Capabilities](capabilities.md) - the key `pam_cap.so` needs
- [Building Finit](../build.md) - `--disable-pam` and its dependency
- [pam(8)](https://man7.org/linux/man-pages/man8/pam.8.html) - the PAM library
- [pam.d(5)](https://man7.org/linux/man-pages/man5/pam.d.5.html) - the file format
- [pam_limits(8)](https://man7.org/linux/man-pages/man8/pam_limits.8.html) - limits from `limits.conf`
