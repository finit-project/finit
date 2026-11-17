Rebooting & Halting
===================

Traditionally, rebooting and halting a UNIX system is done by switching
to the corresponding runlevel (0 or 6).  Over time this has changed and
Finit comes with its own tooling providing: `shutdown`, `reboot`,
`poweroff`, and `suspend`.  These commands are also available from the
[`initctl`](initctl.md) tool.

For compatibility reasons Finit listens to the same set of signals as
BusyBox init.  This is not 100% compatible with SysV init, but clearly
the more common combination for Finit.  For more details, see the
[Signal](signals.md) section.

Scheduled Shutdown
------------------

The `shutdown` command takes a time, and an optional message to warn
logged-in users with:

    shutdown -r +10 "Upgrading to v5.0, back in five"
    shutdown -h 23:30
    shutdown -c

The time is `now`, `+MIN` minutes from now, at most a year, or the next
`HH:MM`.  Finit keeps track of it, so it survives logging out.  It counts
down the time left, changing the system clock does not move it.  At 60, 30, 15 and 10
minutes left, and then every minute from five, Finit writes the warning
to the terminal of every logged-in user.  From five minutes before, it
also creates `/etc/nologin`, with the message, to refuse new logins.  A
`/etc/nologin` already in place is left alone.

A new `shutdown TIME` replaces the scheduled one, and `shutdown -c`
cancels it.  Without a time, or with `now` and no message, `shutdown`
acts right away, as before.
