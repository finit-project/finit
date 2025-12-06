General Logging
===============

**Syntax:** `log size:200k count:5`

Log rotation for run/task/services using the `log` sub-option with
redirection to a log file.  Global setting, applies to all services.

The size can be given as bytes, without a specifier, or in `k`, `M`,
or `G`, e.g. `size:10M`, or `size:3G`.  A value of `size:0` disables
log rotation.  The default is `200k`.

The count value is recommended to be between 1-5, with a default 5.
Setting count to 0 means the logfile will be truncated when the MAX
size limit is reached.

Redirecting Output
------------------

The `run`, `task`, and `service` stanzas also allow the keyword `log` to
redirect `stderr` and `stdout` of the application to a file or syslog
using the native `logit` tool.  This is useful for programs that do not
support syslog on their own, which is sometimes the case when running
in the foreground.

The full syntax is:

    log:/path/to/file
    log:prio:facility.level,tag:ident
    log:console
    log:null
    log

Default `prio` is `daemon.info` and default `tag` is the basename of the
service or run/task command.

Log rotation is controlled using the global `log` setting.

**Example:**

    service log:prio:user.warn,tag:ntpd /sbin/ntpd pool.ntp.org -- NTP daemon

Output Buffering
----------------

When using the `log` directive, Finit redirects the service's stdout and
stderr to a pipe connected to a logger process.  Programs detect this as
non-interactive output (i.e., `isatty()` returns false) and typically
switch from line-buffered to fully-buffered mode.

Most well-behaved daemons explicitly flush their output or use syslog
directly, so this is rarely an issue.  However, if a service's log
messages appear delayed or batched, you can force line-buffered output
by wrapping the command with `stdbuf`:

    service log /usr/bin/stdbuf -oL /path/to/command -- My service

The `-oL` option forces line-buffered output, and `-o0` forces unbuffered
output.  See `stdbuf(1)` for details.

> [!NOTE]
> Using `stdbuf` is rarely necessary. Only use it if you observe actual
> buffering issues with a specific service.
