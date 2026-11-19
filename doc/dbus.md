D-Bus Integration
=================

Finit ships with a built-in, brokerless [D-Bus][] implementation, **libink**
(`-link`), that exposes the running init system as a peer on its own private
bus, and optionally on the system bus when `dbus-daemon` is available.
Everything `initctl` does is also reachable from any generic D-Bus tooling —
`dbus-send`, `dbus-monitor`, `gdbus`, language bindings, dashboards,
monitoring agents, etc.

> [!NOTE]
> D-Bus support is enabled by default, opt out at build time with
> `--disable-dbus`, see [Building](build.md) for details.  When disabled,
> `initctl` keeps using the legacy `INIT_SOCKET` transport and Finit
> exposes no bus.

Bus address
-----------

| Bus                    | Address                                     |
|------------------------|---------------------------------------------|
| Local (always)         | `unix:path=/run/finit/bus`                  |
| System (opportunistic) | `unix:path=/var/run/dbus/system_bus_socket` |

The bundled device manager serves its own `org.finit.Device1` the same
way on `unix:path=/run/keventd/bus`, see [keventd](keventd.md); one
socket per daemon, no forwarding between them.

The **local** bus is brokerless: clients connect straight to Finit over a
Unix-domain socket using the standard D-Bus SASL EXTERNAL handshake.  No
`dbus-daemon` is required, which makes it suitable for embedded systems that
don't ship one.

The socket is `0660`, owned by `root` and the group given to
`--with-group` at build time, the same gate as `/run/finit/socket` that
`initctl` falls back on.  The bus reaches every operation `initctl`
does, so restricting one and not the other would leave the door open.
Members of that group may use it, see [Authorization](#authorization).

Finit accepts at most 64 concurrent local-bus peers; further
connections are refused until one disconnects.  Match rules given to
`AddMatch` support the `type`, `interface`, `member`, and `path` keys;
`arg0` and its variants are not implemented.

For the system bus a standard busconfig policy ships in
`dbus-1/org.finit.conf`, installed to `$datadir/dbus-1/system.d`: only
root may own `org.finit`, unprivileged callers reach introspection,
properties, and the read-only methods.
Finit also enforces per-method authorization itself, so a permissive
policy installed by mistake does not open state-changing methods.

The **system** bus is best-effort: Finit probes for a running `dbus-daemon`
and, when reachable, claims the well-known name `org.finit` so that standard
tooling sees Finit just like any other system service:

```sh
dbus-send --system --print-reply --dest=org.finit /org/finit/manager \
          org.finit.Manager1.ListServices

dbus-monitor --system "sender='org.finit'"
```

If no system bus is present (the common case on embedded targets), this step
is silently skipped.

Object tree
-----------

```
/
├── org/
│   └── finit/
│       ├── manager                          Manager1
│       ├── cond                             Cond1
│       └── service/
│           ├── keventd                      Service1 (one per service)
│           ├── sshd
│           └── …
└── org/freedesktop/DBus                     Standard well-known interfaces
```

Every node implements the usual stock interfaces:

| Interface                             | Purpose                                   |
|---------------------------------------|-------------------------------------------|
| `org.freedesktop.DBus`                | `Hello`, `AddMatch`, `RemoveMatch` — on `/org/freedesktop/DBus` only |
| `org.freedesktop.DBus.Peer`           | `Ping`, `GetMachineId`                    |
| `org.freedesktop.DBus.Introspectable` | `Introspect()` — XML description          |
| `org.freedesktop.DBus.Properties`     | `Get`, `GetAll`; nothing is writable      |

Note: `Hello`, `AddMatch`, and `RemoveMatch` are answered on the canonical
`/org/freedesktop/DBus` object only, as per the D-Bus specification.

`org.finit.Manager1`
--------------------

Lives at **`/org/finit/manager`**.  Owns the global init operations
and the service registry.

### Methods

| Method                       | In sig | Out sig | Priv. | Notes                                                     |
|------------------------------|--------|---------|-------|-----------------------------------------------------------|
| `ListServices`               | —      | `as`    | no    | Returns identities (`name`, `name:id`) of loaded services |
| `GetService`                 | `s`    | `o`     | no    | Resolves an identity to its `Service1` object path        |
| `Start`                      | `s`    | —       | yes   | Start the service(s) matching the identity                |
| `Stop`                       | `s`    | —       | yes   | Stop the service(s) matching the identity                 |
| `Restart`                    | `s`    | —       | yes   | Restart (stop + start) the service(s)                     |
| `Reload`                     | —      | —       | yes   | Re-read all `*.conf` and apply changes                    |
| `SetRunlevel`                | `u`    | —       | yes   | Transition to runlevel `u` (0–9)                          |
| `SetDebug`                   | —      | —       | yes   | Toggle Finit's runtime debug flag                         |
| `Signal`                     | `su`   | —       | yes   | Send signal `u` (1–31) to services matching identity `s`  |
| `Suspend`                    | —      | —       | yes   | `sync()` + suspend-to-RAM                                 |
| `Reboot`, `Halt`, `Poweroff` | `u`    | —       | yes   | Trigger the corresponding shutdown sequence; the argument arms the emergency fallback timer (seconds, 0 = none) |

Edge cases follow the legacy `initctl` protocol: `Suspend` and the
reboot family reply `WrongRunlevel` during bootstrap and shutdown,
`SetRunlevel` is a warning + no-op in runlevel 0/6 and records the
level for the end of bootstrap in runlevel S, and `Signal` fails for
stopped services.  One deliberate divergence: a `SetRunlevel` argument
outside 0–9 returns `InvalidArgs`, where the legacy protocol
acknowledges silently.

### Properties

All read-only strings; observable via `Properties.Get` and
`Properties.GetAll`.

| Property       | Type | Returns                                                |
|----------------|------|--------------------------------------------------------|
| `Runlevel`     | `s`  | Current runlevel as a digit (`"2"`, `"3"`, …) or `"S"` |
| `PrevRunlevel` | `s`  | Previous runlevel, same encoding, `"N"` when none      |
| `Version`      | `s`  | Finit's version string (`PACKAGE_VERSION`)             |

### Signals

| Signal                | Body                                   | Fires when             |
|-----------------------|----------------------------------------|------------------------|
| `ServiceStateChanged` | `sss` — identity, old state, new state | Service transitions    |
| `RunlevelChanged`     | `ss`  — old level, new level           | System runlevel change |
| `ConfigReloaded`      | —                                      | `initctl reload` completed; providers of generation-file conditions re-assert |

State names emitted by `ServiceStateChanged` are stable wire strings:
`halted`, `done`, `dead`, `cleanup`, `teardown`, `stopping`, `setup`,
`paused`, `waiting`, `starting`, `running`.  `RunlevelChanged` levels
use the same encoding as the `Runlevel` property: digits, `"S"`, `"N"`.

`org.finit.Service1` (per-service objects)
------------------------------------------

Lives at **`/org/finit/service/<encoded>`**, one object per loaded service.
`<encoded>` is the service identity (name, or `name:id` for templated
services) put through systemd-style `_HH` hex escaping — ASCII alphanumerics
and `_` pass through, anything else becomes `_HH` where `HH` is the hex byte.
Use `Manager1.GetService(identity)` to look up the exact path rather than
constructing it by hand.

| Method    | In sig | Out sig | Priv. | Notes                                                       |
|-----------|--------|---------|-------|-------------------------------------------------------------|
| `Start`   | —      | —       | yes   | Equivalent to `Manager1.Start(<identity>)` for this service |
| `Stop`    | —      | —       | yes   | …                                                           |
| `Restart` | —      | —       | yes   | …                                                           |
| `Reload`  | —      | —       | yes   | Send the service's `reload-signal`, default `SIGHUP`; restart when set to `"none"` |

### Properties

All read-only; observable via `Properties.Get` and `Properties.GetAll`.

| Property        | Type | Returns                                                        |
|-----------------|------|----------------------------------------------------------------|
| `Identity`      | `s`  | Service identity, `name` or `name:id`                          |
| `Name`          | `s`  | Program name (basename of the command)                         |
| `State`         | `s`  | Current status, same vocabulary as `initctl status`            |
| `Pid`           | `u`  | Current PID, 0 when not running                                |
| `RestartCount`  | `u`  | Restarts since the last stable run                             |
| `Runlevels`     | `u`  | Allowed runlevels as a bitmask, bit N = runlevel N, bit 10 = S |
| `Description`   | `s`  | The service's `description` string                             |
| `Command`       | `s`  | Full command line, arguments included                          |
| `Conditions`    | `s`  | Declared conditions, raw `.conf` form                          |
| `Type`          | `s`  | Unit type: `service`, `task`, `run`, `sysv`, `tty`, `free`     |
| `Origin`        | `s`  | Source `.conf` file, empty for built-ins                       |
| `Environment`   | `s`  | The service's `env` setting, raw                               |
| `PidFile`       | `s`  | Declared PID file, raw (`!` prefix included)                   |
| `User`          | `s`  | User the service runs as                                       |
| `Group`         | `s`  | Group the service runs as                                      |
| `Uptime`        | `u`  | Seconds since start, 0 when not running                        |
| `ExitStatus`    | `u`  | Raw `waitpid(2)` status from the last exit                     |
| `RestartsTotal` | `u`  | Restarts over the service's lifetime                           |
| `RestartMax`    | `u`  | Restart limit before the service is blocked                    |
| `RestartDelay`  | `u`  | Seconds before the next restart, should the service crash      |
| `RestartDelayMax` | `u` | The `restart-max-sec` setting, 0 when not set                 |
| `Starts`        | `u`  | Times started, for `manual-start` units                        |
| `ManualStart`   | `b`  | `manual-start` set in the `.conf`                              |
| `Forking`       | `b`  | Daemon forks to background                                     |
| `Started`       | `b`  | Run/task completed successfully                                |

On every state transition the object also emits the standard
`org.freedesktop.DBus.Properties.PropertiesChanged` signal: `State`
in the changed dictionary, `Pid` and `RestartCount` invalidated (call
`Get` for fresh values).

The per-service surface lets generic tooling supply an object handle
once and then invoke methods on it, instead of repeatedly passing the
identity string.

`org.finit.Cond1`
-----------------

Lives at **`/org/finit/cond`**.  Exposes Finit's
[condition system](conditions.md) to bus clients.

### Methods

| Method  | In sig | Out sig | Priv. | Notes                                                        |
|---------|--------|---------|-------|--------------------------------------------------------------|
| `Get`   | `s`    | `s`     | no    | Returns `"on"`, `"off"`, or `"flux"` for the named condition |
| `Set`   | `s`    | —       | yes   | Assert a `usr/<name>` condition                              |
| `Clear` | `s`    | —       | yes   | Deassert a `usr/<name>` condition                            |
| `List`  | —      | `as`    | no    | Names of all known conditions                                |
| `Dump`  | —      | `a(ss)` | no    | `(name, state)` pairs for everything `List` returns          |

Note: non-`usr/*` paths are rejected with `InvalidArgs` -- system
conditions belong to Finit's state machine.

A service consuming such a condition:

    service alarm {
        description = "Foo alarm"
        runlevel    = "2345"
        conditions  = { "usr/data-ready" }
        command     = "alarm --arg foo"
    }

asserted from any bus client with `Cond1.Set string:"data-ready"`, see
the examples below.

### Signals

| Signal             | Body                   | Fires when                            |
|--------------------|------------------------|---------------------------------------|
| `ConditionChanged` | `ss` — name, new state | A condition is asserted or deasserted |

Authorization
-------------

Privileged methods accept `root`, and any caller belonging to the group given
to `--with-group` at build time.  That is the same set the socket mode already
admits, so the two gates agree instead of the socket letting the group in and
every method turning it away.

On the **local** bus the kernel settles this at `connect()`: `SO_PEERCRED`
gives Finit the caller's uid and `SO_PEERGROUPS` its group set, both straight
from the kernel.  Finit matches the group against `--with-group` itself, so
the check never touches NSS -- `getpwuid`/`getgrouplist` can block on a slow
LDAP or SSSD backend, and PID 1 must never block.  Because the group set is
the caller's real credentials, privilege escalation through the bus is
impossible.

On the **system** bus one connection carries every caller, so `SO_PEERCRED`
describes `dbus-daemon` rather than whoever asked.  Finit asks the bus driver
`GetConnectionUnixUser` about the message sender and holds the call until the
answer arrives -- nothing blocks, the reply comes back through the same event
loop as everything else.  The broker does not report the caller's groups in
that reply, so **privileged methods over the system bus are root-only**; group
membership is honoured on the local bus only.  Lifting that is future work,
see `libink/README.md`.

Answers are cached per sender.  A bus never reuses a unique name while it
runs, so an answer holds for as long as that bus does; Finit empties the cache
when the broker goes away, since a new one numbers its clients from scratch.
A caller Finit cannot identify is refused, so the failure mode is a denial
rather than an escalation.

When a privileged method is rejected the error name is exactly
`org.freedesktop.DBus.Error.AccessDenied`, and the body carries a short reason
string.

`initctl` integration
---------------------

`initctl` transparently routes through D-Bus when the bus socket is present,
and falls back to the legacy `INIT_SOCKET` transport otherwise.  Concretely,
the following subcommands use the bus first:

| Subcommand                 | Method                                           |
|----------------------------|--------------------------------------------------|
| `initctl start`            | `Manager1.Start(svc)`                            |
| `initctl stop`             | `Manager1.Stop(svc)`                             |
| `initctl restart`          | `Manager1.Restart(svc)`                          |
| `initctl reload`           | `Manager1.Reload()`                              |
| `initctl reload S`         | `Service1.Reload()` (per-svc)                    |
| `initctl reboot`           | `Manager1.Reboot(timeout)`                       |
| `initctl halt`             | `Manager1.Halt(timeout)`                         |
| `initctl poweroff`         | `Manager1.Poweroff(timeout)`                     |
| `initctl suspend`          | `Manager1.Suspend()`                             |
| `initctl debug`            | `Manager1.SetDebug()`                            |
| `initctl signal` (or `kill`) | `Manager1.Signal(svc, signo)`                  |
| `initctl runlevel`         | `Properties.Get(Manager1.Runlevel/PrevRunlevel)` |
| `initctl cond set/get/clear` | `Cond1.{Set,Get,Clear}`, `clr` is an alias     |

Two `initctl` subcommands are pure D-Bus features without legacy equivalents:

* `initctl monitor` — subscribes to every signal on the local bus and prints
  one line per delivery (with timestamp, interface and member).  Same idea as
  `dbus-monitor`, but scoped to Finit and with no need to pass `--address`.

* `initctl cond` emits the standard `Cond1.ConditionChanged` signal as a side
  effect, so subscribers observe user-driven state changes the same way they
  observe service-driven ones.

Examples
--------

The examples below use `dbus-send` and `dbus-monitor`, which ship as part of
the [dbus][] reference implementation; they're widely packaged and don't pull
in any extra runtime.  Any tool that speaks D-Bus over an AF_UNIX socket works
equally well — `gdbus`, Python's `jeepney`/`dasbus`, etc. — substitute their
syntax for setting the bus address.  The wire protocol is the compatibility
surface: Finit's own **libink** is an internal implementation detail, external
clients should use any standard D-Bus library.

When `org.finit` is registered on the system bus you can replace
`--address=unix:path=/run/finit/bus` with `--system` in any example below.

List the running services:

```sh
dbus-send --address=unix:path=/run/finit/bus \
          --type=method_call --print-reply --dest=org.finit \
          /org/finit/manager \
          org.finit.Manager1.ListServices
```

Read the current runlevel via the Properties interface:

```sh
dbus-send --address=unix:path=/run/finit/bus \
          --type=method_call --print-reply --dest=org.finit \
          /org/finit/manager \
          org.freedesktop.DBus.Properties.Get \
          string:org.finit.Manager1 string:Runlevel
```

Subscribe to every state change on the manager object:

```sh
dbus-monitor --address=unix:path=/run/finit/bus \
             "type='signal',interface='org.finit.Manager1'"
```

Or use `initctl monitor`, which does the same without any address
plumbing.

Restart a service by its object path:

```sh
dbus-send --address=unix:path=/run/finit/bus \
          --type=method_call --dest=org.finit \
          /org/finit/service/sshd \
          org.finit.Service1.Restart
```

Trigger a `usr/`-condition assertion that wakes any dependent service:

```sh
dbus-send --address=unix:path=/run/finit/bus \
          --type=method_call --dest=org.finit \
          /org/finit/cond \
          org.finit.Cond1.Set string:"data-ready"
```

The `--dest=org.finit` argument is informational on the local
brokerless bus — Finit accepts any destination because there's no
broker to route by name — but `dbus-send` requires it syntactically.

[dbus]:  https://gitlab.freedesktop.org/dbus/dbus
[D-Bus]: https://dbus.freedesktop.org/doc/dbus-specification.html
