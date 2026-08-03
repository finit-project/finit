D-Bus Integration
=================

Finit ships with a built-in, brokerless [D-Bus][] implementation,
**libink**, that exposes the running init system as a peer on its own
private bus, and optionally on the system bus when `dbus-daemon` is
available.  Everything `initctl` does is also reachable from any
generic D-Bus tooling — `dbus-send`, `dbus-monitor`, `gdbus`,
language bindings, dashboards, monitoring agents, etc.

> [!NOTE]
> D-Bus support is enabled at build time with `--enable-dbus`.  See
> [Building](build.md) for details.  When disabled, `initctl` keeps
> using the legacy `INIT_SOCKET` transport and Finit exposes no bus.

Bus address
-----------

| Bus | Address |
| --- | --- |
| Local (always)         | `unix:path=/run/finit/bus` |
| System (opportunistic) | `unix:path=/var/run/dbus/system_bus_socket`, well-known name `org.finit` |

The **local** bus is brokerless: clients connect straight to Finit
over a Unix-domain socket using the standard D-Bus SASL EXTERNAL
handshake.  No `dbus-daemon` is required, which makes it suitable for
embedded systems that don't ship one.

The **system** bus is best-effort: at start-up Finit probes for a
running `dbus-daemon` and, if reachable, registers `org.finit` so that
standard tooling sees Finit just like any other system service:

```sh
dbus-send --system --print-reply --dest=org.finit \
          /org/finit/manager \
          org.finit.Manager1.ListServices

dbus-monitor --system "sender='org.finit'"
```

If no system bus is present (the common case on embedded targets),
this step is silently skipped.

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

| Interface                            | Purpose |
| ------------------------------------ | ------- |
| `org.freedesktop.DBus`               | `Hello`, `AddMatch`, `RemoveMatch` (on `/org/freedesktop/DBus`) |
| `org.freedesktop.DBus.Peer`          | `Ping`, `GetMachineId` |
| `org.freedesktop.DBus.Introspectable`| `Introspect()` — XML description |
| `org.freedesktop.DBus.Properties`    | `Get`, `GetAll` (Set not yet implemented) |

`org.finit.Manager1`
--------------------

Lives at **`/org/finit/manager`**.  Owns the global init operations
and the service registry.

### Methods

| Method                  | In sig | Out sig | Privileged | Notes |
| ----------------------- | ------ | ------- | ---------- | ----- |
| `ListServices`          | —      | `as`    | no  | Returns the identities (`name`, `name:id`) of every loaded service. |
| `GetService`            | `s`    | `o`     | no  | Resolves a service identity to its `Service1` object path. |
| `Start`                 | `s`    | —       | yes | Start the service(s) matching the identity. |
| `Stop`                  | `s`    | —       | yes | Stop the service(s) matching the identity. |
| `Restart`               | `s`    | —       | yes | Restart (stop + start) the service(s). |
| `Reload`                | —      | —       | yes | Re-read all `*.conf` and apply changes (same as `initctl reload`). |
| `SetRunlevel`           | `u`    | —       | yes | Transition to runlevel `u` (0–6). |
| `SetDebug`              | —      | —       | yes | Toggle Finit's runtime debug flag. |
| `Signal`                | `su`   | —       | yes | Send signal number `u` (1–31) to every running service matching identity `s`.  Halted matches are silently skipped. |
| `Suspend`               | —      | —       | yes | `sync()` + suspend-to-RAM. |
| `Reboot` / `Halt` / `Poweroff` | — | —    | yes | Trigger the corresponding shutdown sequence. |

### Properties

All read-only strings; observable via `Properties.Get` and
`Properties.GetAll`.

| Property       | Type | Returns |
| -------------- | ---- | ------- |
| `Runlevel`     | `s`  | Current runlevel as a digit (`"2"`, `"3"`, …) or `"S"`. |
| `PrevRunlevel` | `s`  | Previous runlevel, same encoding. |
| `Version`      | `s`  | Finit's version string (`PACKAGE_VERSION`). |

### Signals

| Signal                  | Body | Fires when |
| ----------------------- | ---- | ---------- |
| `ServiceStateChanged`   | `(sss)` — identity, old state, new state | A service transitions between supervisor states. |
| `RunlevelChanged`       | `(ss)`  — old level, new level           | The system enters a new runlevel. |

State names emitted by `ServiceStateChanged` are stable wire strings:
`halted`, `done`, `dead`, `cleanup`, `teardown`, `stopping`, `setup`,
`paused`, `waiting`, `starting`, `running`.

`org.finit.Service1` (per-service objects)
------------------------------------------

Lives at **`/org/finit/service/<encoded>`**, one object per loaded
service.  `<encoded>` is the service identity (name, or `name:id` for
templated services) put through systemd-style `_HH` hex escaping —
ASCII alphanumerics and `_` pass through, anything else becomes `_HH`
where `HH` is the hex byte.  Use `Manager1.GetService(identity)` to
look up the exact path rather than constructing it by hand.

| Method    | In sig | Out sig | Privileged | Notes |
| --------- | ------ | ------- | ---------- | ----- |
| `Start`   | —      | —       | yes | Equivalent to `Manager1.Start(<identity>)` for this service. |
| `Stop`    | —      | —       | yes | … |
| `Restart` | —      | —       | yes | … |
| `Reload`  | —      | —       | yes | Reload (SIGHUP if supported, else restart). |

### Properties

All read-only; observable via `Properties.Get` and `Properties.GetAll`.

| Property       | Type | Returns |
| -------------- | ---- | ------- |
| `Identity`     | `s`  | Service identity, `name` or `name:id`. |
| `Name`         | `s`  | Program name (basename of the command). |
| `State`        | `s`  | Current status, same vocabulary as `initctl status` (richer than the coarse `ServiceStateChanged` strings). |
| `Pid`          | `u`  | Current PID, 0 when not running. |
| `RestartCount` | `u`  | Restarts since the last stable run. |
| `Runlevels`    | `u`  | Allowed runlevels as a bitmask, bit N = runlevel N, bit 10 = S. |
| `Description`  | `s`  | The service's `description` string. |
| `Command`      | `s`  | Full command line, arguments included. |
| `Conditions`   | `s`  | Declared conditions, raw `.conf` form. |
| `Type`         | `s`  | Unit type: `service`, `task`, `run`, `sysv`, `tty`, `free`. |
| `Origin`       | `s`  | Source `.conf` file, empty for built-ins. |
| `Environment`  | `s`  | The service's `env` setting, raw. |
| `PidFile`      | `s`  | Declared PID file, raw (`!` prefix included). |
| `User`         | `s`  | User the service runs as. |
| `Group`        | `s`  | Group the service runs as. |
| `Uptime`       | `u`  | Seconds since start, 0 when not running. |
| `ExitStatus`   | `u`  | Raw `waitpid(2)` status from the last exit. |
| `RestartsTotal`| `u`  | Restarts over the service's lifetime. |
| `RestartMax`   | `u`  | Restart limit before the service is blocked. |
| `Starts`       | `u`  | Times started, for `manual-start` units. |
| `ManualStart`  | `b`  | `manual-start` set in the `.conf`. |
| `Forking`      | `b`  | Daemon forks to background. |
| `Started`      | `b`  | Run/task completed successfully. |

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

| Method   | In sig | Out sig | Privileged | Notes |
| -------- | ------ | ------- | ---------- | ----- |
| `Get`    | `s`    | `s`     | no  | Returns `"on"`, `"off"`, or `"flux"` for the named condition. |
| `Set`    | `s`    | —       | yes | Assert a `usr/<name>` condition.  Non-`usr/*` paths are rejected with `InvalidArgs` (system conditions belong to Finit's state machine). |
| `Clear`  | `s`    | —       | yes | Deassert a `usr/<name>` condition. |
| `List`   | —      | `as`    | no  | Names of all known conditions. |
| `Dump`   | —      | `a(ss)` | no  | `(name, state)` pairs for everything `List` returns. |

### Signals

| Signal              | Body | Fires when |
| ------------------- | ---- | ---------- |
| `ConditionChanged`  | `(ss)` — name, new state | A condition is asserted or deasserted. |

Authorization
-------------

Privileged methods reject any caller whose peer `uid` isn't 0.
On the **local** bus the kernel's `SO_PEERCRED` socket option tells
Finit exactly who's calling, so privilege escalation through the bus
is impossible.

On the **system** bus, all incoming traffic is treated as
unprivileged: it arrives through `dbus-daemon` (typically running as
root) and Finit cannot yet ask the daemon for the real requester's
uid via `GetConnectionUnixUser`.  This means external tooling can
freely `Get`/`Introspect`/`ListServices`, but every state-changing
method returns `org.freedesktop.DBus.Error.AccessDenied`.  Per-sender
uid lookup is on the roadmap.

When a privileged method is rejected the error name is exactly
`org.freedesktop.DBus.Error.AccessDenied`, and the body carries a
short reason string (e.g. `"permission denied: Start requires root"`).

`initctl` integration
---------------------

`initctl` transparently routes through D-Bus when the bus socket is
present, and falls back to the legacy `INIT_SOCKET` transport
otherwise.  Concretely, the following subcommands use the bus first:

| Subcommand          | Method                          |
| ------------------- | ------------------------------- |
| `initctl start`     | `Manager1.Start(svc)`           |
| `initctl stop`      | `Manager1.Stop(svc)`            |
| `initctl restart`   | `Manager1.Restart(svc)`         |
| `initctl reload`    | `Manager1.Reload()`             |
| `initctl reload S`  | `Service1.Reload()` (per-svc)   |
| `initctl reboot`    | `Manager1.Reboot()`             |
| `initctl halt`      | `Manager1.Halt()`               |
| `initctl poweroff`  | `Manager1.Poweroff()`           |
| `initctl suspend`   | `Manager1.Suspend()`            |
| `initctl debug`     | `Manager1.SetDebug()`           |
| `initctl signal`    | `Manager1.Signal(svc, signo)`   |
| `initctl runlevel`  | `Properties.Get(Manager1.Runlevel/PrevRunlevel)` |
| `initctl cond set/get/clr` | `Cond1.{Set,Get,Clear}`  |

Two `initctl` subcommands are pure D-Bus features without legacy
equivalents:

* `initctl monitor` — subscribes to every signal on the local bus and
  prints one line per delivery (with timestamp, interface and
  member).  Same idea as `dbus-monitor`, but scoped to Finit and with
  no need to pass `--address`.

* `initctl cond` (when D-Bus is reachable) emits the standard
  `Cond1.ConditionChanged` signal as a side effect, so subscribers
  observe user-driven state changes the same way they observe
  service-driven ones.

Examples
--------

The examples below use `dbus-send` and `dbus-monitor`, which ship as
part of the [dbus][] reference implementation; they're widely
packaged and don't pull in any extra runtime.  Any tool that speaks
D-Bus over an AF_UNIX socket works equally well — `gdbus`, Python's
`jeepney`/`dasbus`, etc. — substitute their syntax for setting the
bus address.

When `org.finit` is registered on the system bus you can replace
`--address=unix:path=/run/finit/bus` with `--system` in any example
below.

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

[dbus]: https://gitlab.freedesktop.org/dbus/dbus

Implementation notes
--------------------

The D-Bus server library lives in `libink/`.  It speaks the binary
D-Bus 1.0 wire format directly, has no `libdbus`/`sd-bus`/`GIO`
dependency, and is tiny — a few thousand lines of C.  The Finit-side
glue in `src/dbus.c` registers vtables for Manager1/Service1/Cond1,
emits the four signals from the appropriate hook points (state
transitions, runlevel transitions, condition flips), and bridges the
event loop to the libink server.

The `initctl` client uses the same library — `link_client_open`,
`link_client_call_v`, `link_client_reply`, `link_reader_*` — so the
single wire-format implementation serves both ends.  libink is an
internal implementation detail, linked statically into both binaries
and not installed; external clients should use any standard D-Bus
library, the wire protocol is the compatibility surface.

[D-Bus]: https://dbus.freedesktop.org/doc/dbus-specification.html
