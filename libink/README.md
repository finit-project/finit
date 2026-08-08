libink — brokerless D-Bus for Finit
===================================

libink is a small C library implementing the [D-Bus wire protocol][spec],
both the server and the client side, without a broker and without any
dependency on `libdbus`, `sd-bus`, or GIO.  It was born inside Finit to
let PID 1 be a bus of its own: clients connect straight to the listening
socket, authenticate with the standard SASL EXTERNAL handshake, and get
kernel-authenticated credentials via `SO_PEERCRED`.

For what the bus exposes and how to talk to it, see the User Guide,
[D-Bus Integration](../doc/dbus.md).  This file covers the library
itself.

Status
------

libink is an internal implementation detail of Finit: built as a libtool
convenience library, linked statically into `finit` and `initctl`,
nothing installed.  There is deliberately no ABI promise yet — that
comes if/when libink is extracted into a project of its own.  External
D-Bus clients need none of this; the wire protocol is the compatibility
surface, any standard D-Bus library works.

Layout
------

| File            | Contents                                              |
|-----------------|-------------------------------------------------------|
| `server.c`      | Listening socket, accept, peer credential capture     |
| `auth.c`        | SASL EXTERNAL handshake, uid verification             |
| `connection.c`  | Per-peer state machine, message framing               |
| `proto.c`       | Wire header parse/build                               |
| `marshal.c`     | Body (de)marshalling: basic types, arrays, variants   |
| `dispatch.c`    | Object tree, vtable registration, method dispatch     |
| `builtin.c`     | `org.freedesktop.DBus.*` stock interfaces             |
| `match.c`       | AddMatch/RemoveMatch rule parsing and signal filter   |
| `path.c`        | systemd-style `_HH` object path encoding              |
| `client.c`      | Outgoing connections, method calls, reply/signal wait |
| `io.c`          | Shared EINTR-resilient read/write loops               |

Public API symbols carry the `link_*` prefix (`link.h`), internal ones
`__*` (`internal.h`).  Method handlers are registered as vtables of
`link_method_t`/`link_property_t`; the framework emits variant
signatures from the property table so the declared type is the single
source of truth.

The boundary to Finit is deliberate: nothing under `libink/` includes a
Finit header.  All glue lives in `src/dbus.c` — object registration,
signal emission from the service/condition/runlevel hook points, and
the uev event loop bridge.  `initctl` uses the client half of the same
library, so one wire-format implementation serves both ends.  If libink
is ever spun out, that file is the cut line.

Testing
-------

The `test/dbus-*.sh` suite exercises the library end to end against a
live Finit in a namespace, driven by `test/src/dbus-auth-client.c`.
Wire-format conformance against third-party tools (`dbus-send`,
`dbus-monitor`) and fuzzing of the parsers are tracked as pre-merge
work — this is PID 1's attack surface.

[spec]: https://dbus.freedesktop.org/doc/dbus-specification.html
