#!/bin/sh
# libink: D-Bus AUTH EXTERNAL handshake.
#
# Verifies the SASL handshake itself in isolation -- everything else
# the bus does (built-in DBus interface, vtables, signals, initctl
# routing) lives in the other dbus-*.sh tests.

set -eu

TEST_DIR=$(dirname "$0")

# shellcheck source=/dev/null
. "$TEST_DIR/lib/setup.sh"
# shellcheck source=/dev/null
. "$TEST_DIR/lib/dbus-setup.sh"

# The bus reaches every service operation initctl does, so it has to
# be gated like INIT_SOCKET: 0660, owned by root and the --with-group
# group.  Only the mode is asserted here, the test namespace does not
# enforce it -- a setuid() client still connects to a 0660 socket.
say "Socket is gated like INIT_SOCKET, not world-accessible"
mode=$(texec stat -c %a "$BUS")
sock=$(texec stat -c %a /run/finit/socket)
assert "Socket mode is 660 (got $mode)" "$mode" = "660"
assert "Bus and INIT_SOCKET agree ($mode vs $sock)" "$mode" = "$sock"

say "AUTH EXTERNAL: claim correct UID (root = 0)"
reply=$(texec "$CLIENT" auth "$BUS" 0)
assert "Reply starts with OK (got: $reply)" "${reply%% *}" = "OK"

guid=${reply#OK }
assert "GUID is 32 hex chars (got: $guid)" \
    "$(printf '%s' "$guid" | tr -d '0-9a-f' | wc -c)" -eq 0
assert "GUID length is 32 (got: ${#guid})" "${#guid}" -eq 32

say "AUTH EXTERNAL: wrong UID is rejected"
set +e
wrong_reply=$(texec "$CLIENT" auth "$BUS" 1)
wrong_rc=$?
set -e
assert "Wrong UID rejected (rc=$wrong_rc, reply: $wrong_reply)" \
    "$wrong_rc" -eq 1

say "Two sequential AUTH connections get different GUIDs"
r1=$(texec "$CLIENT" auth "$BUS" 0)
r2=$(texec "$CLIENT" auth "$BUS" 0)
g1=${r1#OK }
g2=${r2#OK }
assert "Per-connection GUIDs differ ($g1 vs $g2)" "$g1" != "$g2"
