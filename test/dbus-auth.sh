#!/bin/sh
# Smoke test for libink AUTH EXTERNAL handshake over /run/finit/bus.
#
# Verifies that with --enable-dbus (the default), Finit opens its
# brokerless D-Bus socket and that the SASL-style AUTH EXTERNAL
# handshake completes for a peer claiming the right UID and is
# rejected for one claiming a wrong UID.

set -eu

TEST_DIR=$(dirname "$0")

# shellcheck source=/dev/null
. "$TEST_DIR/lib/setup.sh"

CLIENT=/sbin/dbus-auth-client
BUS=/run/finit/bus

if ! texec test -x "$CLIENT"; then
    skip "dbus-auth-client not built (configured with --disable-dbus?)"
fi

say "Wait for $BUS to appear"
retry "texec test -S $BUS"

say "Verify socket permissions are 0666"
mode=$(texec stat -c %a "$BUS")
assert "Socket mode is 666 (got $mode)" "$mode" = "666"

say "Happy path — claim correct UID (root inside namespace = 0)"
reply=$(texec "$CLIENT" "$BUS" 0)
assert "Reply starts with OK (got: $reply)" "${reply%% *}" = "OK"

# GUID must be 32 hex chars; a server blindly emitting "OK foo" would
# otherwise pass the prefix check above.
guid=${reply#OK }
assert "GUID is 32 hex chars (got: $guid)" \
    "$(printf '%s' "$guid" | tr -d '0-9a-f' | wc -c)" -eq 0
assert "GUID length is 32 (got: ${#guid})" "${#guid}" -eq 32

say "Wrong UID is rejected"
# Claim uid 1, which does not match peer's real uid 0.  Exit code 1
# means "REJECTED" (the expected denial); 0 would be acceptance,
# 2 a transport error.  Distinguish all three for a useful failure
# message.
set +e
wrong_reply=$(texec "$CLIENT" "$BUS" 1)
wrong_rc=$?
set -e
assert "Wrong UID rejected (rc=$wrong_rc, reply: $wrong_reply)" \
    "$wrong_rc" -eq 1

say "Two sequential connections both authenticate independently"
reply1=$(texec "$CLIENT" "$BUS" 0)
reply2=$(texec "$CLIENT" "$BUS" 0)
assert "First connection OK"  "${reply1%% *}" = "OK"
assert "Second connection OK" "${reply2%% *}" = "OK"

# The two GUIDs in the OK lines should differ; libink generates one
# per connection.  This catches a regression where we accidentally
# share GUID state across peers.
guid1=${reply1#OK }
guid2=${reply2#OK }
assert "Per-connection GUIDs differ ($guid1 vs $guid2)" \
    "$guid1" != "$guid2"
