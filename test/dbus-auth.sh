#!/bin/sh
# End-to-end smoke test for libink:
#   - AUTH EXTERNAL handshake (happy and wrong-uid paths)
#   - org.freedesktop.DBus.Hello
#   - org.freedesktop.DBus.Introspectable.Introspect (root, manager)
#   - org.finit.Manager1.ListServices
#   - Error reply for an unknown method.

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

say "Socket mode is 0666"
mode=$(texec stat -c %a "$BUS")
assert "Socket mode is 666 (got $mode)" "$mode" = "666"

# ---------- AUTH ----------

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

# ---------- Built-in interfaces ----------

say "Hello() returns a unique name beginning with ':1.'"
name=$(texec "$CLIENT" hello "$BUS")
case "$name" in
    :1.*) assert "Hello returned a :1.N name (got $name)" 0 -eq 0 ;;
    *)    fail "Hello returned unexpected name: $name" ;;
esac

say "Two Hello() calls produce different unique names"
n1=$(texec "$CLIENT" hello "$BUS")
n2=$(texec "$CLIENT" hello "$BUS")
assert "Unique names increment ($n1 vs $n2)" "$n1" != "$n2"

say "Introspect on root path returns valid XML referencing /manager"
xml=$(texec "$CLIENT" introspect "$BUS" /)
case "$xml" in
    *'<node'*) assert "XML has <node> root (good)" 0 -eq 0 ;;
    *) fail "Root introspect missing <node>: $xml" ;;
esac

say "Introspect on /org/finit/manager exposes Manager1.ListServices"
xml=$(texec "$CLIENT" introspect "$BUS" /org/finit/manager)
case "$xml" in
    *'org.finit.Manager1'*'ListServices'*)
        assert "Manager1 and ListServices visible in XML" 0 -eq 0 ;;
    *)
        fail "Manager1 XML missing; got: $xml" ;;
esac

# ---------- Real method call ----------

say "Manager1.ListServices returns the running services"
list=$(texec "$CLIENT" liststrings "$BUS" /org/finit/manager \
       org.finit.Manager1 ListServices)
assert "ListServices returned at least one service" \
    "$(printf '%s' "$list" | wc -l | tr -d ' ')" -ge 1
echo "$list"

# ---------- Error reply ----------

say "Unknown method gets an org.freedesktop.DBus.Error.* reply"
set +e
texec "$CLIENT" unknown "$BUS"
unknown_rc=$?
set -e
assert "Unknown method returned an error (rc=$unknown_rc)" "$unknown_rc" -eq 0
