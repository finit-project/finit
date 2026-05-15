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

# ---------- Method with arguments ----------

say "Manager1.Reload (void) succeeds"
texec "$CLIENT" call-void "$BUS" /org/finit/manager \
    org.finit.Manager1 Reload >/dev/null \
    || fail "Reload returned non-zero"
assert "Reload void method ok" 0 -eq 0

say "Manager1.Stop with bogus identity returns NoSuchService error"
set +e
texec "$CLIENT" call-s "$BUS" /org/finit/manager \
    org.finit.Manager1 Stop "no-such-service-here" >/tmp/dbus-stop.out 2>&1
stop_rc=$?
set -e
assert "Bogus service rejected (rc=$stop_rc)" "$stop_rc" -eq 1
case "$(cat /tmp/dbus-stop.out)" in
    *NoSuchService*) assert "Error is NoSuchService" 0 -eq 0 ;;
    *) fail "Unexpected error reply: $(cat /tmp/dbus-stop.out)" ;;
esac

# ---------- Authorization ----------

say "Manager1.Restart from non-root is rejected with AccessDenied"
set +e
texec "$CLIENT" call-s-as-uid 1 "$BUS" /org/finit/manager \
    org.finit.Manager1 Restart "testserv" >/tmp/dbus-authz.out 2>&1
authz_rc=$?
set -e
assert "Non-root Restart rejected (rc=$authz_rc)" "$authz_rc" -eq 1
case "$(cat /tmp/dbus-authz.out)" in
    *AccessDenied*) assert "Error is AccessDenied" 0 -eq 0 ;;
    *) fail "Unexpected error: $(cat /tmp/dbus-authz.out)" ;;
esac

say "Manager1.ListServices is reachable as non-root (not blocked by authz)"
# call-s-as-uid sends an "s" body; ListServices expects "", so the
# server must reply with org.freedesktop.DBus.Error.InvalidArgs.
# Asserting that *positive* marker (not just "no AccessDenied")
# ensures we don't silently pass if setuid() failed or the client
# never reached the server (e.g. a transport error would print
# neither AccessDenied nor InvalidArgs).
set +e
result=$(texec "$CLIENT" call-s-as-uid 1 "$BUS" /org/finit/manager \
         org.finit.Manager1 ListServices "" 2>&1)
set -e
case "$result" in
    *AccessDenied*) fail "Non-root ListServices rejected by authz: $result" ;;
    *InvalidArgs*)  assert "Non-root reached signature check (InvalidArgs, not AccessDenied)" 0 -eq 0 ;;
    *)              fail "Unexpected reply from non-root ListServices: $result" ;;
esac

# ---------- Error reply ----------

say "Unknown method gets an org.freedesktop.DBus.Error.* reply"
set +e
texec "$CLIENT" unknown "$BUS"
unknown_rc=$?
set -e
assert "Unknown method returned an error (rc=$unknown_rc)" "$unknown_rc" -eq 0
