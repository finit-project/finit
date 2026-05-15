#!/bin/sh
# libink: org.finit.Manager1 vtable.
#
# Covers the Manager1 method surface: ListServices, Reload, Stop with
# bogus service, plus per-method authorization (Restart from non-root
# is rejected, ListServices remains reachable as non-root).

set -eu

TEST_DIR=$(dirname "$0")

# shellcheck source=/dev/null
. "$TEST_DIR/lib/setup.sh"
# shellcheck source=/dev/null
. "$TEST_DIR/lib/dbus-setup.sh"

say "Manager1.ListServices returns the running services"
list=$(texec "$CLIENT" liststrings "$BUS" /org/finit/manager \
       org.finit.Manager1 ListServices)
assert "ListServices returned at least one service" \
    "$(printf '%s' "$list" | wc -l | tr -d ' ')" -ge 1
echo "$list"

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

# Send call-s-as-uid an "s" body where the server expects "" -- the
# server must reply with org.freedesktop.DBus.Error.InvalidArgs.
# Asserting that *positive* marker (not just "no AccessDenied")
# ensures we don't silently pass if setuid() failed or the client
# never reached the server (a transport error would print neither
# AccessDenied nor InvalidArgs).
say "Manager1.ListServices is reachable as non-root (not blocked by authz)"
set +e
result=$(texec "$CLIENT" call-s-as-uid 1 "$BUS" /org/finit/manager \
         org.finit.Manager1 ListServices "" 2>&1)
set -e
case "$result" in
    *AccessDenied*) fail "Non-root ListServices rejected by authz: $result" ;;
    *InvalidArgs*)  assert "Non-root reached signature check (InvalidArgs, not AccessDenied)" 0 -eq 0 ;;
    *)              fail "Unexpected reply from non-root ListServices: $result" ;;
esac
