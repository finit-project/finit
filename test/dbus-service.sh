#!/bin/sh
# libink: org.finit.Service1 vtable + ServiceStateChanged signal.
#
# Covers per-service objects exposed at /org/finit/service/<encoded>:
# GetService lookup, Introspect on a service object, Service1.Restart,
# authorization (non-root rejected), and the Manager1.ServiceStateChanged
# signal that Service1.Restart triggers.

set -eu

TEST_DIR=$(dirname "$0")

# shellcheck source=/dev/null
. "$TEST_DIR/lib/setup.sh"
# shellcheck source=/dev/null
. "$TEST_DIR/lib/dbus-setup.sh"

say "Manager1.GetService(keventd) returns the encoded object path"
path=$(texec "$CLIENT" get-service "$BUS" keventd)
expected="/org/finit/service/keventd"
assert "GetService returned expected path (got: $path)" "$path" = "$expected"

say "Introspect on the service object exposes Service1 methods"
xml=$(texec "$CLIENT" introspect "$BUS" /org/finit/service/keventd)
case "$xml" in
    *'org.finit.Service1'*'Restart'*)
        assert "Service1.Restart visible in service-object XML" 0 -eq 0 ;;
    *)
        fail "Service1 not visible on /org/finit/service/keventd: $xml" ;;
esac

say "Service1.Restart on /org/finit/service/keventd succeeds"
texec "$CLIENT" call-void "$BUS" /org/finit/service/keventd \
    org.finit.Service1 Restart >/dev/null \
    || fail "Service1.Restart returned non-zero"
assert "Per-service Restart ok" 0 -eq 0

say "Service1.Restart from non-root is rejected with AccessDenied"
set +e
texec "$CLIENT" call-void-as-uid 1 "$BUS" /org/finit/service/keventd \
    org.finit.Service1 Restart >/tmp/dbus-svcauthz.out 2>&1
svc_authz_rc=$?
set -e
assert "Non-root Service1.Restart rejected (rc=$svc_authz_rc)" \
    "$svc_authz_rc" -eq 1
case "$(cat /tmp/dbus-svcauthz.out)" in
    *AccessDenied*) assert "Service1 authz fires" 0 -eq 0 ;;
    *) fail "Expected AccessDenied, got: $(cat /tmp/dbus-svcauthz.out)" ;;
esac

say "Service1.Restart fires Manager1.ServiceStateChanged"
rm -f /tmp/dbus-sig.out
( texec "$CLIENT" monitor-signal "$BUS" \
    "type='signal',interface='org.finit.Manager1',member='ServiceStateChanged'" \
    5000 > /tmp/dbus-sig.out 2>&1 ) &
mon_pid=$!
sleep 0.5
texec "$CLIENT" call-void "$BUS" /org/finit/service/keventd \
    org.finit.Service1 Restart >/dev/null \
    || fail "Restart trigger returned non-zero"
set +e
wait "$mon_pid"
mon_rc=$?
set -e
assert "monitor saw a signal (rc=$mon_rc)" "$mon_rc" -eq 0
case "$(cat /tmp/dbus-sig.out)" in
    *"SIGNAL org.finit.Manager1 ServiceStateChanged"*keventd*)
        assert "Signal payload contains the keventd identity" 0 -eq 0 ;;
    *)
        fail "Unexpected signal output: $(cat /tmp/dbus-sig.out)" ;;
esac
