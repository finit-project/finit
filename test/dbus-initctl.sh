#!/bin/sh
# initctl: confirms the legacy CLI now routes through D-Bus.
#
# Subscribes to ServiceStateChanged on a background monitor and then
# runs initctl -- if D-Bus is in use, the signal fires.  If the legacy
# socket were still in use, the dbus subscriber would see nothing.

set -eu

TEST_DIR=$(dirname "$0")

# shellcheck source=/dev/null
. "$TEST_DIR/lib/setup.sh"
# shellcheck source=/dev/null
. "$TEST_DIR/lib/dbus-setup.sh"

say "initctl restart drives D-Bus (signal observed via dbus-auth-client)"
rm -f /tmp/dbus-initctl-sig.out
( texec "$CLIENT" monitor-signal "$BUS" \
    "type='signal',interface='org.finit.Manager1',member='ServiceStateChanged'" \
    5000 > /tmp/dbus-initctl-sig.out 2>&1 ) &
ic_pid=$!
sleep 0.5
texec initctl restart keventd >/dev/null \
    || fail "initctl restart returned non-zero"
set +e
wait "$ic_pid"
ic_rc=$?
set -e
assert "ServiceStateChanged fired from initctl restart (rc=$ic_rc)" \
    "$ic_rc" -eq 0
case "$(cat /tmp/dbus-initctl-sig.out)" in
    *"SIGNAL org.finit.Manager1 ServiceStateChanged"*keventd*)
        assert "initctl restart routed through D-Bus" 0 -eq 0 ;;
    *)
        fail "initctl restart didn't produce expected signal: $(cat /tmp/dbus-initctl-sig.out)" ;;
esac

say "initctl reload (no args) routes through Manager1.Reload"
texec initctl reload >/dev/null \
    || fail "initctl reload returned non-zero"
assert "initctl reload ok" 0 -eq 0
