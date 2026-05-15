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

# A ConditionChanged signal can only originate from Cond1.Set going
# through finit (the legacy filesystem path doesn't emit signals).
# So if the monitor sees one, we know initctl cond set was routed
# via D-Bus.
say "initctl cond set drives Cond1.Set via D-Bus"
rm -f /tmp/dbus-initctl-cond.out
( texec "$CLIENT" monitor-signal "$BUS" \
    "type='signal',interface='org.finit.Cond1',member='ConditionChanged'" \
    5000 > /tmp/dbus-initctl-cond.out 2>&1 ) &
ic_cond_pid=$!
sleep 0.5
texec initctl cond set "via-initctl" >/dev/null \
    || fail "initctl cond set returned non-zero"
set +e
wait "$ic_cond_pid"
ic_cond_rc=$?
set -e
assert "ConditionChanged fired from initctl cond set (rc=$ic_cond_rc)" \
    "$ic_cond_rc" -eq 0
case "$(cat /tmp/dbus-initctl-cond.out)" in
    *"SIGNAL org.finit.Cond1 ConditionChanged"*"usr/via-initctl"*on*)
        assert "initctl cond set routed through D-Bus" 0 -eq 0 ;;
    *)
        fail "initctl cond set didn't produce expected signal: $(cat /tmp/dbus-initctl-cond.out)" ;;
esac
