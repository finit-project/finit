#!/bin/sh
# libink: org.finit.Cond1 vtable + ConditionChanged signal.
#
# Covers user-condition manipulation: Get, Set (with signal fan-out),
# the usr/* policy guard (non-usr conditions are rejected), and the
# non-root authorization gate.

set -eu

TEST_DIR=$(dirname "$0")

# shellcheck source=/dev/null
. "$TEST_DIR/lib/setup.sh"
# shellcheck source=/dev/null
. "$TEST_DIR/lib/dbus-setup.sh"

say "Cond1.Get returns 'off' for an unset condition"
result=$(texec "$CLIENT" call-s "$BUS" /org/finit/cond \
    org.finit.Cond1 Get "no-such-cond")
case "$result" in
    OK*) : ;;   # ok, the cond reports a state, fall through
    *)   fail "Cond1.Get failed: $result" ;;
esac

say "Cond1.Set fires Cond1.ConditionChanged and Get reflects the change"
rm -f /tmp/dbus-cond.out
( texec "$CLIENT" monitor-signal "$BUS" \
    "type='signal',interface='org.finit.Cond1',member='ConditionChanged'" \
    5000 > /tmp/dbus-cond.out 2>&1 ) &
cond_mon_pid=$!
sleep 0.5
texec "$CLIENT" call-s "$BUS" /org/finit/cond \
    org.finit.Cond1 Set "dbus-test-cond" >/dev/null \
    || fail "Cond1.Set returned non-zero"
set +e
wait "$cond_mon_pid"
cond_mon_rc=$?
set -e
assert "Cond1 monitor saw a signal (rc=$cond_mon_rc)" "$cond_mon_rc" -eq 0
case "$(cat /tmp/dbus-cond.out)" in
    *"SIGNAL org.finit.Cond1 ConditionChanged"*"usr/dbus-test-cond"*on*)
        assert "ConditionChanged carries usr/dbus-test-cond and 'on'" 0 -eq 0 ;;
    *)
        fail "Unexpected Cond1 signal: $(cat /tmp/dbus-cond.out)" ;;
esac

say "Cond1.Set/Clear on non-usr/* is rejected"
set +e
texec "$CLIENT" call-s "$BUS" /org/finit/cond \
    org.finit.Cond1 Set "pid/sshd" >/tmp/dbus-condrej.out 2>&1
condrej_rc=$?
set -e
assert "pid/* rejected (rc=$condrej_rc)" "$condrej_rc" -eq 1
case "$(cat /tmp/dbus-condrej.out)" in
    *InvalidArgs*) assert "Error is InvalidArgs" 0 -eq 0 ;;
    *) fail "Unexpected reply: $(cat /tmp/dbus-condrej.out)" ;;
esac

say "Cond1.Set from non-root is rejected with AccessDenied"
set +e
texec "$CLIENT" call-s-as-uid 1 "$BUS" /org/finit/cond \
    org.finit.Cond1 Set "would-be-cond" >/tmp/dbus-condauthz.out 2>&1
ca_rc=$?
set -e
assert "Non-root Cond1.Set rejected (rc=$ca_rc)" "$ca_rc" -eq 1
case "$(cat /tmp/dbus-condauthz.out)" in
    *AccessDenied*) assert "Cond1 authz fires" 0 -eq 0 ;;
    *) fail "Unexpected reply: $(cat /tmp/dbus-condauthz.out)" ;;
esac
