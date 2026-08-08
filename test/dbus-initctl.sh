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

# ---------- arc B: signal + reload <svc> routing ----------

# initctl signal exits 0 iff the bus call succeeded.  We send SIGCONT
# (no observable side-effect on a healthy daemon) so the test stays
# benign regardless of how keventd handles it.
say "initctl signal routes through Manager1.Signal"
texec initctl signal keventd CONT >/dev/null \
    || fail "initctl signal returned non-zero"
assert "initctl signal ok" 0 -eq 0

say "initctl signal on a bogus identity reports NoSuchService"
set +e
texec initctl signal no-such-svc-anywhere CONT >/tmp/dbus-sig-bad.out 2>&1
sigbad_rc=$?
set -e
assert "Bogus signal target rejected (rc=$sigbad_rc)" "$sigbad_rc" -ne 0
case "$(cat /tmp/dbus-sig-bad.out)" in
    *"no such task or service"*)
        assert "Error message mentions missing service" 0 -eq 0 ;;
    *)
        fail "Unexpected initctl signal output: $(cat /tmp/dbus-sig-bad.out)" ;;
esac

say "initctl reload <svc> routes through Service1.Reload"
texec initctl reload keventd >/dev/null \
    || fail "initctl reload keventd returned non-zero"
assert "Per-service reload ok" 0 -eq 0

say "initctl status views render over D-Bus alone"
# hide the legacy socket: everything below must come over the bus
texec mv /run/finit/socket /run/finit/socket.hidden

set +e
out=$(texec initctl -p status)
status_rc=$?
one=$(texec initctl -p status keventd)
one_rc=$?
texec initctl -q status keventd
quiet_rc=$?
jout=$(texec initctl -j status)
json_rc=$?
idout=$(texec initctl ident)
ident_rc=$?
set -e

texec mv /run/finit/socket.hidden /run/finit/socket

assert "status table ok without legacy socket (rc=$status_rc)" \
    "$status_rc" -eq 0
case "$out" in
    *keventd*running*) assert "keventd running in table" 0 -eq 0 ;;
    *) fail "keventd/running missing from status table" ;;
esac

assert "status detail view ok (rc=$one_rc)" "$one_rc" -eq 0
case "$one" in
    *"Status : running"*"Identity : keventd"*"Restarts :"*)
        assert "detail view fields present" 0 -eq 0 ;;
    *) fail "detail view incomplete: $one" ;;
esac

assert "quiet mode exit code (rc=$quiet_rc)" "$quiet_rc" -eq 0

assert "json mode ok (rc=$json_rc)" "$json_rc" -eq 0
case "$jout" in
    *'"identity": "keventd"'*'"status": "running"'*)
        assert "json fields present" 0 -eq 0 ;;
    *) fail "json output incomplete: $jout" ;;
esac

assert "ident ok (rc=$ident_rc)" "$ident_rc" -eq 0
case "$idout" in
    *keventd*) assert "ident lists keventd" 0 -eq 0 ;;
    *) fail "ident missing keventd" ;;
esac
