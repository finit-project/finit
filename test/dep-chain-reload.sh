#!/bin/sh
# Verify transitive dependency chain during reload and crash
#
# Four services in a chain: A → B → C → D, all using notify:pid.
# B and C are placed in separate sub-config files so we can use
# 'initctl touch' on them independently.  B supports SIGHUP (reload),
# while C and D use '!' (noreload) and '~' (propagate reload),
# matching a common pattern in real-world setups (e.g., FRR routing
# daemons on Infix OS).
#
# Chain: A ← B <pid/A> ← C <!~pid/B> ← D <!~pid/C>
#
# Test 1 - touch C + reload (the "Infix" scenario):
#   C is in the middle of the chain.  After 'initctl touch svc_c.conf'
#   + 'initctl reload':
#     - A and B should be unaffected (same PID)
#     - C is stopped/started (config was touched, noreload)
#     - D must be restarted (reload propagated from C)
#
# Test 2 - crash (kill -9):
#   When B is killed with SIGKILL the crash path (RUNNING → HALTED)
#   bypasses STOPPING.  Without cond_clear() in service_cleanup(),
#   pid/B is never invalidated and C, D are never restarted.
#
# Test 3 - touch B + reload:
#   B supports SIGHUP (no '!' prefix).  After 'initctl touch
#   svc_b.conf' + 'initctl reload':
#     - A should be unaffected (same PID)
#     - B is SIGHUP'd (same PID, config was touched)
#     - C and D must be restarted (reload propagated, '~' prefix)

set -eu

TEST_DIR=$(dirname "$0")

test_teardown()
{
    say "Running test teardown."
    run "rm -f $FINIT_RCSD/svc_b.conf $FINIT_RCSD/svc_c.conf"
}

pidof()
{
    texec initctl -j status "$1" | jq .pid
}

test_setup()
{
    run "cat >> $FINIT_CONF" <<EOF
service log:stdout notify:pid               name:svc_a serv -np -i svc_a -- Chain root
service log:stdout notify:pid <!~pid/svc_c>  name:svc_d serv -np -i svc_d -- Needs C
EOF
    run "cat >> $FINIT_RCSD/svc_b.conf" <<EOF
service log:stdout notify:pid <pid/svc_a>    name:svc_b serv -np -i svc_b -- Needs A
EOF
    run "cat >> $FINIT_RCSD/svc_c.conf" <<EOF
service log:stdout notify:pid <!~pid/svc_b>  name:svc_c serv -np -i svc_c -- Needs B
EOF
}

# shellcheck source=/dev/null
. "$TEST_DIR/lib/setup.sh"

sep "Configuration"
run "cat $FINIT_CONF"
run "cat $FINIT_RCSD/svc_b.conf"
run "cat $FINIT_RCSD/svc_c.conf"

say "Reload Finit to start all services"
run "initctl reload"

say "Wait for full chain to start"
retry 'assert_status "svc_d" "running"' 10 1

run "initctl status"
run "initctl cond dump"

# ――――――――――――――――――――――――――――――――――――――――――――――――――――――
# Test 1: touch C (middle of chain, noreload) + reload
# ――――――――――――――――――――――――――――――――――――――――――――――――――――――
sep "Test 1: Touch C (middle) and global reload"

pid_a=$(pidof svc_a)
pid_b=$(pidof svc_b)
pid_c=$(pidof svc_c)
pid_d=$(pidof svc_d)
say "PIDs before: A=$pid_a B=$pid_b C=$pid_c D=$pid_d"

run "initctl touch svc_c.conf"
run "initctl reload"

say "Wait for chain to settle"
retry 'assert_status "svc_d" "running"' 15 1

run "initctl status"
run "initctl cond dump"

new_pid_a=$(pidof svc_a)
new_pid_b=$(pidof svc_b)
new_pid_c=$(pidof svc_c)
new_pid_d=$(pidof svc_d)
say "PIDs after:  A=$new_pid_a B=$new_pid_b C=$new_pid_c D=$new_pid_d"

# shellcheck disable=SC2086
assert "A was not restarted"              $new_pid_a -eq $pid_a
# shellcheck disable=SC2086
assert "B was not restarted"              $new_pid_b -eq $pid_b
# shellcheck disable=SC2086
assert "C was restarted (touched)"        $new_pid_c -ne $pid_c
# shellcheck disable=SC2086
assert "D was restarted (transitive dep)" $new_pid_d -ne $pid_d

# ――――――――――――――――――――――――――――――――――――――――――――――――――――――
# Test 2: crash (kill -9), bypasses STOPPING
# ――――――――――――――――――――――――――――――――――――――――――――――――――――――
sep "Test 2: Kill B with SIGKILL (bypasses STOPPING)"

pid_b=$(pidof svc_b)
pid_c=$(pidof svc_c)
pid_d=$(pidof svc_d)
say "PIDs before: B=$pid_b C=$pid_c D=$pid_d"

run "kill -9 $pid_b"

say "Wait for B to respawn and chain to settle"
retry 'assert_status "svc_d" "running"' 15 1

run "initctl status"
run "initctl cond dump"

new_pid_b=$(pidof svc_b)
new_pid_c=$(pidof svc_c)
new_pid_d=$(pidof svc_d)
say "PIDs after:  B=$new_pid_b C=$new_pid_c D=$new_pid_d"

# shellcheck disable=SC2086
assert "B was restarted (crashed+respawn)" $new_pid_b -ne $pid_b
# shellcheck disable=SC2086
assert "C was restarted (transitive dep)"  $new_pid_c -ne $pid_c
# shellcheck disable=SC2086
assert "D was restarted (transitive dep)"  $new_pid_d -ne $pid_d

# ――――――――――――――――――――――――――――――――――――――――――――――――――――――
# Test 3: touch B (supports SIGHUP) + reload
# ――――――――――――――――――――――――――――――――――――――――――――――――――――――
sep "Test 3: Touch B (SIGHUP) and global reload"

pid_a=$(pidof svc_a)
pid_b=$(pidof svc_b)
pid_c=$(pidof svc_c)
pid_d=$(pidof svc_d)
say "PIDs before: A=$pid_a B=$pid_b C=$pid_c D=$pid_d"

run "initctl debug"
run "initctl touch svc_b.conf"
run "initctl reload"
sleep 2
run "initctl status"

say "Wait for chain to settle"
retry 'assert_status "svc_d" "running"' 15 1

run "initctl status"
run "initctl cond dump"

new_pid_a=$(pidof svc_a)
new_pid_b=$(pidof svc_b)
new_pid_c=$(pidof svc_c)
new_pid_d=$(pidof svc_d)
say "PIDs after:  A=$new_pid_a B=$new_pid_b C=$new_pid_c D=$new_pid_d"

# shellcheck disable=SC2086
assert "A was not restarted"              $new_pid_a -eq $pid_a
# shellcheck disable=SC2086
assert "B was not restarted (SIGHUP)"     $new_pid_b -eq $pid_b
# shellcheck disable=SC2086
assert "C was restarted (transitive dep)" $new_pid_c -ne $pid_c
# shellcheck disable=SC2086
assert "D was restarted (transitive dep)" $new_pid_d -ne $pid_d

return 0
