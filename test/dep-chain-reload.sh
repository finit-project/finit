#!/bin/sh
# Verify transitive dependency chain during reload and crash
#
# Four services in a chain: A → B → C → D, where B depends on
# pid/A and C depends on pid/B and D depends on pid/C.  B is
# placed in a sub-config file so we can use 'initctl touch' on
# it.  B uses <!pid/svc_a> (with leading '!') so it does not
# support SIGHUP, causing a full stop/start cycle on 'initctl
# touch svc_b.conf' + reload.
#
# Test 1 - touch + reload:
#   After 'initctl touch svc_b.conf' + 'initctl reload':
#     - A should be unaffected (same PID)
#     - B is restarted (config was touched, noreload)
#     - C goes PAUSED (pid/B in flux), then PAUSED → RUNNING
#       once B reasserts pid/B via the pidfile plugin
#     - D must also resume: C's PAUSED → RUNNING handler must
#       call cond_set() (not just cond_set_path()) so that
#       cond_update() steps D out of PAUSED
#
# Test 2 - crash (kill -9):
#   When B is killed with SIGKILL the crash path (RUNNING →
#   HALTED) bypasses STOPPING, where cond_clear() used to be
#   the only call site.  The pidfile plugin only watches for
#   IN_CLOSE_WRITE, so neither the pidfile removal (IN_DELETE)
#   nor a pidfile touch (IN_ATTRIB) triggers an inotify event.
#   Without the fix in service_cleanup(), pid/B is never
#   invalidated and C (and D) are never restarted.

set -eu

TEST_DIR=$(dirname "$0")

test_teardown()
{
    say "Running test teardown."
    run "rm -f $FINIT_RCSD/svc_b.conf"
}

pidof()
{
    texec initctl -j status "$1" | jq .pid
}

test_setup()
{
    run "cat >> $FINIT_CONF" <<EOF
service log:stdout notify:pid               name:svc_a serv -np -i svc_a -- Chain root
service log:stdout notify:pid <pid/svc_b>   name:svc_c serv -np -i svc_c -- Needs B
service log:stdout notify:pid <pid/svc_c>   name:svc_d serv -np -i svc_d -- Needs C
EOF
    run "cat >> $FINIT_RCSD/svc_b.conf" <<EOF
service log:stdout notify:pid <!pid/svc_a>  name:svc_b serv -np -i svc_b -- Needs A
EOF
}

# shellcheck source=/dev/null
. "$TEST_DIR/lib/setup.sh"

sep "Configuration"
run "cat $FINIT_CONF"
run "cat $FINIT_RCSD/svc_b.conf"

say "Reload Finit to start all services"
run "initctl reload"

say "Wait for full chain to start"
retry 'assert_status "svc_d" "running"' 10 1

run "initctl status"
run "initctl cond dump"

# ――――――――――――――――――――――――――――――――――――――――――――――――――――――
# Test 1: touch + reload
# ――――――――――――――――――――――――――――――――――――――――――――――――――――――
sep "Test 1: Touch B and global reload"

pid_a=$(pidof svc_a)
pid_b=$(pidof svc_b)
pid_c=$(pidof svc_c)
pid_d=$(pidof svc_d)
say "PIDs before: A=$pid_a B=$pid_b C=$pid_c D=$pid_d"

run "initctl touch svc_b.conf"
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
assert "B was restarted (touched)"        $new_pid_b -ne $pid_b
# shellcheck disable=SC2086
assert "C was restarted (transitive dep)" $new_pid_c -ne $pid_c
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

return 0
