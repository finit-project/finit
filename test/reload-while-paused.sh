#!/bin/sh
# A reload must not be lost on a service paused by a condition
#
# svc_s writes its PID file one second after a SIGHUP, so a service
# with <pid/svc_s> is paused for that second whenever svc_s reloads.
# svc_x counts the SIGHUPs it gets.  Both .conf files are touched and
# two reloads are requested back to back, so the second one arrives
# while svc_x is paused with its own reload still pending.  svc_x must
# get exactly one SIGHUP and keep its PID.

set -eu

TEST_DIR=$(dirname "$0")

test_teardown()
{
    say "Running test teardown."
    run "rm -f $FINIT_RCSD/svc_s.conf $FINIT_RCSD/svc_x.conf /tmp/hup.sh /tmp/hup.log"
}

pidof()
{
    texec initctl -j status "$1" | jq .pid
}

test_setup()
{
    run "cat > /tmp/hup.sh" <<EOF
#!/bin/sh
trap 'echo HUP >> /tmp/hup.log' HUP
trap 'exit 0' TERM
while true; do
    sleep 1
done
EOF
    run "cat > $FINIT_RCSD/svc_s.conf" <<EOF
service log:stdout notify:pid pid:!/run/service.pid name:svc_s service.sh -- Slow to reassert
EOF
    run "cat > $FINIT_RCSD/svc_x.conf" <<EOF
service log:stdout <pid/svc_s> name:svc_x /bin/sh /tmp/hup.sh -- Paused while svc_s reloads
EOF
}

# shellcheck source=/dev/null
. "$TEST_DIR/lib/setup.sh"

sep "Configuration"
run "cat $FINIT_RCSD/svc_s.conf"
run "cat $FINIT_RCSD/svc_x.conf"

say "Reload Finit to start both services"
run "initctl reload"
retry 'assert_status "svc_x" "running"' 10 1

pid_x=$(pidof svc_x)
say "svc_x PID before: $pid_x"

sep "Touch both, reload twice"
run "rm -f /tmp/hup.log"
run "initctl touch svc_s.conf"
run "initctl touch svc_x.conf"
run "initctl reload"
run "initctl reload"

say "Wait for services to settle"
retry 'assert_status "svc_x" "running"' 15 1
run "initctl status"

# shellcheck disable=SC2016
retry 'assert "svc_x got its SIGHUP" "$(texec sh -c "cat /tmp/hup.log 2>/dev/null | wc -l")" -eq 1' 10 1

new_pid_x=$(pidof svc_x)
# shellcheck disable=SC2086
assert "svc_x was not restarted" $new_pid_x -eq $pid_x

return 0
