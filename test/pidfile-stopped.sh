#!/bin/sh
# Verify that a PID file written by someone else does not make a stopped
# or waiting service look started, see issue #452.  E.g., a container
# started by hand with podman, outside of Finit.
set -eu

TEST_DIR=$(dirname "$0")

PIDFN=/run/ext.pid

# Stand-in for the process started outside of Finit
external()
{
    say "Starting a process outside of Finit, it writes $PIDFN"
    run "sh -c 'sleep 100 & echo \$! > $PIDFN'"

    # Negative check, give the pidfile plugin time to (not) react
    sleep 2
}

cleanup()
{
    run "kill \$(cat $PIDFN 2>/dev/null) 2>/dev/null || true"
    run "rm -f $PIDFN /bin/late.sh /tmp/late"
}

test_teardown()
{
    say "Running test teardown."
    cleanup
    run "rm -f $FINIT_CONF"
}

# shellcheck source=/dev/null
. "$TEST_DIR/lib/setup.sh"

sep
say 'A stopped forking service stays stopped'
run "echo 'service name:ext pid:!$PIDFN serv -p -P $PIDFN -- External' > $FINIT_CONF"
run "initctl reload"
retry 'assert_status ext running'

run "initctl stop ext"
retry 'assert_status ext stopped'
run "rm -f $PIDFN"

external
assert_status ext stopped
assert_nocond pid/ext
cleanup

sep
say 'A service waiting for its condition stays waiting'
run "echo 'service name:ext pid:!$PIDFN <usr/never> serv -p -P $PIDFN -- External' > $FINIT_CONF"
run "initctl reload"
retry 'assert_status ext waiting'

external
assert_status ext waiting
assert_nocond pid/ext
cleanup

# A forking daemon whose launcher exits before the daemon has written
# its PID file.  A stop in that window must hold, and the daemon that
# shows up late must be stopped, not adopted as running.
sep
say 'A forking service stopped before its PID file appears stays stopped'
# Unquoted END, $PIDFN expands here.  /tmp/late marks the daemon start
cat > "$SYSROOT/bin/late.sh" <<END
#!/bin/sh
( sleep 1; touch /tmp/late; exec serv -n -p -P $PIDFN ) &
END
chmod +x "$SYSROOT/bin/late.sh"
run "echo 'service name:ext pid:!$PIDFN late.sh -- Late' > $FINIT_CONF"
run "initctl reload"
run "initctl stop ext"

retry 'texec test -e /tmp/late'

# Negative check, give the pidfile plugin time to (not) react
sleep 1
assert_status ext stopped
assert_nocond pid/ext
assert_num_children 0 serv
