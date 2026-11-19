#!/bin/sh
# Verify the delay between restarts of a crashing service.  It logs
# the uptime, in centiseconds, of each start and then exits.
set -eu

TEST_DIR=$(dirname "$0")

STARTS=/tmp/starts

# Wait for start $2, then check the delay since start $1, in sec
assert_delay()
{
    retry "texec sh -c 'test \$(wc -l < $STARTS) -ge $2'" 150 0.1
    # shellcheck disable=SC2016 # $1 is awk's field reference, not the shell's
    delay=$(texec awk -v a="$1" -v b="$2" 'NR == a { t = $1 } NR == b { print $1 - t }' $STARTS)
    assert "Delay between start $1 and $2 is $3-$4 sec" "$delay" -ge "$(($3 * 100))"
    assert "Delay between start $1 and $2 is $3-$4 sec" "$delay" -le "$(($4 * 100))"
}

# Replace the service, settings in $1, and let it start crashing
crash()
{
    run "rm -f $FINIT_CONF"
    run "initctl reload"
    run "rm -f $STARTS"
    run "cat > $FINIT_CONF" <<CONF
service crash {
    $1
    command = "crash.sh"
}
CONF
    run "initctl reload"
}

test_teardown()
{
    say "Running test teardown."
    run "rm -f $FINIT_CONF $STARTS /bin/crash.sh"
}

# shellcheck source=/dev/null
. "$TEST_DIR/lib/setup.sh"

cat > "$SYSROOT/bin/crash.sh" <<SCRIPT
#!/bin/sh
tr -d . < /proc/uptime | cut -d' ' -f1 >> $STARTS
exit 1
SCRIPT
chmod +x "$SYSROOT/bin/crash.sh"

sep
say 'restart always, at once the first time, then every other second'
crash 'restart = "always"'
assert_delay 1 2 0 1
assert_delay 2 3 2 3
assert_delay 3 4 2 3

sep
say 'restart-max-sec, the delay doubles from restart-sec up to the limit'
crash 'restart         = "always"
    restart-sec     = 1
    restart-max-sec = 4'
assert_delay 1 2 1 2
assert_delay 2 3 2 3
assert_delay 3 4 4 5
assert_delay 4 5 4 5

say 'The restart counter stops where the delay peaks'
assert "Restart counter is 2" "$(texec initctl status crash | awk '/Restarts/{ print $4 }')" = "(2/-1)"
