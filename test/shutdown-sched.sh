#!/bin/sh
# Verify scheduled shutdown, see issue #149: shutdown TIME [MESSAGE]
# blocks new logins from five minutes before, and shutdown -c cancels
# it.  The countdown never runs out here, it is always cancelled.
set -eu

TEST_DIR=$(dirname "$0")

NOLOGIN=/etc/nologin

# Assert that the command, run in the test namespace, fails
fails()
{
    assert "$1 fails" "$(texec sh -c "$1 >/dev/null 2>&1 || echo fail")" = fail
}

test_teardown()
{
    say "Running test teardown."
    run "shutdown -c 2>/dev/null || true"
    run "rm -f $NOLOGIN"
}

# shellcheck source=/dev/null
. "$TEST_DIR/lib/setup.sh"

sep
say 'Schedule a reboot in two minutes, within the nologin window'
run "shutdown -r +2 Testing scheduled reboot"
retry "assert_file_contains $NOLOGIN 'Testing scheduled reboot'"

say 'Cancel it, nologin is removed and the system stays up'
run "shutdown -c"
retry "texec sh -c '! test -e $NOLOGIN'"
assert "Still in runlevel 2" "$(texec initctl runlevel | awk '{print $2}')" = 2

sep
say 'Nothing to cancel'
fails "shutdown -c"

say 'An invalid time is refused'
fails "shutdown -r 25:00"
fails "shutdown -r +999999999"

sep
say 'A later shutdown replaces it, and its nologin'
run "shutdown -r +2 First"
retry "assert_file_contains $NOLOGIN First"
run "shutdown -r +120 Second"
retry "texec sh -c '! test -e $NOLOGIN'"
run "shutdown -c"

sep
say 'A nologin file of the admin is left alone'
run "echo 'Down for maintenance' > $NOLOGIN"
run "shutdown -h +2"
sleep 1		# first tick, where nologin would be written
run "shutdown -c"
assert_file_contains $NOLOGIN 'Down for maintenance'
