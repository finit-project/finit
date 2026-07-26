#!/bin/sh
# A timeout on a stop: or reload: script must not take PID 1 with it.
# Those two hooks passed a NULL timeout pointer to parse_script(),
# which wrote through it whenever the script was prefixed with a
# valid number.  Only a valid number reached the store, so
# 'stop:abc,/bin/true' was harmless while 'stop:5,/bin/true' was not.
set -eu

TEST_DIR=$(dirname "$0")

test_teardown()
{
    say "Running test teardown."
    run "rm -f $FINIT_CONF"
}

# shellcheck source=/dev/null
. "$TEST_DIR/lib/setup.sh"

# shellcheck disable=SC2154
assert_alive()
{
	assert "Finit survived $1" "$(kill -0 "$finit_pid" 2>/dev/null && echo yes)" = "yes"
}

for hook in stop reload post pre; do
	say "Timeout on a $hook: script"
	run "echo 'service $hook:5,/bin/true service.sh -- Timeout test' > $FINIT_CONF"
	run "initctl reload" || true
	assert_alive "$hook:5,/bin/true"
done

say 'The service still runs afterwards'
run "echo 'service stop:5,/bin/true service.sh -- Timeout test' > $FINIT_CONF"
run "initctl reload"
retry 'assert_num_children 1 service.sh'
