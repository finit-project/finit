#!/bin/sh
# Verify supplementary groups, @user:group,sup1,sup2,..., are all set on
# the service, and that dropping them drops the groups.
set -eu

TEST_DIR=$(dirname "$0")

# Optional argument is the supplementary group list, ",sup1,sup2,..."
write_conf()
{
    run "echo 'service @root:root${1:-} name:grp serv -np -i grp -- Groups' > $FINIT_CONF"
}

# Kernel sorts the list, so it compares as a plain string.
assert_groups()
{
    pid=$(texec initctl -j status grp | jq .pid)
    assert "Service groups == $1" \
	   "$(texec cat "/proc/$pid/status" | sed -n 's/^Groups:[[:space:]]*//p' | xargs)" = "$1"
}

test_teardown()
{
    say "Running test teardown."
    run "rm -f $FINIT_CONF"
}

# shellcheck source=/dev/null
. "$TEST_DIR/lib/setup.sh"

say 'Seven supplementary groups'
write_conf ',daemon,bin,sys,adm,tty,disk,dialout'
run "initctl reload"

retry 'assert_num_children 1 serv'
retry 'assert_groups "0 1 2 3 4 5 6 20"'

# The running process keeps its groups, the next start drops them
say 'Dropping supplementary groups drops the groups'
write_conf
run "initctl reload"
run "initctl restart grp"

retry 'assert_groups "0"'
