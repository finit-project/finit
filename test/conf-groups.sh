#!/bin/sh
# Verify group and supplementary groups, @user:group,sup1,sup2,..., are
# set on the service, and that dropping either drops the group(s) too.
set -eu

TEST_DIR=$(dirname "$0")

# Optional arguments are the group and the supplementary group list,
# ",sup1,sup2,...", the latter requires a group
write_conf()
{
    user="@root"
    if [ -n "${1:-}" ]; then
	user="@root:$1${2:-}"
    fi
    run "echo 'service $user name:grp serv -np -i grp -- Groups' > $FINIT_CONF"
}

# Kernel sorts the list, so it compares as a plain string.
assert_groups()
{
    pid=$(texec initctl -j status grp | jq .pid)
    assert "Service groups == $1" \
	   "$(texec cat "/proc/$pid/status" | sed -n 's/^Groups:[[:space:]]*//p' | xargs)" = "$1"
}

assert_gid()
{
    pid=$(texec initctl -j status grp | jq .pid)
    assert "Service gid == $1" \
	   "$(texec cat "/proc/$pid/status" | awk '/^Gid:/ {print $2}')" = "$1"
}

test_teardown()
{
    say "Running test teardown."
    run "rm -f $FINIT_CONF"
}

# shellcheck source=/dev/null
. "$TEST_DIR/lib/setup.sh"

say 'Seven supplementary groups'
write_conf root ',daemon,bin,sys,adm,tty,disk,dialout'
run "initctl reload"

retry 'assert_num_children 1 serv'
retry 'assert_groups "0 1 2 3 4 5 6 20"'

# The running process keeps its groups, the next start drops them
say 'Dropping supplementary groups drops the groups'
write_conf root
run "initctl reload"
run "initctl restart grp"

retry 'assert_groups "0"'

say 'Dropping group drops the group'
write_conf adm
run "initctl reload"
run "initctl restart grp"
retry 'assert_gid 4'

write_conf
run "initctl reload"
run "initctl restart grp"
retry 'assert_gid 0'
