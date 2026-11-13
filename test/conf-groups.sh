#!/bin/sh
# Verify extra-groups sets every listed group on the service, and that
# dropping the setting drops the groups.
set -eu

TEST_DIR=$(dirname "$0")

# Optional argument is the extra-groups list
write_conf()
{
    run "echo 'service grp {'                     >  $FINIT_CONF"
    run "echo '    group   = \"root\"'            >> $FINIT_CONF"
    if [ -n "${1:-}" ]; then
	run "echo '    extra-groups = { $1 }'     >> $FINIT_CONF"
    fi
    run "echo '    command = \"serv -np -i grp\"' >> $FINIT_CONF"
    run "echo '}'                                 >> $FINIT_CONF"
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

say 'Seven extra groups'
write_conf '"daemon", "bin", "sys", "adm", "tty", "disk", "dialout"'
run "initctl reload"

retry 'assert_num_children 1 serv'
retry 'assert_groups "0 1 2 3 4 5 6 20"'

# The running process keeps its groups, the next start drops them
say 'Dropping extra-groups drops the groups'
write_conf
run "initctl reload"
run "initctl restart grp"

retry 'assert_groups "0"'
