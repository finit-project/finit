#!/bin/sh
# Verify that a command which starts like a service option, e.g. pidof
# vs. pid, is still taken as the command.
set -eu

TEST_DIR=$(dirname "$0")

test_teardown()
{
    say "Running test teardown."
    run "rm -f $FINIT_CONF"
}

# shellcheck source=/dev/null
. "$TEST_DIR/lib/setup.sh"

say 'A command named like an option is the command'
run "echo 'task [2345] name:lookalike pidof serv -- Lookalike' > $FINIT_CONF"
run "initctl reload"

retry "test \"\$(texec initctl -p status lookalike | sed -n 's/.*Command : //p')\" = 'pidof serv'"
