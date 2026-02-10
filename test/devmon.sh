#!/bin/sh
#
# Verify device monitor (built-in plugin)
#

set -eu

TEST_DIR=$(dirname "$0")

test_teardown()
{
    say "Running test teardown."

    run "rm -f $FINIT_CONF /tmp/post"
}

# Cannot run mknod as non-root even in a chroot
# touch is close enough for our needs
mkdev()
{
    dir=$(dirname "$1")
    run "mkdir -p $dir"
    run "touch $1"
}

rmdev()
{
    run "rm $1"
}

test_one()
{
    cond="$1"
    node="/$cond"

    say "Checking cond $cond and device $node ..."
    run "echo service log:null \<$cond\> serv -np >> $FINIT_CONF"
    run "cat $FINIT_CONF"
    run "initctl reload"

    assert_status "serv" "waiting"

    mkdev "$node"
    assert_status "serv" "running"
    assert_cond "$cond"

    run "initctl reload"
    assert_status "serv" "running"
    assert_cond "$cond"

    rmdev "$node"
    assert_status "serv" "waiting"

    say "Cleaning up ..."
    run "rm $FINIT_CONF"
    run "initctl reload"
}

# shellcheck source=/dev/null
. "$TEST_DIR/lib/setup.sh"

sep
test_one "dev/fbsplash"
sep
test_one "dev/subdir/42"
sep
