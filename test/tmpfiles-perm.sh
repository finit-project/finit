#!/bin/sh
# Verify that tmpfiles leaves the mode of an existing directory alone
# when the entry does not give one, issue #523
set -eu

TEST_DIR=$(dirname "$0")

DIR=/tmp/perm
CONF=/tmp/perm.conf

# Run tmpfiles with entry $1, then check mode $2 and owner $3 of $DIR
assert_perm()
{
    run "echo '$1' > $CONF"
    run "/libexec/finit/tmpfiles --create $CONF"
    assert "Entry '$1' gives $2 $3" "$(texec stat -c '%a %U:%G' $DIR)" = "$2 $3"
}

test_teardown()
{
    say "Running test teardown."
    run "rm -rf $DIR $CONF"
}

# shellcheck source=/dev/null
. "$TEST_DIR/lib/setup.sh"

sep
say 'A new directory gets the default mode and owner'
assert_perm "d $DIR" 755 root:root

sep
say 'An existing directory keeps its mode when the entry gives none'
run "chmod 1777 $DIR"
assert_perm "d $DIR"                 1777 root:root
assert_perm "d $DIR - - -"           1777 root:root
assert_perm "d $DIR 0750"            750  root:root
assert_perm "e $DIR"                 750  root:root
assert_perm "d $DIR 1777 root root"  1777 root:root
