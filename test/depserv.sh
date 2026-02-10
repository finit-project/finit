#!/bin/sh
# Verify handling of dependent services, bug #314
# Two services: foo and bar, where bar depends on foo:
#
#   - bar must not start until foo is ready
#   - bar must be stopped when foo goes down
#   - bar must be restarted when foo is restarted
#   - bar must be restarted when foo is reloaded (per-service reload)
#
# Regression test bug #314, that bar is not in a restart loop when foo
# is stopped.  Also, verify that changing between runlevels, where foo
# is not allowed to run, but bar is, that bar is stopped also for that.

set -eu

TEST_DIR=$(dirname "$0")

test_teardown()
{
    say "Running test teardown."

    run "rm -f $FINIT_CONF" "/tmp/post"
}

# shellcheck source=/dev/null
. "$TEST_DIR/lib/setup.sh"

#run "initctl debug"
#run "ls -l /run/finit/cond/pid/ /lib/finit/plugins/"

test_one()
{
    cond=$1
    say "Verifying foo -> <$cond> bar ..."
    run "echo service log:stderr name:foo            serv -np -i foo -f /tmp/arrakis  > $FINIT_CONF"
    run "echo service log:stderr name:bar \<!$cond\> serv -np -i bar -F /tmp/arrakis >> $FINIT_CONF"
    run "cat $FINIT_CONF"

    say 'Reload Finit'
    run "initctl reload"

    run "initctl status"
    assert_status "foo" "running"
    assert_cond   "$cond"
    assert_status "bar" "running"

    say "Verify bar is restarted when foo is ..."
    pid=$(texec initctl |grep bar | awk '{print $1;}')
    run "initctl restart foo"
    run "initctl status"
    assert "bar is restarted" "$(texec initctl |grep bar | awk '{print $1;}')" != "$pid"

    say "Verify bar is restarted when foo is reloaded (per-service) ..."
    retry 'assert_status "bar" "running"' 5 1
    pid=$(texec initctl |grep bar | awk '{print $1;}')
    run "initctl reload foo"
    retry 'assert_status "bar" "running"' 5 1
    assert "bar is restarted on reload" "$(texec initctl |grep bar | awk '{print $1;}')" != "$pid"

    # Wait for spice to be stolen by the Harkonnen
    sleep 3
    # bar should now have detected the loss of spice and be in restart
    run "initctl status"
    assert_status "bar" "restart"
    # verify bar is stopped->waiting and no longer in restart after stopping foo
    run "initctl stop foo"
    run "initctl status"
    run "initctl status bar"
    assert_status "bar" "waiting"
}

run "initctl debug"
sep
test_one "pid/foo"
sep
#run "initctl debug"
test_one "service/foo/ready"
