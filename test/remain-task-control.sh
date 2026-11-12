#!/bin/sh

set -eu

TEST_DIR=$(dirname "$0")
TEST_CONF=/etc/finit.d/remain-task.conf
STATE=/run/remain-task.state

test_teardown()
{
    run "rm -f $TEST_CONF $STATE"
}

assert_runs()
{
    assert "Remain task has run $1 time(s)" \
           "$(texec initctl -j status remain-task | jq -M .restarts)" -eq "$1"
}

# shellcheck source=/dev/null
. "$TEST_DIR/lib/setup.sh"

say 'Add remain task'
run "cat > $TEST_CONF" <<EOF
task remain-task {
    description       = "Remain task control"
    runlevel          = "2345"
    remain-after-exit = true
    command           = "/bin/touch $STATE"
    exec-stop-post    = "/bin/rm -f $STATE"
}
EOF
run "initctl reload"

retry 'assert_status remain-task done'
assert_file_exists "$STATE"
assert_runs 1

say 'Stop remain task'
run "initctl stop remain-task"
retry 'assert_status remain-task stopped'
assert "Post script removed state" \
       "$(texec sh -c "[ ! -e '$STATE' ] && echo yes")" = yes
assert_runs 1

say 'Start remain task'
run "initctl start remain-task"
retry 'assert_status remain-task done'
assert_file_exists "$STATE"
assert_runs 2

say 'Restart remain task'
run "initctl restart remain-task"
retry 'assert_runs 3'
retry 'assert_status remain-task done'
assert_file_exists "$STATE"

say 'Reload changed remain task'
run "sed -i 's/Remain task control/Updated remain task control/' $TEST_CONF"
run "initctl reload"
retry 'assert_runs 4'
retry 'assert_status remain-task done'
assert_file_exists "$STATE"

say 'Leave remain task runlevel'
run "initctl runlevel 1"
retry 'assert_status remain-task halted'
assert "Post script removed state" \
       "$(texec sh -c "[ ! -e '$STATE' ] && echo yes")" = yes
assert_runs 4

say 'Re-enter remain task runlevel'
run "initctl runlevel 2"
retry 'assert_runs 5'
retry 'assert_status remain-task done'
assert_file_exists "$STATE"
