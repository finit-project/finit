#!/bin/sh
# Verify stop-scope, which processes a stop applies to, see issue #413.
# The service leaves a child behind in its process group, like the
# action script of avahi-autoipd.  Cgroups are not available in the
# test namespace, so cgroup and mixed fall back to the process group.
set -eu

TEST_DIR=$(dirname "$0")

CHILD=/tmp/scope-child

# Start the service, stop it, and check if its child is still there.
# Optional second argument is the stop-scope.
stop_one()
{
    sep
    say "stop-scope ${2:-default}, child is left $1"
    run "rm -f $CHILD"
    run "cat > $FINIT_CONF" <<EOF
service scope {
    ${2:+stop-scope = "$2"}
    command = "scope.sh"
}
EOF
    run "initctl reload"
    run "initctl start scope"
    retry 'assert_status scope running'
    retry "texec test -s $CHILD"

    run "initctl stop scope"
    retry 'assert_status scope stopped'
    if [ "$1" = alive ]; then
	assert "Child is alive" "$(texec sh -c "kill -0 \$(cat $CHILD) && echo yes")" = yes
	run "kill \$(cat $CHILD)"
    else
	retry "texec sh -c '! kill -0 \$(cat $CHILD) 2>/dev/null'"
    fi
}

test_teardown()
{
    say "Running test teardown."
    run "kill \$(cat $CHILD 2>/dev/null) 2>/dev/null || true"
    run "rm -f $FINIT_CONF $CHILD /bin/scope.sh"
}

# shellcheck source=/dev/null
. "$TEST_DIR/lib/setup.sh"

cat > "$SYSROOT/bin/scope.sh" <<EOF
#!/bin/sh
sleep 100 &
echo \$! > $CHILD
exec serv -np -i scope
EOF
chmod +x "$SYSROOT/bin/scope.sh"

stop_one dead
stop_one dead  pgroup
stop_one alive process
stop_one dead  cgroup
stop_one dead  mixed
