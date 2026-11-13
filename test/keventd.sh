#!/bin/sh
#
# Verify keventd, the bundled device manager.  Network interfaces are
# the only devices an unprivileged test can hotplug: the sandbox has
# its own network namespace, so `ip link add` makes the kernel emit
# genuine uevents for keventd to process.
#
# Verifies that keventd signals readiness, that an interface add event
# asserts <class/net/IFNAME> to start a dependent service -- but never
# <dev/IFNAME>, interfaces are not device nodes -- that the
# /run/udev/data entry uses libudev-style n<ifindex> keying, and that
# the remove event reverses it all.
#

set -eu

TEST_DIR=$(dirname "$0")

test_teardown()
{
    say "Running test teardown."

    run "ip link del dummy0 2>/dev/null || true"
    run "rm -f $FINIT_CONF"
}

# shellcheck source=/dev/null
. "$TEST_DIR/lib/setup.sh"

if ! texec initctl -p status keventd >/dev/null 2>&1; then
    skip "keventd not enabled in this build"
fi

if ! run "ip link add probe0 type dummy 2>/dev/null"; then
    skip "cannot create dummy interfaces in test namespace"
fi
run "ip link del probe0"

sep "keventd readiness"
retry 'assert_ready "keventd"' 50 0.2

# Finit does not touch a daemon-owned pidfile, so keventd must do it
# after SIGHUP to reassert readiness, see issue #503.  Signalled with
# kill to keep Finit out of it.
sep "keventd touches its pidfile on SIGHUP"
run "touch -d '2000-01-01 00:00' /run/keventd.pid"
run "kill -HUP $(texec cat /run/keventd.pid)"
retry "test \$(texec stat -c %Y /run/keventd.pid) -gt 1000000000" 10 0.2

sep "interface add asserts <class/net/dummy0>"
cat >> "$SYSROOT$FINIT_CONF" <<EOF
service serv {
    log { file = "/dev/null" }
    conditions = { "class/net/dummy0" }
    command = "serv -np"
}
EOF
run "cat $FINIT_CONF"
run "initctl reload"
assert_status "serv" "waiting"

run "ip link add dummy0 type dummy"
retry 'assert_cond "class/net/dummy0"'
assert_nocond "dev/dummy0"
retry 'assert_status "serv" "running"'

sep "udev database uses n<ifindex> keying"
ifindex=$(texec cat /sys/class/net/dummy0/ifindex)
assert_file_exists "/run/udev/data/n$ifindex"
assert_file_contains "/run/udev/data/n$ifindex" "E:INTERFACE=dummy0"

sep "conditions survive initctl reload"
run "initctl reload"
retry 'assert_cond "class/net/dummy0"'
retry 'assert_status "serv" "running"'

sep "interface remove clears <class/net/dummy0>"
run "ip link del dummy0"
retry 'assert_nocond "class/net/dummy0"'
retry 'assert_status "serv" "waiting"'
retry "texec test ! -e /run/udev/data/n$ifindex"
