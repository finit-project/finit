#!/bin/sh
# Verify initctl -j status: it has the settings of a service, and gives
# the same over D-Bus as over the initctl socket.
set -eu

TEST_DIR=$(dirname "$0")

BUS=/run/finit/bus

# Check member $1 of the JSON status in $json
assert_json()
{
    assert "$1 is $2" "$(echo "$json" | jq -c "$1")" = "$2"
}

test_teardown()
{
    say "Running test teardown."
    run "test -e $BUS.hidden && mv $BUS.hidden $BUS || true"
    run "rm -f $FINIT_CONF"
}

# shellcheck source=/dev/null
. "$TEST_DIR/lib/setup.sh"

run "cat > $FINIT_CONF" <<CONF
service json {
    description     = "JSON status"
    notify          = "pid"
    stop-signal     = "SIGINT"
    stop-timeout    = 5
    stop-scope      = "process"
    restart-max     = 3
    restart-sec     = 2
    restart-max-sec = 8
    oncrash         = "script"
    exec-stop-post  = "/bin/true"
    exec-stop-post-timeout = 7
    runtime-dir     = "json"
    runtime-dir-mode = 0750
    rlimit {
        soft.nofile = 123
        hard.nofile = 456
        core        = unlimited
    }
    cgroup maint { cpu.weight = 250 }
    runtime-dir-preserve = "restart"
    extra-groups    = { "daemon", "bin" }
    provides        = { "usr/json-a", "usr/json-b" }
    conflicts       = { "nosuch" }
    log {
        identity = "jason"
    }
    command         = "serv -np -i json"
}
CONF
run "initctl reload"
retry 'assert_status json running'

sep
say 'The settings of the service are in the JSON status'
run "initctl -j status json"
json=$(texec initctl -j status json)

assert_json .notify            '"pid"'
assert_json .remain            'false'
assert_json .stop              '{"signal":"SIGINT","timeout":5,"scope":"process"}'
assert_json .reload.signal     '"SIGHUP"'
assert_json .restart.max       '3'
assert_json .restart.sec       '2'
assert_json .restart.limit     '8'
assert_json .restart.respawn   'false'
assert_json .restart.oncrash   '"script"'
assert_json .scripts           '{"exec-stop-post":{"command":"/bin/true","timeout":7}}'
assert_json .directories       '{"runtime":{"name":"json","mode":"0750"},"preserve":"restart"}'
assert_json .rlimits.nofile    '{"soft":123,"hard":456}'
assert_json .rlimits.core      '{"soft":"unlimited","hard":"unlimited"}'
assert_json '."cgroup-config"' '{"group":"maint","config":"cpu.weight:250","delegate":false}'
assert_json .name              '"json"'
assert_json .protected         'false'
assert_json .id                '""'
assert_json .internal.removed  'false'
assert_json .internal.oldpid   '0'
assert_json .reload.propagate  'false'
assert_json .groups            '["daemon","bin"]'
assert_json .provides          '["usr/json-a","usr/json-b"]'
assert_json .conflicts         '["nosuch"]'
assert_json .log.enabled       'true'
assert_json .log.identity      '"jason"'

if texec test -e $BUS; then
    sep
    say 'Same over the initctl socket, with the bus hidden'
    run "mv $BUS $BUS.hidden"
    legacy=$(texec initctl -j status json)
    run "mv $BUS.hidden $BUS"
    assert "Same JSON from both" "$(echo "$json" | jq -cS 'del(.uptime)')" = "$(echo "$legacy" | jq -cS 'del(.uptime)')"
fi
