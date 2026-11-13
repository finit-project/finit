#!/bin/sh
# Verify a command list.  The entries are candidates for the same
# service and the first one whose binary resolves wins, which the
# line-based format could only express as one stanza per candidate.
set -eu

TEST_DIR=$(dirname "$0")

# shellcheck disable=SC2034
# The first candidate is not installed, so the second one runs.  This
# is the udevd case from system/10-hotplug.conf, where the systemd
# build of the daemon is tried before the standalone one.
BOOTSTRAP="service pick {
    runlevel = \"S12345\"
    command  = { \"/no/such/binary --daemon\", \"serv -np -i pick\" }
}"

# The chosen candidate is what Finit runs, so assert on that rather
# than on process names: pgrep matches a substring, and 'serv' is one
# of 'service.sh'.
assert_cmd()
{
    assert "Service $1 command == $2" \
	   "$(texec initctl status "$1" | grep 'Command' | sed 's/.*Command : //')" = "$2"
}

test_teardown()
{
    say "Running test teardown."
    run "rm -f $FINIT_CONF"
}

# shellcheck source=/dev/null
. "$TEST_DIR/lib/setup.sh"

say 'A missing first candidate hands the service to the next one'
retry 'assert_num_children 1 serv'
assert_cmd pick "serv -np -i pick"

# With a BOOTSTRAP the test is released in runlevel S, where a reload
# is ignored, and the rewritten file would then be picked up by the
# runlevel change instead of the reload under test.
say 'Waiting for bootstrap to finish before rewriting the configuration'
retry "test \"\$(texec sh -c \"initctl runlevel | awk '{print \\\$2;}'\")\" = 2" 20 1

# Both binaries exist here, so a plain "does it resolve" check would
# be satisfied by either.  Only order decides.
say 'When several candidates resolve, the first one wins'
run "echo 'service pick {'                                    >  $FINIT_CONF"
run "echo '    command = { \"serv -np -i pick\", \"service.sh\" }' >> $FINIT_CONF"
run "echo '}'                                                 >> $FINIT_CONF"
run "initctl reload"

retry 'assert_cmd pick "serv -np -i pick"'
assert_num_children 1 serv

say 'The order is honoured the other way around too'
run "echo 'service pick {'                                    >  $FINIT_CONF"
run "echo '    command = { \"service.sh\", \"serv -np -i pick\" }' >> $FINIT_CONF"
run "echo '}'                                                 >> $FINIT_CONF"
run "initctl reload"

retry 'assert_cmd pick "service.sh"'
assert_num_children 1 service.sh

# libconfuse takes a bare string for a list option, so the spelling
# every other .conf uses has to keep working after command became one.
say 'A single command needs no braces'
run "echo 'service pick {'                         >  $FINIT_CONF"
run "echo '    description = \"Single command\"'   >> $FINIT_CONF"
run "echo '    command     = \"serv -np -i pick\"' >> $FINIT_CONF"
run "echo '}'                                      >> $FINIT_CONF"
run "initctl reload"

retry 'assert_cmd pick "serv -np -i pick"'
assert_desc "Single command" pick
assert_num_children 1 serv

# The description has its own setting, so a -- in the command is an
# argument to it, see issue #512.
say 'A -- in the command is passed on to it'
run "echo 'service pick {'                                >  $FINIT_CONF"
run "echo '    description = \"Dashes\"'                   >> $FINIT_CONF"
run "echo '    command     = \"serv -np -i pick -- extra\"' >> $FINIT_CONF"
run "echo '}'                                             >> $FINIT_CONF"
run "initctl reload"

retry 'assert_cmd pick "serv -np -i pick -- extra"'
assert_desc "Dashes" pick
assert_num_children 1 serv

# Options are matched as whole tokens, so a command that merely starts
# like one, pidof vs. pid, is still the command.
say 'A command named like an option is the command'
run "echo 'task lookalike {'             >  $FINIT_CONF"
run "echo '    command = \"pidof serv\"' >> $FINIT_CONF"
run "echo '}'                            >> $FINIT_CONF"
run "initctl reload"

retry 'assert_cmd lookalike "pidof serv"'

# A tty block takes the same list, its command is the getty to run.
# Asserting it is loaded is enough here, a getty in the test namespace
# has no terminal to attach to.
say 'A tty block takes candidates too'
run "echo 'tty console {'                                  >  $FINIT_CONF"
run "echo '    runlevel = \"12345\"'                       >> $FINIT_CONF"
run "echo '    command  = { \"/no/such/getty\", \"serv -np -i ttypick\" }' >> $FINIT_CONF"
run "echo '}'                                              >> $FINIT_CONF"
run "initctl reload"

retry 'assert_cmd tty "serv -np -i ttypick"'

# Nothing resolves, so the block is skipped the same way a single
# missing command is.  The leading - only decides whether that is
# quiet, service_register_desc() bails before svc_new() either way.
say 'A block whose candidates are all missing is skipped'
run "echo 'service ghost {'                                >  $FINIT_CONF"
run "echo '    command = { \"-/no/such/one\", \"-/no/such/two\" }' >> $FINIT_CONF"
run "echo '}'                                              >> $FINIT_CONF"
run "initctl reload"

assert_num_services 0 ghost
