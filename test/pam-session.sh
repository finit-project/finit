#!/bin/sh
# A service can run inside a PAM session, so the session stack in
# /etc/pam.d applies to the process that becomes the daemon.
#
# The session outlives the setup: a keeper process, (finit-pam), holds
# the PAM handle and closes the session when the service dies.  Here we
# check that it appears and disappears with the service, that a denied
# account stack keeps the service from running at all, and that a
# missing pam.d config, or a value that is a path rather than a name,
# does the same.
#
# Skipped unless Finit was built --enable-pam and the host had PAM
# modules for lib/sysroot.mk to stage.
set -eu

TEST_DIR=$(dirname "$0")

test_teardown()
{
    say "Running test teardown."
    run "rm -f $FINIT_CONF"
    run "rm -f /tmp/pre"
    run "rm -rf /etc/pam.d"
    run "rm -rf /etc/security"
}

# shellcheck source=/dev/null
. "$TEST_DIR/lib/setup.sh"

# shellcheck disable=SC2154 # top_builddir comes from AM_TESTS_ENVIRONMENT
grep -q "define HAVE_LIBPAM" "$top_builddir/config.h" 2>/dev/null \
    || skip "Finit built without --enable-pam"

# Staged by lib/sysroot.mk from the host, when it has them.  All three,
# not just pam_permit.so: without pam_deny.so the denied case would fail
# for the wrong reason and still look like a pass.
# shellcheck disable=SC2016 # the globs are for the shell inside texec
PAMDIR=$(texec sh -c 'for d in /lib/*/security /usr/lib/*/security /lib/security; do
                          test -f "$d/pam_permit.so" || continue
                          test -f "$d/pam_deny.so"   || continue
                          test -f "$d/pam_limits.so" || continue
                          echo "$d" && break
                      done')
[ -n "$PAMDIR" ] || skip "no PAM modules in the test root, need them on the host"

assert_keeper()
{
    assert "$1 PAM session keeper(s)" \
           "$(texec sh -c 'cat /proc/[0-9]*/comm 2>/dev/null | grep -c "(finit-pam)"' || true)" -eq "$1"
}

# pamsess_open() leaves the child with EX_OSERR, so a service that fails
# for any other reason -- a bad command, a pidfile it cannot write -- is
# a test failure rather than a pass.
denied="crashed (code=exited, status=71/OSERR)"

say 'A permissive PAM config, and one that denies the account stack'
run "mkdir -p /etc/pam.d"
run "printf 'auth required pam_permit.so\naccount required pam_permit.so\nsession required pam_permit.so\n' > /etc/pam.d/finit-ok"
run "printf 'auth required pam_permit.so\naccount required pam_deny.so\nsession required pam_permit.so\n'   > /etc/pam.d/finit-no"

say 'A service in a session runs, and a keeper appears alongside it'
run "printf 'service pamok {\n runlevel = \"S12345\"\n user = \"daemon\"\n pam = \"finit-ok\"\n command = \"/sbin/serv -n -i pamok\"\n}\n' > $FINIT_CONF"
run "initctl reload"
retry 'assert_status pamok running'
retry 'assert_keeper 1'

say 'Stopping the service takes the keeper with it'
run "initctl stop pamok"
retry 'assert_status pamok stopped'
retry 'assert_keeper 0'

say 'Starting again opens a fresh session'
run "initctl start pamok"
retry 'assert_status pamok running'
retry 'assert_keeper 1'
run "initctl stop pamok"
retry 'assert_keeper 0'

say 'A denied account stack keeps the service from running'
run "printf 'service pamno {\n runlevel = \"S12345\"\n user = \"daemon\"\n pam = \"finit-no\"\n command = \"/sbin/serv -n -i pamno\"\n}\n' > $FINIT_CONF"
run "initctl reload"
retry "assert_status_full pamno '$denied'" 500
assert_keeper 0

say 'So does a pam.d config that is not there'
run "printf 'service pamgone {\n runlevel = \"S12345\"\n user = \"daemon\"\n pam = \"finit-no-such-config\"\n command = \"/sbin/serv -n -i pamgone\"\n}\n' > $FINIT_CONF"
run "initctl reload"
retry "assert_status_full pamgone '$denied'" 500
assert_keeper 0

say 'A pam value that is a path is refused, the service does not start'
run "printf 'service pampath {\n runlevel = \"S12345\"\n user = \"daemon\"\n pam = \"/etc/pam.d/finit-ok\"\n command = \"/sbin/serv -n -i pampath\"\n}\n' > $FINIT_CONF"
run "initctl reload"
retry 'assert_status pampath missing'
assert_keeper 0

# The pre: script forks from SVC_SETUP_STATE, before service_start()
# runs, so it is pamsess_open() that has to refuse the value here.  The
# script exits 71 without ever running, hence no /tmp/pre.
say 'And a pre: script does not get the refused value either'
run "printf 'service pampre {\n runlevel = \"S12345\"\n user = \"daemon\"\n pam = \"/etc/pam.d/finit-ok\"\n exec-start-pre = \"/bin/pre.sh\"\n command = \"/sbin/serv -n -i pampre\"\n}\n' > $FINIT_CONF"
run "initctl reload"
retry "assert_status_full pampre '$denied'" 500
assert "pre: script did not run" "$(texec sh -c 'test -e /tmp/pre && echo yes || echo no')" = "no"
assert_keeper 0

say 'pam_limits wins over the per-service rlimit'
run "mkdir -p /etc/security"
run "printf 'daemon hard nofile 512\ndaemon soft nofile 512\n' > /etc/security/limits.conf"
run "printf 'auth required pam_permit.so\naccount required pam_permit.so\nsession required pam_limits.so\n' > /etc/pam.d/finit-lim"
run "printf 'service pamlim {\n runlevel = \"S12345\"\n user = \"daemon\"\n pam = \"finit-lim\"\n rlimit {\n  nofile = 4096\n }\n command = \"/sbin/serv -n -i pamlim\"\n}\n' > $FINIT_CONF"
run "initctl reload"
retry 'assert_status pamlim running'

pamlim_pid=$(texec initctl -j status pamlim | jq -M .pid)
# shellcheck disable=SC2016 # $4 is awk's field reference, not the shell's
assert "nofile is 512, from limits.conf, not 4096 from the block" \
       "$(texec awk '/Max open files/ { print $4 }' "/proc/$pamlim_pid/limits")" = "512"

run "initctl stop pamlim"
retry 'assert_keeper 0'
