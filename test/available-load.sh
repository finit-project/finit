#!/bin/sh
# Verify the load-available setting: units in /etc/finit.d/available/ are
# registered with available-only source state and controllable with initctl,
# but not started automatically.  Enabling a service (symlink in enabled/,
# read last) makes it follow its independent manual-start policy; disabling
# it again keeps it loaded and startable, and must not re-run a completed
# task.  Files in the top-level
# finit.d directory are unaffected, and override available/ by name.
set -eu

TEST_DIR=$(dirname "$0")

SYSROOT="${SYSROOT:-$(pwd)/$TEST_DIR/sysroot}"
FINITD="$SYSROOT/etc/finit.d"

test_teardown()
{
    say "Removing test files from sysroot."
    rm -f "$FINITD/available/svcblk.conf" \
          "$FINITD/available/svcleg.conf" \
          "$FINITD/available/svcauto.conf" \
          "$FINITD/available/svcmanual.conf" \
          "$FINITD/available/svctask.conf" \
          "$FINITD/available/svcrun.conf" \
          "$FINITD/available/svcsysv.conf" \
          "$FINITD/available/svcwait.conf" \
          "$FINITD/available/svctty.conf" \
          "$FINITD/available/svcinclude.conf" \
          "$FINITD/available/global.conf" \
          "$FINITD/available/dup.conf" \
          "$FINITD/available/cond.conf" \
          "$FINITD/available/provider.conf" \
          "$FINITD/available/dangling.conf" \
          "$FINITD/available/svclate.conf" \
          "$FINITD/dup.conf" \
          "$FINITD/cond.conf" \
          "$FINITD/provider.conf" \
          "$FINITD/svctop.conf" \
          "$FINITD/avenvprobe.conf" \
          "$FINITD/enabled/svcblk.conf" \
          "$FINITD/enabled/svcauto.conf" \
          "$FINITD/enabled/svcmanual.conf" \
          "$FINITD/enabled/svctask.conf" \
          "$FINITD/enabled/dangling.conf" \
          "$FINITD/enabled/svclate.conf" \
          "$SYSROOT/etc/available-include.conf" \
          "$SYSROOT/etc/load-available.conf" \
          "$SYSROOT/sbin/avtask.sh" \
          "$SYSROOT/sbin/avenv.sh" \
          "$SYSROOT/sbin/avlate.sh" \
          "$SYSROOT/var/avtask.log" \
          "$SYSROOT/var/avenv.log" \
          "$SYSROOT/run/svclate.pid"
}

# shellcheck disable=SC2034
BOOTSTRAP="load-available = true"

mkdir -p "$FINITD/available" "$FINITD/enabled"

# Counts each execution, run as a task below
cat > "$SYSROOT/sbin/avtask.sh" <<'EOF'
#!/bin/sh
echo run >> /var/avtask.log
EOF
chmod +x "$SYSROOT/sbin/avtask.sh"

# A top-level setting in available/ must not affect the system until
# that file is enabled.  A regular task records what environment it saw.
cat > "$SYSROOT/sbin/avenv.sh" <<'EOF'
#!/bin/sh
echo "${AVAIL_GLOBAL-unset}" > /var/avenv.log
EOF
chmod +x "$SYSROOT/sbin/avenv.sh"

cat > "$FINITD/available/global.conf" <<EOF
environment {
    AVAIL_GLOBAL = "leaked"
}
EOF
cat > "$FINITD/avenvprobe.conf" <<EOF
task avenvprobe {
    runlevel = "2345"
    command  = "/sbin/avenv.sh"
}
EOF

# Block format, no explicit manual-start: available-only and startable
cat > "$FINITD/available/svcblk.conf" <<EOF
service svcblk {
    runlevel = "2345"
    command  = "/sbin/serv -np -i svcblk"
}
EOF

# Legacy one-liner: source state applies without changing manual policy
cat > "$FINITD/available/svcleg.conf" <<EOF
service [2345] name:svcleg /sbin/serv -np -i svcleg -- Legacy available service
EOF

# Explicit false cannot make an available-only unit start automatically
cat > "$FINITD/available/svcauto.conf" <<EOF
service svcauto {
    runlevel     = "2345"
    manual-start = false
    command      = "/sbin/serv -np -i svcauto"
}
EOF

# Explicit true remains manual after the unit is enabled
cat > "$FINITD/available/svcmanual.conf" <<EOF
service svcmanual {
    runlevel     = "2345"
    manual-start = true
    command      = "/sbin/serv -np -i svcmanual"
}
EOF

# Available-only task: must not re-run when disabled again
cat > "$FINITD/available/svctask.conf" <<EOF
task svctask {
    runlevel = "2345"
    command  = "/sbin/avtask.sh"
}
EOF

# Run and sysv share the service translator, but have distinct lifecycle
# handling.  Keep direct coverage of every runnable stanza type here.
cat > "$FINITD/available/svcrun.conf" <<EOF
run svcrun {
    runlevel = "2345"
    command  = "/bin/true"
}
EOF
cat > "$FINITD/available/svcsysv.conf" <<EOF
sysv svcsysv {
    runlevel = "2345"
    command  = "/sbin/service.sh"
}
EOF

# A manually started service waiting on a condition must stay armed
# across unrelated configuration reloads.
cat > "$FINITD/available/svcwait.conf" <<EOF
service svcwait {
    runlevel   = "2345"
    conditions = { "usr/available-gate" }
    command    = "/sbin/serv -np -i svcwait"
}
EOF

# TTY is the fifth runnable stanza type and follows the same default.
cat > "$FINITD/available/svctty.conf" <<EOF
tty available-console {
    runlevel = "2345"
    device   = "/dev/console"
}
EOF

# Legacy includes must inherit the available/ source context even when
# the included file itself lives elsewhere.
cat > "$SYSROOT/etc/available-include.conf" <<EOF
service [2345] name:svcinclude /sbin/serv -np -i svcinclude -- Included available service
EOF
cat > "$FINITD/available/svcinclude.conf" <<EOF
include /etc/available-include.conf
EOF

# Same basename as a top-level file: the top-level copy must win
cat > "$FINITD/available/dup.conf" <<EOF
service dupavail {
    runlevel = "2345"
    command  = "/sbin/serv -np -i dupavail"
}
EOF
cat > "$FINITD/dup.conf" <<EOF
service dupwin {
    runlevel = "2345"
    command  = "/sbin/serv -np -i dupwin"
}
EOF

# A broken higher-priority symlink must not hide a valid available unit.
cat > "$FINITD/available/dangling.conf" <<EOF
service dangling {
    runlevel = "2345"
    command  = "/sbin/serv -np -i dangling"
}
EOF
ln -s /nonexistent "$FINITD/enabled/dangling.conf"

# Forking service used to verify a late pidfile does not undo disable.
cat > "$SYSROOT/sbin/avlate.sh" <<'EOF'
#!/bin/sh
/bin/sh -c 'sleep 3; echo $$ > /run/svclate.pid; sleep 30' &
EOF
chmod +x "$SYSROOT/sbin/avlate.sh"
cat > "$FINITD/available/svclate.conf" <<EOF
service svclate {
    runlevel       = "2345"
    type           = "forking"
    pidfile = "/run/svclate.pid"
    command = "/sbin/avlate.sh"
}
EOF

# Available-only units do not satisfy if:name during configuration pruning
cat > "$FINITD/available/cond.conf" <<EOF
service optional {
    runlevel = "2345"
    command  = "/sbin/serv -np -i optional"
}
EOF
cat > "$FINITD/cond.conf" <<EOF
service condmain {
    if       = "optional"
    runlevel = "2345"
    command  = "/sbin/serv -np -i condmain"
}
service condfallback {
    if       = "!optional"
    runlevel = "2345"
    command  = "/sbin/serv -np -i condfallback"
}
EOF

# An enabled provider must displace an available-only provides claim
cat > "$FINITD/available/provider.conf" <<EOF
service standby {
    runlevel = "2345"
    provides = { "usr/available-provider" }
    command  = "/sbin/serv -np -i standby"
}
EOF
cat > "$FINITD/provider.conf" <<EOF
service active {
    runlevel = "2345"
    provides = { "usr/available-provider" }
    command  = "/sbin/serv -np -i active"
}
service consumer {
    runlevel   = "2345"
    conditions = { "usr/available-provider" }
    command    = "/sbin/serv -np -i consumer"
}
EOF

# Top-level finit.d file: not affected by load-available, starts at boot
cat > "$FINITD/svctop.conf" <<EOF
service [2345] name:svctop /sbin/serv -np -i svctop -- Top level service
EOF

# shellcheck source=/dev/null
. "$TEST_DIR/lib/setup.sh"

# manual-start services expose "starts" in JSON status, others do not
assert_manual()
{
    assert "$1 is manual-start" "$(texec initctl -j status "$1" | jq -M 'has("starts")')" = "true"
}

assert_not_manual()
{
    assert "$1 is not manual-start" "$(texec initctl -j status "$1" | jq -M 'has("starts")')" = "false"
}

task_runs()
{
    n=$(texec sh -c 'if [ -f /var/avtask.log ]; then wc -l < /var/avtask.log; else echo 0; fi' | tr -cd 0-9)
    echo "${n:-0}"
}

assert_ran()
{
    assert "svctask ran at least once" "$(task_runs)" -ge 1
}

say 'Services in available/ are loaded, but not started at boot'
retry 'assert_loaded svcblk 1'
assert_loaded svcleg 1
assert_loaded svcauto 1
assert_loaded svcmanual 1
assert_loaded svctask 1
assert_loaded svcrun 1
assert_loaded svcsysv 1
assert_loaded svcwait 1
assert_loaded svcinclude 1
assert_loaded tty:console 1
assert_not_manual svcblk
assert_not_manual svcleg
assert_not_manual svcauto
assert_manual svcmanual
assert_not_manual svctask
assert_not_manual svcrun
assert_not_manual svcsysv
assert_not_manual svcwait
assert_not_manual svcinclude
assert_not_manual tty:console
retry 'assert_status svcblk stopped'
retry 'assert_status svcleg stopped'
retry 'assert_status svcauto stopped'
retry 'assert_status svcmanual stopped'
retry 'assert_status svcrun stopped'
retry 'assert_status svcsysv stopped'
retry 'assert_status tty:console stopped'
assert "svctask did not run at boot" "$(task_runs)" -eq 0

say 'Top-level settings in available/ stay inactive until enabled'
retry 'assert_file_contains /var/avenv.log unset'

say 'Explicit manual-start = false cannot bypass available-only state'
assert_not_manual svcauto
retry 'assert_status svcauto stopped'

say 'Top-level finit.d files keep the old default and start at boot'
assert_not_manual svctop
retry 'assert_status svctop running'

say 'A same-named top-level file overrides the available/ copy'
assert_loaded dupavail 0
assert_loaded dupwin 1
retry 'assert_status dupwin running'

say 'A dangling override does not hide a valid available unit'
assert_loaded dangling 1
retry 'assert_status dangling stopped'

say 'Available-only units do not satisfy if:name'
assert_loaded optional 1
assert_loaded condmain 0
assert_loaded condfallback 1
retry 'assert_status condfallback running'

say 'Enabled providers displace available-only provides claims'
retry 'assert_status active running'
retry 'assert_status consumer running'
retry 'assert_status standby stopped'

say 'Available-only services are controllable at runtime'
run "initctl start svcblk"
retry 'assert_status svcblk running'
run "initctl stop svcblk"
retry 'assert_status svcblk stopped'

say 'A late pidfile cannot undo an explicit stop during disable'
run "initctl enable svclate"
run "initctl reload"
sleep 1
run "initctl disable svclate"
run "initctl reload"
sleep 4
retry 'assert_status svclate stopped'

say 'A running available-only service satisfies if:name'
run "initctl start optional"
retry 'assert_status optional running'
run "initctl reload"
retry 'assert_loaded condmain 1'
retry 'assert_status condmain running'
assert_loaded condfallback 0

say 'A manual service waiting on a condition stays armed across reload'
run "initctl start svcwait"
retry 'assert_status svcwait waiting'
run "initctl reload"
retry 'assert_status svcwait waiting'
run "initctl cond set available-gate"
retry 'assert_status svcwait running'

say 'Enable + reload: omitted manual-start allows automatic start'
run "initctl enable svcblk"
run "initctl reload"
retry 'assert_status svcblk running'
assert_not_manual svcblk

say 'Enable + reload: explicit false also allows automatic start'
run "initctl enable svcauto"
run "initctl reload"
retry 'assert_status svcauto running'
assert_not_manual svcauto

say 'Enable + reload: explicit true remains manual'
run "initctl enable svcmanual"
run "initctl reload"
retry 'assert_status svcmanual stopped'
assert_manual svcmanual
run "initctl start svcmanual"
retry 'assert_status svcmanual running'

say 'Disable + reload: still loaded and explicitly startable'
run "initctl stop svcblk"
retry 'assert_status svcblk stopped'
run "initctl disable svcblk"
run "initctl reload"
retry 'assert_loaded svcblk 1'
assert_not_manual svcblk
run "initctl start svcblk"
retry 'assert_status svcblk running'

say 'A completed task is not re-run when disabled to available-only'
run "initctl start svctask"
retry 'assert_ran'
run "initctl enable svctask"
run "initctl reload"
sleep 2
runs1=$(task_runs)
say "svctask runs after enable+reload: $runs1"
run "initctl disable svctask"
run "initctl reload"
sleep 2
runs2=$(task_runs)
assert "svctask not re-run by disable+reload ($runs1 -> $runs2)" "$runs1" -eq "$runs2"

say 'A legacy format finit.conf falls back to the default (off)'
# A legacy one-liner: fails block-format probe, goes to the legacy
# parser, which cannot express load-available => setting must reset
run "echo 'task [2345] name:legacynoop /bin/true -- Legacy format probe' > $FINIT_CONF"
run "initctl reload"
retry 'assert_loaded svcleg 0'
if run "initctl start svcleg" 2>/dev/null; then
    fail "svcleg startable after finit.conf turned legacy format"
fi
say 'available/ no longer loaded, as expected'

say 'A legacy finit.conf can enable it through a block-format include'
run "echo 'load-available = true' > /etc/load-available.conf"
run "echo 'include /etc/load-available.conf' > $FINIT_CONF"
run "echo 'task [2345] name:legacynoop /bin/true -- Legacy format probe' >> $FINIT_CONF"
run "initctl reload"
retry 'assert_loaded svcleg 1'
run "initctl start svcleg"
retry 'assert_status svcleg running'

say 'load-available = false unloads available-only services'
run "echo 'load-available = false' > $FINIT_CONF"
run "initctl reload"
retry 'assert_loaded svcleg 0'
if run "initctl start svcleg" 2>/dev/null; then
    fail "svcleg startable with load-available = false"
fi
say 'initctl start refused, as expected'

say 'An empty available/ directory does not break later config globs'
run "rm -f $FINIT_RCSD/available/*.conf"
run "echo 'load-available = true' > $FINIT_CONF"
run "initctl reload"
retry 'assert_loaded svcauto 0'
retry 'assert_loaded svctop 1'
retry 'assert_status svctop running'
