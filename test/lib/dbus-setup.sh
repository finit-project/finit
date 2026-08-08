# shellcheck shell=sh
# Shared preamble for the D-Bus smoke tests.  Expects test/lib/setup.sh
# to have been sourced already (so texec, skip, retry, say, assert are
# available).  Skips the test when the libink-driven client was not
# built, otherwise blocks until the bus socket appears.
#
# Exports: CLIENT, BUS.

command -v texec >/dev/null \
    || { echo "dbus-setup.sh: source test/lib/setup.sh first" >&2; exit 99; }

CLIENT=/sbin/dbus-auth-client
BUS=/run/finit/bus

if ! texec test -x "$CLIENT"; then
    skip "dbus-auth-client not built (configured with --disable-dbus?)"
fi

say "Wait for $BUS to appear"
retry "texec test -S $BUS"
