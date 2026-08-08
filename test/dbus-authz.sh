#!/bin/sh
# Who may invoke a privileged method.  Root always, and anyone in the
# group the bus socket is owned by, which is DEFGROUP from
# --with-group, 'root' in a test build.  Everyone else is refused.
#
# A caller that gets past the check still has to name a service that
# exists, so NoSuchService is how we tell "allowed, then failed" apart
# from "not allowed at all".

set -eu

TEST_DIR=$(dirname "$0")

# shellcheck source=/dev/null
. "$TEST_DIR/lib/setup.sh"
# shellcheck source=/dev/null
. "$TEST_DIR/lib/dbus-setup.sh"

# uid 1000 is 'wheelie', a member of group root in the test sysroot.
# uid 2 is 'bin', a member of nothing that matters here.
say "A member of the group may call a privileged method"
set +e
allowed=$(texec "$CLIENT" call-s-as-uid 1000 "$BUS" /org/finit/manager \
	  org.finit.Manager1 Restart nosuchservice 2>&1)
set -e
case "$allowed" in
    *AccessDenied*) fail "Group member was refused: $allowed" ;;
    *NoSuchService*) assert "Group member passed authorization" 0 -eq 0 ;;
    *)              fail "Unexpected reply for group member: $allowed" ;;
esac

say "A caller outside the group may not"
set +e
denied=$(texec "$CLIENT" call-s-as-uid 2 "$BUS" /org/finit/manager \
	 org.finit.Manager1 Restart nosuchservice 2>&1)
set -e
case "$denied" in
    *AccessDenied*)  assert "Non-member refused" 0 -eq 0 ;;
    *NoSuchService*) fail "Non-member passed authorization: $denied" ;;
    *)               fail "Unexpected reply for non-member: $denied" ;;
esac

say "Root is still allowed"
set +e
asroot=$(texec "$CLIENT" call-s "$BUS" /org/finit/manager \
	 org.finit.Manager1 Restart nosuchservice 2>&1)
set -e
case "$asroot" in
    *AccessDenied*) fail "Root was refused: $asroot" ;;
    *NoSuchService*) assert "Root passed authorization" 0 -eq 0 ;;
    *)              fail "Unexpected reply for root: $asroot" ;;
esac
