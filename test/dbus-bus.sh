#!/bin/sh
# libink: org.freedesktop.DBus built-in interface.
#
# Covers the stock D-Bus interface every conforming bus implements:
# Hello (peer name allocation), Introspect (XML), and AddMatch's
# error-path rule parser.

set -eu

TEST_DIR=$(dirname "$0")

# shellcheck source=/dev/null
. "$TEST_DIR/lib/setup.sh"
# shellcheck source=/dev/null
. "$TEST_DIR/lib/dbus-setup.sh"

say "Hello() returns a unique name beginning with ':1.'"
name=$(texec "$CLIENT" hello "$BUS")
case "$name" in
    :1.*) assert "Hello returned a :1.N name (got $name)" 0 -eq 0 ;;
    *)    fail "Hello returned unexpected name: $name" ;;
esac

say "Two Hello() calls produce different unique names"
n1=$(texec "$CLIENT" hello "$BUS")
n2=$(texec "$CLIENT" hello "$BUS")
assert "Unique names increment ($n1 vs $n2)" "$n1" != "$n2"

say "Introspect on root path returns valid XML"
xml=$(texec "$CLIENT" introspect "$BUS" /)
case "$xml" in
    *'<node'*) assert "XML has <node> root (good)" 0 -eq 0 ;;
    *) fail "Root introspect missing <node>: $xml" ;;
esac

say "Introspect on /org/finit/manager exposes Manager1.ListServices"
xml=$(texec "$CLIENT" introspect "$BUS" /org/finit/manager)
case "$xml" in
    *'org.finit.Manager1'*'ListServices'*)
        assert "Manager1 and ListServices visible in XML" 0 -eq 0 ;;
    *)
        fail "Manager1 XML missing; got: $xml" ;;
esac

say "AddMatch with a bogus key is rejected"
set +e
texec "$CLIENT" call-s "$BUS" /org/freedesktop/DBus \
    org.freedesktop.DBus AddMatch "bogus='whatever'" >/tmp/dbus-match.out 2>&1
am_rc=$?
set -e
assert "Bad rule rejected (rc=$am_rc)" "$am_rc" -eq 1
case "$(cat /tmp/dbus-match.out)" in
    *MatchRuleInvalid*) assert "Error is MatchRuleInvalid" 0 -eq 0 ;;
    *) fail "Unexpected reply: $(cat /tmp/dbus-match.out)" ;;
esac

say "Unknown method on a Finit interface gets an org.freedesktop.DBus.Error.* reply"
set +e
texec "$CLIENT" unknown "$BUS"
unknown_rc=$?
set -e
assert "Unknown method returned an error (rc=$unknown_rc)" "$unknown_rc" -eq 0
