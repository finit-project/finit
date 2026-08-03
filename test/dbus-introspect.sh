#!/bin/sh
# libink: introspection XML well-formedness.
#
# Covers compound type signatures in generated introspection XML:
# Cond1.Dump declares out_sig "a(ss)", which must appear as a single
# <arg>, not one <arg> per signature character.

set -eu

TEST_DIR=$(dirname "$0")

# shellcheck source=/dev/null
. "$TEST_DIR/lib/setup.sh"
# shellcheck source=/dev/null
. "$TEST_DIR/lib/dbus-setup.sh"

say "Introspect on /org/finit/cond"
xml=$(texec "$CLIENT" introspect "$BUS" /org/finit/cond)

say "Cond1.Dump advertises a single a(ss) out arg"
case "$xml" in
    *'<arg type="a(ss)" direction="out"/>'*) assert "a(ss) intact" 0 -eq 0 ;;
    *) fail "a(ss) not found as a single arg" ;;
esac

say "No per-character type fragments in the XML"
case "$xml" in
    *'type="("'* | *'type=")"'* | *'type="{"'* | *'type="}"'* | *'type="a"'*)
        fail "per-character <arg> fragment leaked" ;;
    *) assert "no bracket/array fragments" 0 -eq 0 ;;
esac
