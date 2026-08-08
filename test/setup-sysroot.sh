#!/bin/sh

set -eu

# shellcheck disable=SC2154
make -C "$top_builddir" DESTDIR="$SYSROOT" install

mkdir -p "$SYSROOT/sbin/"
cp "$top_builddir/test/src/serv" "$SYSROOT/sbin/"
if [ -x "$top_builddir/test/src/dbus-auth-client" ]; then
	cp "$top_builddir/test/src/dbus-auth-client" "$SYSROOT/sbin/"
fi

# shellcheck disable=SC2154
FINITBIN="$(pwd)/$top_builddir/src/finit" DEST="$SYSROOT" make -f "$srcdir/lib/sysroot.mk"

# Drop plugins we don't need in test, only causes confusing FAIL in logs.
for plugin in tty.so urandom.so rtc.so modprobe.so; do
    find "$SYSROOT" -name $plugin -delete
done

# Drop system .conf files we don't need in test, same as above
# shellcheck disable=SC2043
for conf in 10-hotplug.conf; do
    find "$SYSROOT" -name $conf -delete
done

# Update dynamic linker cache for /usr/local/lib libraries
ldconfig -r "$SYSROOT" || echo "Warning: ldconfig failed with exit code $?"
