#!/bin/sh

set -eu

echo "=== Finit Test Sysroot Setup ==="
echo "Date: $(date)"
echo "SYSROOT: $SYSROOT"
echo "top_builddir: $top_builddir"
echo "srcdir: $srcdir"
echo "================================"
echo

# shellcheck disable=SC2154
make -C "$top_builddir" DESTDIR="$SYSROOT" install

mkdir -p "$SYSROOT/sbin/"
cp "$top_builddir/test/src/serv" "$SYSROOT/sbin/"
if [ -x "$top_builddir/test/src/dbus-auth-client" ]; then
    cp "$top_builddir/test/src/dbus-auth-client" "$SYSROOT/sbin/"
fi

# shellcheck disable=SC2154
# Prefer the real ELF in .libs/ over the libtool wrapper script at
# $top_builddir/src/finit.  Libtool generates a shell wrapper when
# the binary depends on an in-tree convenience library (e.g. libink),
# and `ldd <wrapper>` returns "not a dynamic executable", which
# silently makes sysroot.mk copy zero host libs into the sysroot.
if [ -f "$top_builddir/src/.libs/finit" ]; then
    finitbin_for_ldd="$(pwd)/$top_builddir/src/.libs/finit"
else
    finitbin_for_ldd="$(pwd)/$top_builddir/src/finit"
fi
FINITBIN="$finitbin_for_ldd" DEST="$SYSROOT" make -f "$srcdir/lib/sysroot.mk"

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
echo "Running ldconfig in sysroot: $SYSROOT"
echo "Contents of $SYSROOT/etc/ld.so.conf:"
cat "$SYSROOT/etc/ld.so.conf" || echo "Warning: ld.so.conf not found"
echo "Libraries in $SYSROOT/usr/local/lib:"
ls -la "$SYSROOT/usr/local/lib/" 2>/dev/null || echo "Warning: /usr/local/lib not found in sysroot"
ldconfig -v -r "$SYSROOT" || echo "Warning: ldconfig failed with exit code $?"
echo "Verifying ldconfig cache was created:"
ls -la "$SYSROOT/etc/ld.so.cache" || echo "Warning: ld.so.cache not created"
