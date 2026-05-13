#!/bin/sh
# Run test suite with the correct configure params
run_make=1
jobs=17

while [ $# -gt 0 ]; do
    case "$1" in
	-n|--no-make)
	    run_make=0
	    ;;
	-j|--jobs)
	    shift
	    jobs="$1"
	    ;;
	*)
	    echo "Usage: $0 [--no-make] [-j N]"
	    exit 1
	    ;;
    esac
    shift
done

if [ "$run_make" -eq 1 ]; then
    make distclean
fi

./configure --prefix=/usr --exec-prefix= --sysconfdir=/etc --localstatedir=/var	\
	    --enable-dbus --enable-x11-common-plugin --enable-testserv-plugin   \
	    --with-watchdog --with-keventd --with-libsystemd                    \
	    CFLAGS='-fsanitize=address -ggdb'

if [ "$run_make" -eq 1 ]; then
    make -j"$jobs" clean check
fi
