Finit Test Suite
================

Finit comes with a set of tests and a small framework for running them.
Contributors are encouraged to write new tests when implementing features, or
fixing bugs.

Each test is run in isolation, in it's own namespace. Finit will therefore
be able to be launched as PID 1. Since it's also running with it's own root
directory it will be able to function properly without having any super user
privileges in the host environment.


Requirements
------------

On Debian, Ubuntu, and Linux Mint, install the build dependencies and
the tools the tests use:

    sudo apt install build-essential autoconf automake libtool pkg-config \
                     libconfuse-dev libblkid-dev libcap-dev libpam0g-dev  \
                     uidmap jq wget dbus shellcheck

  * `uidmap` has `newuidmap` and `newgidmap`, which `unshare` needs to
    set up the namespace of each test.  Without it every test fails with
    `unshare: failed to execute newuidmap`.  Your user also needs a range
    in `/etc/subuid` and `/etc/subgid`, which `adduser` sets up
  * `jq` is used by the tests that read `initctl -j`
  * `wget` fetches the BusyBox binary for the test root, on the first run
  * `dbus` has the `dbus-daemon` and `dbus-send` that the D-Bus broker
    test stages in the test root, without them that test is skipped
  * `shellcheck` is used by the `checkself.sh` test, which checks the
    test scripts themselves
  * `libcap-dev` and `libpam0g-dev` are optional for Finit.  Without
    the latter the PAM session test is skipped

Finit also needs [libuEv][] v2.4.1 and [libite][] v2.6.1, or later.  The
`libuev-dev` and `libite-dev` packages may be older, check with:

    apt-cache policy libuev-dev libite-dev

In Ubuntu 24.04, `libuev-dev` is new enough but `libite-dev` is not, so
libite has to be built and installed from source, see the [build
instructions](../doc/build.md).

[libuEv]: https://github.com/troglobit/libuev
[libite]: https://github.com/troglobit/libite


Running tests
-------------

To run the test suite, first [build](../doc/build.md) Finit, e.g:

    ./configure --prefix=/usr --exec-prefix= --sysconfdir=/etc --localstatedir=/var --enable-testserv-plugin
    make -j9 clean all

Then run (parallel does not work atm):

    make check

`make check` will set up the required assets for the test environment, and then
run the full set of tests. The environment is not removed afterwards so at
this point individual tests can be executed without having to run the entire
test suite, which is handy when developing new tests or debugging existing
test. To execute an individual test, simply invoke the script containing it:

    ./test/name-of-the-test.sh

Another way to run a single (or more) test(s) is to define the `TESTS`
environment variable:

    TESTS="start-kill-service" make check
