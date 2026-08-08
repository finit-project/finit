Building Finit
==============

Finit comes with a traditional configure script to control features and
optional plugins to enable.  It depends on three external libraries:

- [libuEv][], the event loop
- [libite][] (-lite), much needed frog DNA
- [libConfuse][], the parser behind the .conf format

> [!IMPORTANT]
> Most free/open source software packages that use `configure` default
> to install to `/usr/local`.  However, some Linux distributions do no
> longer search that path for installed software, e.g. Fedora and Alpine
> Linux.  To get finit's configure script to find its dependencies you
> have to help the `pkg-config` tool a bit if you do not change the
> default prefix path:
>
>     PKG_CONFIG_LIBDIR=/usr/local/lib/pkgconfig ./configure

The configure script checks for all dependencies, including the correct
version of the above mentioned libraries.  Currently required versions:

- libite v2.2.0, or later
- libuEv v2.2.0, or later
- libConfuse v3.3, or later


Configure
---------

Below are a few of the main switches to configure:

* `--prefix=..`: Usually you want to set this to `/usr`, default is the GNU
  default: `/usr/local`

* `--exec-prefix=..`: This you want to set to the empty string, or `/`, to
  ensure the programs `finit` and `initctl` are installed to the proper
  locations.  Linux expects an "init" in `/sbin`, default: `--prefix`

* `--sysconfdir=..`: follows `--prefix`, you likely want it to be `/etc`

* `--localstatedir=..`: follows `--prefix`, you likely want `/var`

* `--enable-static`: Build Finit statically.  The plugins will be
  built-ins (.o files) and all external libraries, except the C library
  will be linked statically.

* `--enable-kernel-cmdline`: Enable Finit pre-4.1 parsing of init args from
  `/proc/cmdline`, this is *not recommended* since Finit may be running as the
  init for container apps that can see the host's `/proc` filesystem

* `--disable-dbus`: Opt out of Finit's built-in D-Bus support, enabled by
  default.  See [D-Bus Integration](dbus.md) for what it provides.  Not to
  be confused with `--enable-dbus-plugin` below, which only starts an
  external `dbus-daemon`

* `--enable-alsa-utils-plugin`: Enable the optional `alsa-utils.so` sound plugin.

* `--enable-dbus-plugin`: Enable the optional D-Bus `dbus.so` plugin, which
  launches `dbus-daemon` at boot.  Unrelated to the built-in bus, see
  `--disable-dbus` above.

* `--enable-resolvconf-plugin`: Enable the `resolvconf.so` optional plugin.

* `--enable-x11-common-plugin`: Enable the optional X Window `x11-common.so` plugin.

* `--with-sulogin`: Enable bundled `sulogin` program.  Default is to use the
  system `sulogin(8)`.  The sulogin shipped with Finit *allows password-less*
  login if the `root` user is disabled or has no password at all.

For more configure flags, see <kbd>./configure --help</kbd>

> [!NOTE]
> The configure script is not available in the GIT sources.  It is
> however included in (officially supported) released tarballs.  The
> idea is that you should not need GNU autotools to build, only the
> above mentioned dependencies, a POSIX shell, a C compiler and make.
> Any contributing to Finit can generate it from `configure.ac` using
> the `autogen.sh` script.


Example
-------

First, unpack the archive:

```shell
$ tar xf finit-4.3.tar.gz
$ cd finit-4.3/
```

Then configure, build and install:

```shell
$ ./configure --prefix=/usr                 --exec-prefix=         \
              --sysconfdir=/etc             --localstatedir=/var   \
              --with-keventd                --with-watchdog
$ make
.
.
.
$ DESTDIR=/tmp/finit make install
```

In this example the [finit-4.3.tar.gz][1] archive is unpacked to the
user's home directory, configured, built and installed to a temporary
staging directory.  The environment variable `DESTDIR` controls the
destination directory when installing, very useful for building binary
standalone packages.

Finit 4.1 and later can detect if it runs on an embedded system, or a
system that use BusyBox tools instead of udev & C:o.  On such systems
`mdev` instead of `udev` is used.  However, remember to also change the
Linux config to:

    CONFIG_UEVENT_HELPER_PATH="/sbin/mdev"

> [!TIP]
> If you run into problems starting Finit, take a look at `finit.c`.
> One of the most common problems is a custom Linux kernel build that
> lack `CONFIG_DEVTMPFS`.  Another is too much cruft in the system
> `/etc/fstab`.


Running
-------

Having successfully built Finit it is now be time to take it for a test
drive.  The `make install` attempts to set up finit as the system system
init, `/sbin/init`, but this is usually a symlink pointing to the
current init.

So either change the symlink, or change your boot loader (GRUB, LOADLIN,
LILO, U-Boot/Barebox or RedBoot) configuration to append the following
to the kernel command line:

```shell
append="init=/sbin/finit"
```

Remember to also set up an initial `/etc/finit.conf` before rebooting!


Recovery
--------

To rescue a system with Finit, append the following to the kernel
command line:

```shell
append="init=/sbin/finit rescue"
```

This tells Finit to start in a very limited recovery mode, no services
are loaded, no filesystems are mounted or checked, and no networking is
enabled.  The default Finit rescue mode configuration is installed into
`/lib/finit/rescue.conf`, which can be safely removed or changed.

By default the a root shell, without login, is started.

> [!IMPORTANT]
> In rescue mode `initctl` will not work, the same goes for `reboot`,
> `shutdown`, and `poweroff` commands, provided they are the Finit
> versions of these commands.  Use the `-f` flag to force the action.


Debugging
---------

Edit, or append to, the kernel command line: remove `quiet` to enable
kernel messages and add `finit.debug` to enable Finit debug messages.

```shell
append="init=/sbin/finit -- finit.debug"
```

Notice the `--` separator.

To debug startup issues, in particular issues with getty/login, add
the following to your Finit .conf file:

    tty board {
        runlevel = "12345789"
        notty    = true
        noclear  = true
    }

The `notty` option ensures reusing the stdin/stdout set up by the
kernel.  Remember, this is only for debugging and would leave your
production system potentially wide open.

There is also a rescue shell available, in case Finit crashes and the
kernel usually reboots: `configure --enable-emergency-shell`.  However,
the behavior of Finit is severely limited when this is enabled, so use
it only for debugging start up issues when Finit crashes.

> [!CAUTION]
> None of these options should be enabled on production systems since
> they can potentially give a user root access.

[1]:       https://github.com/finit-project/finit/releases/download/4.3/finit-4.3.tar.gz
[libuEv]:  https://github.com/troglobit/libuev
[libite]:  https://github.com/troglobit/libite
[libConfuse]: https://github.com/libconfuse/libconfuse
