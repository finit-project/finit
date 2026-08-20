Finit Features
==============

This page highlights some of Finit's key features with examples and usage
scenarios. For complete documentation, configuration syntax, and advanced
options, see the [Configuration](config/index.md) section.

**Process Supervision**

Start, monitor and restart services should they fail.


**Getty**

Finit supports external getty but also comes with a limited built-in
Getty, useful for really small systems.  A getty sets up the TTY and
waits for user input before handing over to `/bin/login`, which is
responsible for handling the actual authentication.

```conf
tty tty1   { runlevel = "12345"  device = "/dev/tty1"     term = "linux"  nowait = true }
tty ttyAMA0 { runlevel = "12345"  device = "/dev/ttyAMA0"  term = "vt100"  noclear = true }
tty getty   { runlevel = "12345"  command = "/sbin/getty -L /dev/ttyAMA0 vt100" }
```

Users of embedded systems may want to enable automatic serial console
with the special `@console` device.  This works regardless whether the
system uses `ttyS0`, `ttyAMA0`, `ttyMXC0`, or anything else.  Finit
figures it out by querying sysfs: `/sys/class/tty/console/active`.

```conf
tty console { runlevel = "12345"  device = "@console"  term = "linux"  noclear = true }
```

Notice the optional `noclear`, `nowait`, and `nologin` flags.  The
latter is for skipping the login process entirely. For more information,
see the [TTY and Consoles](config/tty.md) section.


**Runlevels**

Support for SysV init-style [runlevels][5] is available, in the same
minimal style as everything else in Finit.  The `runlevel` setting
applies to service, task, run, and tty blocks alike.

Reserved runlevels are 0 and 6, halt and reboot, respectively just like
SysV init.  Runlevel 1 can be configured freely, but is recommended to
be kept as the system single-user runlevel since Finit will not start
networking here.  The configured `runlevel` from `/etc/finit.conf`
is what Finit changes to after bootstrap, unless 'single' (or 'S') is
given on the kernel cmdline, in which case runlevel 1 is started.

All services in runlevel S are started first, followed by the desired
run-time runlevel.  Run tasks in runlevel S can be started in sequence
by using a `run` block with `runlevel = "S"`.  Changing runlevels at
runtime is done like any other init, e.g. <kbd>init 4</kbd>, but also
using the more advanced [`initctl`](initctl.md) tool.


**Conditions**

As mentioned previously, Finit has an advanced dependency system to
handle synchronization, called [conditions](conditions.md).  It can
be used in many ways; depend on another service, network availability,
etc.

One *really cool* example useful for embedded systems is to run certain
scripts if a board has a certain feature encoded in its device tree.  At
bootstrap we run the following `ident` script:

```sh
#!/bin/sh
conddir=/var/run/finit/cond/hw/model
dtmodel=/sys/firmware/devicetree/base/model

if ! test -e $dtmodel; then
    exit 0
fi

model=$(cat $dtmodel | tr "[A-Z] " "[a-z]-")
mkdir -p $conddir && ln -s ../../reconf $conddir/$model
```

Provided the device tree node exists, and is a string, we can then use
the condition `<hw/model/foo>` when starting other scripts.  Here is an
example:

```
run ident {
    description = ""
    runlevel    = "S"
    command     = "/path/to/ident"
}
task foo-init {
    description = "Initializing Foo board"
    runlevel    = "2"
    conditions  = { "hw/model/foo" }
    command     = "/path/to/foo-init"
}
```

> [!TIP]
> Notice the trick with an empty description to hide the call to `ident`
> in the Finit progress output.


**Plugins**

Plugins can *extend* the functionality of Finit and *hook into* the
different stages of the boot process and at runtime.  Plugins are
written in C and compiled into a dynamic library loaded automatically by
finit at boot.  A basic set of plugins are bundled in the `plugins/`
directory.

Capabilities:

- **Hooks**  
  Hook into the boot at predefined points to extend Finit
- **I/O**  
  Listen to external events and control Finit behavior/services

Extensions and functionality not purely related to what an `/sbin/init`
needs to start a system are available as a set of plugins that either
hook into the boot process or respond to various I/O.

For more information, see the [Plugins](plugins.md) section.


**Automatic Reload**{ #automatic-reload }

By default, Finit monitors `/etc/finit.d/` and `/etc/finit.d/enabled/`
registering any changes to `.conf` files.  To activate a change the user
must call `initctl reload`, which reloads all modified files, stops any
removed services, starts new ones, and restarts any modified ones.  If the
command line arguments of a service have changed, the process will be
terminated and then started again with the updated arguments. If the arguments
have not been modified and the process supports SIGHUP, the process will
receive a SIGHUP rather than being terminated and started.

For some use-cases the extra step of calling `initctl reload` creates an
unnecessary overhead, which can be removed at build-time using:

    configure --enable-auto-reload


**Linux Capabilities**

Finit supports Linux capabilities, allowing services to run with minimal
required privileges instead of running as root. This improves security by
following the principle of least privilege.

```conf
service nginx {
    runlevel     = "2345"
    user         = "www-data"
    group        = "www-data"
    capabilities = { "^cap_net_bind_service" }
    command      = "/usr/sbin/nginx -g 'daemon off;'"
}
```

In this example, nginx runs as the unprivileged `www-data` user but retains
the ability to bind to privileged ports (80, 443) through the
`cap_net_bind_service` capability.

The `capabilities` list uses the IAB (Inheritable, Ambient, Bounding) format:
- `^` = Ambient (recommended) - capabilities survive exec()
- `%` = Inheritable only - requires file capabilities
- `!` = Bounding - block from acquiring capability

Multiple capabilities can be specified as comma-separated:

```conf
capabilities = { "^cap_net_raw", "^cap_net_admin", "!cap_sys_admin" }
```

See the [Linux Capabilities](config/capabilities.md) section for detailed
information, examples, and security best practices.


**PAM Sessions**

A service can run inside a PAM session, so the `session` stack in
`/etc/pam.d` applies to it, e.g. limits from `pam_limits`:

```conf
service weston {
    user    = "weston"
    pam     = "weston-autologin"
    command = "/usr/bin/weston --continue-without-input"
}
```

Without a `user` the session is for root.  Requires a build with PAM
support, which is the default; see `--disable-pam`.

See the [PAM Sessions](config/pam.md) section for the pam.d file the
example needs, and for how PAM and Finit settings interact.


**Supplementary Groups**

Finit supports supplementary groups for services, allowing them to access
resources owned by multiple groups without running as root. This complements
capabilities for fine-grained privilege control.

```conf
service @caddy:caddy,ssl-cert /usr/bin/caddy run
```

In this example, the Caddy web server runs as user `caddy` with primary group
`caddy`, but also has access to resources owned by the `ssl-cert` group (such
as TLS certificates).

Finit automatically reads the user's supplementary group membership from
`/etc/group`. Additional groups can be specified explicitly using the syntax
`@user:group,sup1,sup2,...`.

See the [Non-privileged Services](config/services.md#non-privileged-services)
section for more information.


**Cgroups**

Finit supports cgroups v2 and comes with the following default groups in
which services and user sessions are placed in:

     /sys/fs/cgroup
       |-- init/               # cpu.weight:100
       |-- system/             # cpu.weight:9800
       `-- user/               # cpu.weight:100

Finit itself and its helper scripts and services are placed in the
top-level leaf-node group `init/`, which also is _reserved_.

All run/task/service/sysv processes are placed in their own sub-group
in `system/`.  The name of each sub-group is taken from the respective
`.conf` file from `/etc/finit.d`.

All getty/tty processes are placed in their own sub-group in `user/`.
The name of each sub-group is taken from the username.

A fourth group also exists, the `root` group.  It is also _reserved_ and
primarily intended for RT tasks.  If you have RT tasks they need to be
declared as such in their service block like this:

    service foo {
        cgroup root {}
        command = "/path/to/foo args"
    }

Every block names the group it joins, so a second RT task says so too:

    service bar {
        cgroup root {}
        command = "/path/to/bar args"
    }

See the [Cgroups](config/cgroups.md) section for more information, e.g.,
how to configure per-group limits.

The `initctl` tool has three commands to help debug and optimize the
setup and monitoring of cgroups.  See the `ps`, `top`, and `cgroup`
commands for details.

> [!NOTE]
> Systems that do not support cgroups, specifically version 2, are
> automatically detected.  On such systems the above functionality is
> disabled early at boot.


**Service Management**

Finit includes the `initctl` tool for managing services and system state at
runtime. Key capabilities include:

- **Enable/Disable services**: Manage which services start at boot by moving
  configuration files between `/etc/finit.d/available` and
  `/etc/finit.d/enabled`
- **Start/Stop/Restart**: Control individual services without requiring a
  full system reboot
- **Status monitoring**: View service state, PID, uptime, and resource usage
- **Condition management**: Set and clear user-defined conditions to control
  service dependencies
- **Cgroup monitoring**: Real-time process and resource monitoring with
  `initctl top`, similar to the traditional `top` command but cgroup-aware

Example commands:

```bash
initctl enable myservice          # Enable service for next boot
initctl start myservice           # Start service now
initctl status                    # Show all services
initctl top                       # Interactive resource monitor
initctl cond set usr/custom       # Set custom condition
```

`initctl` rides Finit's built-in [D-Bus API](dbus.md) when available,
which is also open to any other bus client, including `dbus-send` and
language bindings.

See the [Commands & Status](initctl.md) section for complete documentation.


**Rescue Mode**

Finit provides a built-in rescue mode for system recovery and maintenance.
When booting with the `rescue` kernel parameter, the system enters a
protected maintenance shell.

If the bundled `sulogin` program is available (from Finit, util-linux, or
BusyBox), you'll be prompted for the root password before accessing the
maintenance shell. This provides secure access for system recovery.

If `sulogin` is not available, Finit falls back to reading
`/lib/finit/rescue.conf` and boots the system in a limited maintenance mode.

```
# Kernel command line
linux /vmlinuz root=/dev/sda1 rescue
```

In rescue mode, `initctl` will not work. After fixing the problem, use
`reboot -f` to force reboot.

Rescue mode can be disabled at build time with `configure --without-rescue`.

See the [Rescue Mode](config/rescue.md) section for more information.


**Switch Root**

Finit supports switching from an initramfs to a real root filesystem using
the built-in `initctl switch-root` command.  This allows Finit to serve as
the init system in an initramfs for early boot tasks (LUKS unlock, LVM
activation, network boot) before transitioning to the real root.

```bash
# In initramfs, after mounting the real root:
initctl switch-root /mnt/root
```

The switch-root operation:

1. Runs the `HOOK_SWITCH_ROOT` hook for cleanup
2. Stops all services gracefully
3. Moves virtual filesystems (`/dev`, `/proc`, `/sys`, `/run`) to the new root
4. Deletes initramfs contents to free memory
5. Pivots to the new root and execs the new init

See the [Switch Root](switchroot.md) section for complete documentation.


[5]: https://en.wikipedia.org/wiki/Runlevel
