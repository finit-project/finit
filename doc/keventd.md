Bundled Device Manager
======================

The kernel event daemon `keventd` is a built-in device manager bundled
with Finit.  It replaces the need for external device managers like
mdev, mdevd, or udevd on systems where a lighter-weight solution is
preferred, particularly on embedded systems.

It is enabled by default since Finit v5.  To disable it and use an
external device manager instead: `./configure --without-keventd`


Features
--------

When started, keventd listens on a `NETLINK_KOBJECT_UEVENT` socket for
kernel events and handles:

- **Device node creation**: creates and removes `/dev` nodes with
  correct permissions on device add/remove events
- **Persistent symlinks**: creates `/dev/disk/by-id/`, `/dev/disk/by-path/`,
  and `/dev/input/by-id/`, `/dev/input/by-path/` symlinks for stable
  device naming
- **Firmware loading**: responds to kernel firmware requests by searching
  `/lib/firmware/` and writing firmware data to sysfs
- **Module loading**: parses `MODALIAS` from uevents and spawns `modprobe`
  to load the appropriate kernel module
- **Coldplug**: with the `-c` flag, walks `/sys/devices` and triggers
  add events for all devices present at boot
- **Power supply monitoring**: tracks AC power status and provides the
  `sys/pwr/ac` condition
- **Device conditions**: sets `dev/*` conditions in the Finit condition
  system when device nodes appear or disappear


Device Nodes
------------

On receiving an `add` event with `MAJOR`, `MINOR`, and `DEVNAME`
fields, keventd creates the corresponding device node in `/dev` using
`mknod()`.  Parent directories are created automatically (e.g.,
`/dev/input/` for `/dev/input/event0`).

On `remove` events, the device node and its associated symlinks and
conditions are cleaned up.

### Default Permissions

keventd applies permissions based on built-in rules that match on
device subsystem and name:

| Subsystem     | Pattern      | Mode   | Owner:Group    |
|---------------|-------------|--------|----------------|
| block         | sd*, vd*, nvme*, mmcblk*, loop*, dm-*, md* | 0660 | root:disk |
| tty           | tty[0-9]*   | 0620   | root:tty       |
| tty           | ttyS*, ttyUSB*, ttyACM* | 0660 | root:dialout |
| input         | event*, mouse*, mice | 0660 | root:root |
| sound         | *           | 0660   | root:audio     |
| video4linux   | *           | 0660   | root:video     |
| drm           | card*, render* | 0660 | root:video     |
| (any)         | null, zero, full, random, urandom | 0666 | root:root |
| (any)         | console     | 0600   | root:root      |
| (default)     |             | 0660   | root:root      |


Persistent Symlinks
-------------------

For block devices, keventd creates symlinks under `/dev/disk/`:

- **by-id**: based on the device serial number and model, read from
  sysfs attributes (`/sys/.../device/vendor`, `model`, `serial`)
- **by-path**: based on the device topology path

For input devices, symlinks are created under `/dev/input/`:

- **by-id**: based on the device name from sysfs
- **by-path**: based on the physical device path

These symlinks are tracked internally and automatically removed when the
corresponding device is unplugged.


Firmware Loading
----------------

When a kernel driver requests firmware (via `request_firmware()`), the
kernel sends a uevent with a `FIRMWARE=` field.  keventd handles this
by:

1. Searching for the firmware file in order:
   - `/lib/firmware/updates/<kernel-version>/<name>`
   - `/lib/firmware/updates/<name>`
   - `/lib/firmware/<kernel-version>/<name>`
   - `/lib/firmware/<name>`
2. Writing `1` to `/sys/<devpath>/loading` to signal start
3. Copying the firmware data to `/sys/<devpath>/data`
4. Writing `0` to `/sys/<devpath>/loading` on success (or `-1` on failure)

This is particularly important early in boot when drivers for graphics
cards, network adapters, and other hardware need firmware before they
can operate.


Module Loading
--------------

When a device add event includes a `MODALIAS` field, keventd spawns
`modprobe -bq <modalias>` to load the matching kernel module.  Module
loading is done asynchronously (keventd does not wait for modprobe to
complete) to avoid blocking other event processing.


Coldplug
--------

To handle devices that were present before keventd started, it supports
a coldplug mode activated with the `-c` flag.  This walks the entire
`/sys/devices` tree and writes `add` to each `uevent` file, causing the
kernel to re-emit add events for all existing devices.

This replaces the separate `coldplug` script previously used with mdev.


Conditions
----------

keventd provides conditions in two namespaces:

### Device Conditions (`dev/`)

When a device node is created, keventd asserts a corresponding condition
in `/run/finit/cond/dev/`.  This allows services to wait for specific
devices:

    service [2345] <dev/sda>  /usr/sbin/mdadm --monitor /dev/md0 -- RAID monitor
    service [2345] <dev/ttyUSB0> /usr/sbin/gps-daemon -- GPS daemon

When the device is removed, the condition is cleared and Finit stops
the dependent services.

### Power Supply Conditions (`sys/pwr/`)

keventd monitors the `power_supply` subsystem and provides:

- `sys/pwr/ac` -- asserted when AC power is connected

This is useful for preventing power-hungry services from running on
battery:

    service [2345] <sys/pwr/ac,pid/syslogd> cron -f -- Cron daemon


Usage
-----

    keventd [-cdhnv]

    Options:
      -c        Run coldplug at startup
      -d        Enable debug mode (foreground, verbose)
      -h        Show help text
      -n        Run in foreground (no daemon)
      -v        Show version

In normal operation, Finit starts keventd automatically via its system
configuration.  The `-d` flag is useful for debugging device issues --
it runs keventd in the foreground and logs all received uevents.

Debug logging can also be toggled at runtime by sending `SIGUSR1`:

    kill -USR1 $(pidof keventd)


Integration with Finit
----------------------

keventd is a standalone daemon started by Finit as an internal service.
It communicates with Finit exclusively through the filesystem-based
condition system -- creating and removing symlinks in `/run/finit/cond/`.

This means keventd can also be tested independently:

    # Run in debug mode to see all kernel events
    keventd -d

    # Run with coldplug to populate /dev from scratch
    keventd -c -n

When keventd is enabled, it conflicts with external device managers.
Only one device manager should be active at a time.  The system
configuration uses the `conflict:` directive to enforce this:

    service conflict:udevd,mdevd,mdev [...] keventd -c -- Finit device manager
