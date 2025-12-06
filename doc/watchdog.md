Bundled Watchdog Daemon
=======================

When built `--with-watchdog` a separate service is built and installed
in `/libexec/finit/watchdogd`.  If this exists at runtime, and the WDT
device node exists, Finit will start it and treat it as the elected
watchdog service to delegate its reboot to.  This delegation is to
ensure that the system is rebooted by a hardware watchdog timer -- on
many embedded systems this is crucial to ensure all circuits on the
board are properly reset for the next boot, in effect ensuring the
system works the same after both a power-on and reboot event.

> [!NOTE]
> The watchdog reboot delegation can be enabled with the `reboot-watchdog`
> configuration option in `/etc/finit.conf`.  By default this is disabled
> and the system reboots directly via the SoC using the kernel's `reboot(2)`
> syscall.  See [Runlevels](config/runlevels.md) for details.

The delegation is performed at the very last steps of system shutdown,
if reboot has been selected, `reboot-watchdog` is enabled, and an elected
watchdog is known.  First a `SIGPWR` is sent to advise watchdogd of the
pending reboot.  Then, when the necessary steps of preparing the system
for shutdown (umount etc.) are completed, Finit sends `SIGTERM` to
watchdogd and puts itself in a 10 sec timeout loop waiting for the WDT
to reset the board.  If a reset is not done before the timeout, Finit
falls back to `reboot(RB_AUTOBOOT)` which tells the kernel to do the
reboot.

An external watchdog service can also be used.  The more advanced cousin
[watchdogd](https://github.com/troglobit/watchdogd/) is the recommended
option here.  It can register itself with Finit using the same IPC as
`initctl`.  If the bundled watchdogd is running a hand-over takes place,
so it's safe to have both services installed on a system.  For the
hand-over to work it requires that the WDT driver supports the safe exit
functionality where `"V"` is written to the device before closing the
device descriptor.  If the kernel driver has been built without this,
the only option is to remove `/libexec/finit/watchdogd` or build without
it at configure time.
