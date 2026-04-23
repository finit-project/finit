Switch Root
===========

Finit supports switching from an initramfs to a real root filesystem
using the `initctl switch-root` command.  This is useful for systems
that use an initramfs for early boot (LUKS, LVM, network boot, etc.)
and need to transition to the real root before starting services.


Usage
-----

```sh
initctl switch-root NEWROOT [INIT]
```

- `NEWROOT`: Path to the mounted new root filesystem (e.g., `/mnt/root`)
- `INIT`: Optional path to init on the new root (default: `/sbin/init`)


Requirements
------------

1. Must be run during runlevel S (bootstrap) or runlevel 1
2. `NEWROOT` must be a mount point (different device than /)
3. `INIT` must exist and be executable on the new root
4. Finit must be running as PID 1 (in initramfs)


How It Works
------------

1. Runs `HOOK_SWITCH_ROOT` for any cleanup scripts/plugins
2. Runs `HOOK_SHUTDOWN` to notify plugins
3. Stops all services and kills remaining processes
4. Exits all plugins gracefully
5. Moves `/dev`, `/proc`, `/sys`, `/run` to new root
6. Deletes initramfs contents (if on tmpfs/ramfs) to free memory
7. Moves new root mount to `/`
8. Chroots to new root
9. Reopens `/dev/console` for stdin/stdout/stderr
10. Execs new init as PID 1


Example: Initramfs finit.conf
-----------------------------

Configuration file `/etc/finit.conf` in the initramfs:

```
# /etc/finit.conf in initramfs

# Mount the real root filesystem
run [S] name:mount-root /bin/mount /dev/sda1 /mnt/root -- Mounting root filesystem

# Switch to real root after mount completes
run [S] name:switch-root /sbin/initctl switch-root /mnt/root -- Switching to real root
```

For more complex setups (LUKS, LVM, etc.):

```
# Unlock LUKS volume
# The tty:@console stanza is required so cryptsetup can prompt for a passphrase
run [S] name:cryptsetup tty:@console /sbin/cryptsetup open /dev/sda2 cryptroot -- Unlocking encrypted root

# Activate LVM
run [S] name:lvm /sbin/lvm vgchange -ay -- Activating LVM volumes

# Mount root
run [S] name:mount-root /bin/mount /dev/vg0/root /mnt/root -- Mounting root

# Switch root
run [S] name:switch-root /sbin/initctl switch-root /mnt/root -- Switching to real root
```


Example: Using Runlevel 1 for Switch Root
-----------------------------------------

For more complex initramfs setups where ordering of tasks becomes
difficult in runlevel S, you can perform the switch-root in runlevel 1:

```
# /etc/finit.conf in initramfs

# Start mdevd for device handling
service [S] name:mdevd notify:s6 /sbin/mdevd -D %n -- Device event daemon
run [S] name:coldplug <service/mdevd/ready> /sbin/mdevd-coldplug -- Coldplug devices

# Mount the real root filesystem (after devices are ready)
run [S] name:mount-root <run/coldplug/success> /bin/mount /dev/sda1 /mnt/root -- Mounting root

# Transition to runlevel 1 after all S tasks complete
# The switch-root runs cleanly in runlevel 1
run [1] name:switch-root /sbin/initctl switch-root /mnt/root -- Switching to real root
```

This approach separates the initramfs setup (runlevel S) from the
switch-root operation (runlevel 1), making task ordering simpler.


Hooks
-----

The `HOOK_SWITCH_ROOT` hook runs before the switch begins.  Use it for:

- Saving state to the new root
- Unmounting initramfs-only mounts
- Cleanup tasks

Plugins can register for `HOOK_SWITCH_ROOT` just like other hooks:

```c
static void my_switch_root_hook(void *arg)
{
    /* Cleanup before switch_root */
}

static plugin_t plugin = {
    .name = "my-plugin",
    .hook[HOOK_SWITCH_ROOT] = {
        .cb = my_switch_root_hook
    }
};

PLUGIN_INIT(plugin_init)
{
    plugin_register(&plugin);
}
```


Conditions
----------

After switch_root, the new finit instance starts fresh.  No conditions
or state are preserved across the switch.  The new finit will:

1. Re-read `/etc/finit.conf` from the new root
2. Re-initialize all conditions
3. Start services according to the new configuration


See Also
--------

- [switch_root(8)](https://man7.org/linux/man-pages/man8/switch_root.8.html) - util-linux switch_root utility
- [Kernel initramfs documentation](https://docs.kernel.org/filesystems/ramfs-rootfs-initramfs.html)
