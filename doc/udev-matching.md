# How udev rules work

## Summary of the complete fix

- hardware.c: Write authorized_default=1 on the bus path before nftw
  runs (just 2 lines added). This exploits the fact that apath already
  contains path/authorized_default at that point (set by the snprintf on
  line 71). With authorized_default=1 set on the root hub, any device
  that appears behind an intermediate hub during hub enumeration gets
  auto-authorized by the kernel.
- 70-usb-authorize.rules: Belt-and-suspenders for the async case. If hub
  port probing is slow enough that children appear after nftw has
  already returned, udev sees the add event with authorized=0, walks up
  the parent chain with ATTRS{authorized_default}=="1", and authorizes
  the device. Locked buses (authorized_default=0) are correctly skipped.

```
ACTION=="add", SUBSYSTEM=="usb", ENV{DEVTYPE}=="usb_device", \
    ATTR{authorized}=="0", \
    ATTRS{authorized_default}=="1", \
    RUN+="/bin/sh -c 'echo 1 > /sys%p/authorized'"
```

  This keeps authorized_default=2 (deny by default) fully intact — the
  security window stays closed. The udev rule only fires when confd has
  explicitly marked a bus as unlocked.

## Comment from Undersigned

Very interesting, I did not know you could do such complex operations
with udev rules. Could you explain a bit more in detail how the matching
works and how we can guarantee locked buses/ports are not accidentally unlocked?

> Sure. Let's walk through it step by step.

## How udev ATTRS{} matching works

A udev rule matches against a device and its entire parent chain in the
sysfs device tree. When a device like 2-1.4 (the keyboard) is added, its
sysfs hierarchy looks like:

```
/sys/devices/.../0000:01:00.0/usb2/           ← root hub (usbN)
                              usb2/2-1/       ← VIA Labs hub
                              usb2/2-1/2-1.4/ ← keyboard ← event fires here
```

- ATTR{} (no trailing S) — matches attributes on the device itself only
- ATTRS{} (with S) — matches attributes on the device or any of its
  parents, walking up the tree until it finds a match or runs out of
  parents

So ATTRS{authorized_default}=="1" on a keyboard event at 2-1.4 walks:

1. 2-1.4/authorized_default — doesn't exist (not a hub/controller)
2. 2-1/authorized_default — doesn't exist (downstream hubs don't have
   this attribute, only root hubs do)
3. usb2/authorized_default — exists, check its value

This is exactly the right level: authorized_default only lives on root
hubs (usbN), which is precisely where confd writes.

## Why locked buses can't be accidentally unlocked

The invariant is: confd owns `authorized_default`. It sets it to 0
(locked) or 1 (unlocked). The udev rule only reads it, never writes it.

Walk through the locked case:

```
confd sets usb2/authorized_default = 0   ← locked
```

A device plugs into usb2. udev fires:

1. ATTR{authorized}=="0" — matches (device is unauthorized)
2. ATTRS{authorized_default}=="1" — walks up to usb2, finds 0 → no match
3. Rule doesn't fire. Device stays denied. ✓

For a device behind an intermediate hub on a locked bus:

```
usb2/authorized_default = 0              ← bus locked
usb2/2-1/                                ← hub (somehow authorized)
usb2/2-1/2-1.4/                          ← keyboard
```

Even if the hub itself were authorized somehow, the keyboard's parent
chain still reaches `usb2/authorized_default = 0` before finding any
`authorized_default = 1`. The rule doesn't fire. ✓

The only remaining question: what if two buses exist and one is locked?

Say usb1 is unlocked and usb2 is locked. A device on usb2 fires a udev
event. ATTRS walks up: `usb2/authorized_default = 0` — stops there (once
it finds the attribute it stops).  It does not continue up to PCIe or
platform buses looking for usb1's attribute. Each USB device's parent
chain only goes through its own root hub.

This is because authorized_default is found at usb2 — udev stops as soon
as it matches the attribute name, regardless of value. If the value
doesn't match the condition, the whole rule fails. It doesn't continue
looking at other buses.

## Summary of the guarantee

```
┌───────────────────────┬─────────────────────────┬─────────────────────────┐
│       Scenario        │ usb2/authorized_default │       Rule fires?       │
├───────────────────────┼─────────────────────────┼─────────────────────────┤
│ Bus unlocked by confd │ 1                       │ Yes → device authorized │
├───────────────────────┼─────────────────────────┼─────────────────────────┤
│ Bus locked by confd   │ 0                       │ No → device denied      │
├───────────────────────┼─────────────────────────┼─────────────────────────┤
│ Bus at kernel default │ 2                       │ No → device denied      │
├───────────────────────┼─────────────────────────┼─────────────────────────┤
│ Bus doesn't exist yet │ —                       │ No → no match           │
└───────────────────────┴─────────────────────────┴─────────────────────────┘
```

The rule is purely reactive: it can only authorize devices on buses that
confd has already explicitly declared unlocked. It has no ability to
override a lock.
