AM_CPPFLAGS        = -D_XOPEN_SOURCE=600 -D_BSD_SOURCE -D_GNU_SOURCE -D_DEFAULT_SOURCE
AM_CPPFLAGS       += -I$(top_srcdir)/src

pkglibexec_PROGRAMS = keventd

keventd_SOURCES    = keventd.c keventd.h uevent.c \
		     udevdb.c udevdb.h \
		     sysfs.c sysfs.h \
		     rules.c rules.h \
		     builtin.c builtin.h \
		     $(top_srcdir)/src/util.c $(top_srcdir)/src/util.h
keventd_CFLAGS     = -W -Wall -Wextra -std=gnu99
# Silence noisy false positives from PATH_MAX-into-PATH_MAX sysfs path
# concatenations; real concerns (e.g. USB strings into small buffers) are
# handled via explicit checks where present.  Matches systemd-udev policy.
keventd_CFLAGS    += -Wno-format-truncation
keventd_CFLAGS    += $(lite_CFLAGS)
keventd_CFLAGS    += $(blkid_CFLAGS)
keventd_LDADD      = $(lite_LIBS)
keventd_LDADD     += $(blkid_LIBS)

# Curated udev rules derived from eudev 3.2.14 (GPL-2.0-or-later).
# Installed to /lib/udev/rules.d/ so existing third-party rules and
# local overrides under /etc/udev/rules.d/ coexist with standard udev
# precedence.  See .notes/curated-rules-manifest.md.
if UDEV_RULES
udevrulesdir       = $(prefix)/lib/udev/rules.d
dist_udevrules_DATA = \
	rules.d/50-udev-default.rules \
	rules.d/60-autosuspend.rules \
	rules.d/60-block.rules \
	rules.d/60-cdrom_id.rules \
	rules.d/60-drm.rules \
	rules.d/60-evdev.rules \
	rules.d/60-fido-id.rules \
	rules.d/60-input-id.rules \
	rules.d/60-persistent-alsa.rules \
	rules.d/60-persistent-input.rules \
	rules.d/60-persistent-storage.rules \
	rules.d/60-persistent-storage-tape.rules \
	rules.d/60-persistent-v4l.rules \
	rules.d/60-sensor.rules \
	rules.d/60-serial.rules \
	rules.d/64-btrfs.rules \
	rules.d/70-camera.rules \
	rules.d/70-joystick.rules \
	rules.d/70-memory.rules \
	rules.d/70-mouse.rules \
	rules.d/70-touchpad.rules \
	rules.d/75-net-description.rules \
	rules.d/75-probe_mtd.rules \
	rules.d/78-sound-card.rules \
	rules.d/80-drivers.rules \
	rules.d/80-net-name-slot.rules \
	rules.d/81-net-dhcp.rules
endif
