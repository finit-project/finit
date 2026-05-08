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
