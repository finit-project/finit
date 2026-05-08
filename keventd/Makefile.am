AM_CPPFLAGS        = -D_XOPEN_SOURCE=600 -D_BSD_SOURCE -D_GNU_SOURCE -D_DEFAULT_SOURCE
AM_CPPFLAGS       += -I$(top_srcdir)/src

pkglibexec_PROGRAMS = keventd

keventd_SOURCES    = keventd.c keventd.h uevent.c \
		     $(top_srcdir)/src/util.c $(top_srcdir)/src/util.h
keventd_CFLAGS     = -W -Wall -Wextra -std=gnu99
keventd_CFLAGS    += $(lite_CFLAGS)
keventd_LDADD      = $(lite_LIBS)
