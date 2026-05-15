# libink — brokerless D-Bus library (server + client), born inside Finit
lib_LTLIBRARIES          = libink.la
libink_la_SOURCES        = server.c auth.c connection.c \
                           proto.c proto.h               \
                           marshal.c marshal.h           \
                           dispatch.c builtin.c          \
                           match.c                       \
                           path.c                        \
                           client.c io.c                 \
                           internal.h

libink_la_LDFLAGS        = -version-info 0:0:0
libink_la_CPPFLAGS       = -D_GNU_SOURCE -D_DEFAULT_SOURCE -D_BSD_SOURCE
libink_la_CFLAGS         = -W -Wall -Wextra -Wno-unused-parameter -std=gnu99

# pkg-config support
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libink.pc

# Public headers install to $(includedir)/ink/
inkdir = $(includedir)/ink
ink_HEADERS = link.h path.h
