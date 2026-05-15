# libink — D-Bus server library born inside Finit
lib_LTLIBRARIES          = libink.la
libink_la_SOURCES        = server.c auth.c connection.c \
                           proto.c proto.h               \
                           marshal.c marshal.h           \
                           dispatch.c builtin.c          \
                           path.c                        \
                           ink-internal.h

# Public header: ink.h installed by `ink_HEADERS` below; path.h
# is also exported, so consumers get ink_path_encode.
libink_la_LDFLAGS        = -version-info 0:0:0
libink_la_CPPFLAGS       = -D_GNU_SOURCE -D_DEFAULT_SOURCE -D_BSD_SOURCE
libink_la_CFLAGS         = -W -Wall -Wextra -Wno-unused-parameter -std=gnu99

# pkg-config support
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libink.pc

# Public header installs to $(includedir)/ink/ink.h
inkdir = $(includedir)/ink
ink_HEADERS = ink.h path.h
