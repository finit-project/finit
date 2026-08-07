# libink — brokerless D-Bus library (server + client), born inside Finit
#
# Internal convenience library: linked statically into finit and
# initctl, nothing installed.  Public install (and the ABI promise
# that comes with it) is deferred until libink is extracted into its
# own project.
noinst_LTLIBRARIES       = libink.la
libink_la_SOURCES        = server.c auth.c connection.c \
                           proto.c proto.h               \
                           marshal.c marshal.h           \
                           dispatch.c builtin.c          \
                           match.c                       \
                           path.c                        \
                           client.c io.c log.c           \
                           link.h path.h internal.h

libink_la_CPPFLAGS       = -D_GNU_SOURCE -D_DEFAULT_SOURCE -D_BSD_SOURCE
libink_la_CFLAGS         = -W -Wall -Wextra -Wno-unused-parameter -std=gnu99
