noinst_PROGRAMS = serv

serv_SOURCES    = serv.c
serv_CPPFLAGS   = -D_XOPEN_SOURCE=600 -D_BSD_SOURCE -D_GNU_SOURCE -D_DEFAULT_SOURCE -I$(top_builddir)
if LIBSYSTEMD
serv_CPPFLAGS  += -I$(top_srcdir)/libsystemd $(lite_CFLAGS)
serv_SOURCES   += $(top_srcdir)/libsystemd/sd-daemon.c
serv_LDADD      = $(lite_LIBS)
endif

if DBUS
noinst_PROGRAMS           += dbus-auth-client
dbus_auth_client_SOURCES   = dbus-auth-client.c
dbus_auth_client_CPPFLAGS  = -D_GNU_SOURCE -I$(top_srcdir)/libink
dbus_auth_client_LDADD     = $(top_builddir)/libink/libink.la
endif
