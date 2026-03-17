pkglibdir           = $(plugin_path)
AM_LDFLAGS          = -module -avoid-version -shared
AM_CFLAGS           = -W -Wall -Wextra -Wno-unused-parameter -std=gnu99
AM_CPPFLAGS         = -I$(top_srcdir)/src
AM_CPPFLAGS        += -D_XOPEN_SOURCE=600 -D_BSD_SOURCE -D_GNU_SOURCE -D_DEFAULT_SOURCE
AM_CPPFLAGS        += -D__FINIT__ $(lite_CFLAGS) $(uev_CFLAGS)

if STATIC
noinst_LTLIBRARIES  = libplug.la
libplug_la_SOURCES  = bootmisc.c pidfile.c procps.c sys.c usr.c

if BUILD_ALSA_UTILS_PLUGIN
libplug_la_SOURCES += alsa-utils.c
endif

if BUILD_DBUS_PLUGIN
libplug_la_SOURCES += dbus.c
endif

if BUILD_MODULES_LOAD_PLUGIN
libplug_la_SOURCES += modules-load.c
endif

if BUILD_MODPROBE_PLUGIN
libplug_la_SOURCES += modprobe.c
endif

if BUILD_NETLINK_PLUGIN
libplug_la_SOURCES += netlink.c
endif

if BUILD_PLYMOUTH_PLUGIN
libplug_la_SOURCES += plymouth.c
endif

if BUILD_RESOLVCONF_PLUGIN
libplug_la_SOURCES += resolvconf.c
endif

if BUILD_RTC_PLUGIN
libplug_la_SOURCES += rtc.c
endif

if BUILD_TTY_PLUGIN
libplug_la_SOURCES += tty.c
endif

if BUILD_URANDOM_PLUGIN
libplug_la_SOURCES += urandom.c
endif

if BUILD_X11_COMMON_PLUGIN
libplug_la_SOURCES += x11-common.c
endif

else
pkglib_LTLIBRARIES  = bootmisc.la pidfile.la procps.la sys.la usr.la

if BUILD_ALSA_UTILS_PLUGIN
pkglib_LTLIBRARIES += alsa-utils.la
endif

if BUILD_DBUS_PLUGIN
pkglib_LTLIBRARIES += dbus.la
endif

if BUILD_HOOK_SCRIPTS_PLUGIN
pkglib_LTLIBRARIES += hook-scripts.la
endif

if BUILD_MODULES_LOAD_PLUGIN
pkglib_LTLIBRARIES += modules-load.la
endif

if BUILD_MODPROBE_PLUGIN
pkglib_LTLIBRARIES += modprobe.la
endif

if BUILD_NETLINK_PLUGIN
pkglib_LTLIBRARIES += netlink.la
endif

if BUILD_PLYMOUTH_PLUGIN
pkglib_LTLIBRARIES += plymouth.la
endif

if BUILD_RESOLVCONF_PLUGIN
pkglib_LTLIBRARIES += resolvconf.la
endif

if BUILD_RTC_PLUGIN
pkglib_LTLIBRARIES += rtc.la
endif

if BUILD_TTY_PLUGIN
pkglib_LTLIBRARIES += tty.la
endif

if BUILD_URANDOM_PLUGIN
pkglib_LTLIBRARIES += urandom.la
endif

if BUILD_X11_COMMON_PLUGIN
pkglib_LTLIBRARIES += x11-common.la
endif

# Clean up .la files installed by libtool despite being in -module mode
install-exec-hook:
	@(cd $(DESTDIR)$(pkglibdir) && $(RM) $(pkglib_LTLIBRARIES))

uninstall-hook:
	@(cd $(DESTDIR)$(pkglibdir) && for file in $(pkglib_LTLIBRARIES); do $(RM) `basename $$file .la`.so; done)
endif
