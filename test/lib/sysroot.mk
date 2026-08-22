# Root file system for test environment.
#
# Copyright (c) 2021  Jacques de Laval <jacques@de-laval.se>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

srcdir         ?= ../
SKEL           ?= $(srcdir)/skel
DEST           ?= ../sysroot

CACHE          ?= ~/.cache
ARCH           ?= x86_64

FINITBIN       ?= ./sbin/finit

BBVER          ?= 1_35_0
BBBIN           = busybox-$(ARCH)
BBHOME         ?= https://github.com/troglobit/busybox-builder/releases/download
BBURL          ?= $(BBHOME)/$(BBVER)/$(BBBIN)

# glibc dlopen()s NSS modules at runtime, so ldd does not list them, but
# without libnss_files getpwnam() cannot resolve users inside the chroot
_libs_nss      := $(firstword $(wildcard /lib/$(ARCH)-linux-gnu/libnss_files.so.2 \
                                         /usr/lib/$(ARCH)-linux-gnu/libnss_files.so.2 \
                                         /lib64/libnss_files.so.2 /lib/libnss_files.so.2))
# PAM dlopen()s its modules too, so ldd cannot see them either.  Only
# the three the pam-session test needs; absent is fine, it skips.  Their
# own dependencies are picked up by the ldd pass below.  libpam looks in
# one compiled-in directory, and here /lib and /usr/lib are two real
# directories rather than the host's symlink, so /usr/lib comes first.
_pam_mods      := $(foreach m,pam_permit.so pam_deny.so pam_limits.so,				\
                    $(firstword $(wildcard /usr/lib/$(ARCH)-linux-gnu/security/$(m)	\
                                           /lib/$(ARCH)-linux-gnu/security/$(m)	\
                                           /lib/security/$(m))))
# A real broker and a real client, staged when the host has them, so
# one test can check Finit against dbus-daemon instead of only against
# libink's own client.  Absent is fine, dbus-broker.sh skips.
dbus_bins      := $(foreach b,dbus-daemon dbus-send,$(firstword $(wildcard /usr/bin/$(b) /bin/$(b))))

# Bundled helpers like keventd link more libraries than finit itself,
# and so does dbus-daemon.  One ldd per binary: given several at once
# ldd prefixes each with a 'path:' header, and that trailing colon
# would land in a make target.
_bins          := $(FINITBIN) $(dbus_bins) \
                  $(shell find $(abspath $(DEST)) -path '*libexec/finit*' -type f -perm -u+x 2>/dev/null)
# The dbus binaries stage exactly like the libraries: same host path,
# same path under DEST, copied by the rule below.
_libs_src      := $(foreach bin,$(_bins),$(shell ldd $(bin) 2>/dev/null | grep -Eo '/[^ ]+')) \
                  $(foreach mod,$(_pam_mods),$(shell ldd $(mod) 2>/dev/null | grep -Eo '/[^ ]+')) \
                  $(_libs_nss) $(_pam_mods) $(dbus_bins)
libs           := $(foreach path,$(sort $(_libs_src)),$(abspath $(DEST))$(path))

all: $(libs) $(DEST)/bin/$(BBBIN)
	@(cd $(DEST);					\
	for prg in `./bin/$(BBBIN) --list-full`; do 	\
	    case $$prg in				\
	        usr/bin/* | usr/sbin/*)			\
		    ln -sf ../../bin/$(BBBIN) $$prg;;	\
                bin/* | sbin/*)				\
                    ln -sf ../bin/$(BBBIN) $$prg;;	\
                *)					\
                    ln -sf bin/$(BBBIN) $$prg;;		\
	    esac;					\
	done)

$(DEST)/bin/$(BBBIN).sha256:
	@mkdir -p $(DEST)
	@cp -a $(SKEL)/* $(DEST)/
	@chmod -R u+w $(DEST)/
	@find $(DEST) -name .empty -delete

$(DEST)/bin/$(BBBIN): $(DEST)/bin/$(BBBIN).sha256
	@(cd $(dir $@);								\
	if ! sha256sum --status -c $(BBBIN).sha256 2>/dev/null; then		\
		if [ -d $(CACHE) ]; then					\
			echo "Cannot find $(BBBIN), checking $(CACHE) ...";	\
			cd $(CACHE);						\
			cp -v $(DEST)/bin/$(BBBIN).sha256 .;			\
			if ! sha256sum --status -c $(BBBIN).sha256; then	\
				echo "No $(BBBIN), downloading $(BBURL) ...";	\
				wget -O $(BBBIN) $(BBURL);			\
			else							\
				echo "Found valid $(BBBIN) in cache!";		\
			fi;							\
			cp $(BBBIN) $@;						\
			cd $(dir $@);						\
		else								\
			echo "Cannot find $(BBBIN), downloading ...";		\
			wget -O $@ $(BBURL);					\
		fi;								\
		sha256sum -c $(BBBIN).sha256 || (rm $@; false);			\
	fi)
	@chmod +x $@

$(libs): $(DEST)/bin/$(BBBIN).sha256
	mkdir -p $(dir $@)
	cp $(patsubst $(abspath $(DEST))%,%,$@) $@
