/* Builtin command implementations for keventd rules engine
 *
 * Copyright (c) 2025  Joachim Wiberg <troglobit@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <blkid/blkid.h>

#include <linux/input.h>

#include "builtin.h"
#include "keventd.h"
#include "sysfs.h"

/* Forward declarations from keventd.c and uevent.c */
void logit(int prio, const char *fmt, ...);
int  modprobe_load(const char *modalias);

/* Forward declarations — defined in the usb_id section below */
static int find_usb_dev(const char *devpath, char *usbdir, size_t len);
static int is_scsi_sysname(const char *name);

/* ---- kmod -------------------------------------------------------- */

static int builtin_kmod(struct uevent *ev, int argc, char **argv)
{
	int idx = 1;
	int i;

	/* udev convention: kmod load <alias> [<alias> ...] -- skip the subcommand */
	if (idx < argc && !strcmp(argv[idx], "load"))
		idx++;

	if (idx >= argc) {
		const char *alias = ev->modalias;

		if (!alias)
			alias = uevent_getenv(ev, "MODALIAS");
		if (!alias)
			return -1;
		return modprobe_load(alias);
	}

	{
		int rc = 0;

		for (i = idx; i < argc; i++) {
			if (modprobe_load(argv[i]) < 0)
				rc = -1;
		}
		return rc;
	}
}

/* ---- hwdb -------------------------------------------------------- */

/*
 * Match a single text hwdb file against the lookup key.
 * Text format: match lines at column 0, property lines indented.
 * Empty lines or lines starting with '#' reset the match state.
 *
 * Multiple consecutive match lines OR-merge: if any of the match lines
 * matches the lookup key, the following property block applies.  The
 * group ends when we see a property line followed by another match
 * line (start of next group), or a blank/comment line.
 */
static void hwdb_match_file(const char *path, const char *lookup,
			     struct uevent *ev)
{
	char  line[1024];
	int   matched = 0;
	int   in_props = 0;	/* saw a property line for the current group */
	FILE *fp;

	fp = fopen(path, "r");
	if (!fp)
		return;

	while (fgets(line, sizeof(line), fp)) {
		line[strcspn(line, "\n")] = '\0';

		if (!line[0] || line[0] == '#') {
			matched  = 0;
			in_props = 0;
			continue;
		}

		if (isspace((unsigned char)line[0])) {
			char *p, *eq;

			if (!matched)
				continue;
			p  = line;
			while (isspace((unsigned char)*p))
				p++;
			eq = strchr(p, '=');
			if (!eq)
				continue;
			*eq = '\0';
			uevent_setenv(ev, p, eq + 1);
			in_props = 1;
		} else {
			/* Match line.  If we just finished a property block,
			 * start a fresh match group; otherwise OR-merge with
			 * any previous match lines in this group. */
			if (in_props) {
				matched  = 0;
				in_props = 0;
			}
			if (fnmatch(line, lookup, 0) == 0)
				matched = 1;
		}
	}

	fclose(fp);
}

/*
 * Build the hwdb lookup key for input devices.
 *
 * udev hwdb files use the format:
 *   evdev:input:b{BUS}v{VENDOR}p{PRODUCT}e{VERSION}*
 * where all fields are 4-digit uppercase hex.
 *
 * The id/ files live under the input device directory.  For eventN nodes
 * (devpath ends in .../inputN/eventN) we strip the last component first.
 */
static void hwdb_input_key(const struct uevent *ev, char *key, size_t len)
{
	char base[PATH_MAX];
	char path[PATH_MAX];
	char bus_s[8], vendor_s[8], product_s[8], version_s[8];

	if (!ev->devpath)
		return;

	snprintf(base, sizeof(base), "/sys%s", ev->devpath);

	/* Try parent dir first (for eventN nodes sitting under inputN/) */
	snprintf(path, sizeof(path), "%s", base);
	{
		char *sl = strrchr(path, '/');

		if (sl)
			*sl = '\0';
	}
	snprintf(base, sizeof(base), "%s/id/bustype", path);
	if (sysfs_read_file(base, bus_s, sizeof(bus_s)) < 0) {
		/* Already at the input device dir */
		snprintf(base, sizeof(base), "/sys%s/id/bustype", ev->devpath);
		if (sysfs_read_file(base, bus_s, sizeof(bus_s)) < 0)
			return;
		snprintf(path, sizeof(path), "/sys%s", ev->devpath);
	}

	snprintf(base, sizeof(base), "%s/id/vendor",  path); sysfs_read_file(base, vendor_s,  sizeof(vendor_s));
	snprintf(base, sizeof(base), "%s/id/product",  path); sysfs_read_file(base, product_s, sizeof(product_s));
	snprintf(base, sizeof(base), "%s/id/version",  path); sysfs_read_file(base, version_s, sizeof(version_s));

	snprintf(key, len, "evdev:input:b%04Xv%04Xp%04Xe%04X*",
		 (unsigned)strtoul(bus_s,     NULL, 16),
		 (unsigned)strtoul(vendor_s,  NULL, 16),
		 (unsigned)strtoul(product_s, NULL, 16),
		 (unsigned)strtoul(version_s, NULL, 16));
}

/*
 * Build the hwdb lookup key for USB devices.
 *
 * udev hwdb files use the format:  usb:v{VID}p{PID}*
 * where VID and PID are 4-digit uppercase hex.
 *
 * Works for both usb_device events (devpath IS the USB device dir) and
 * for child events where we need to navigate up to the USB device parent.
 */
static void hwdb_usb_key(const struct uevent *ev, char *key, size_t len)
{
	char path[PATH_MAX];
	char usbdir[PATH_MAX];
	char vendor_s[8] = "", product_s[8] = "";

	if (!ev->devpath)
		return;

	/* Try devpath directly first (DEVTYPE==usb_device rule context) */
	snprintf(path, sizeof(path), "/sys%s/idVendor", ev->devpath);
	if (sysfs_read_file(path, vendor_s, sizeof(vendor_s)) < 0) {
		/* Navigate up to the USB device ancestor */
		if (find_usb_dev(ev->devpath, usbdir, sizeof(usbdir)) < 0)
			return;
		snprintf(path, sizeof(path), "%s/idVendor", usbdir);
		if (sysfs_read_file(path, vendor_s, sizeof(vendor_s)) < 0)
			return;
		snprintf(path, sizeof(path), "%s/idProduct", usbdir);
	} else {
		snprintf(path, sizeof(path), "/sys%s/idProduct", ev->devpath);
	}

	if (sysfs_read_file(path, product_s, sizeof(product_s)) < 0)
		return;

	snprintf(key, len, "usb:v%04Xp%04X*",
		 (unsigned)strtoul(vendor_s,  NULL, 16),
		 (unsigned)strtoul(product_s, NULL, 16));
}

static void hwdb_scan(const char *key, struct uevent *ev)
{
	static const char *dirs[] = {
		"/lib/udev/hwdb.d",
		"/run/udev/hwdb.d",
		"/etc/udev/hwdb.d",
		NULL
	};
	int i;

	for (i = 0; dirs[i]; i++) {
		struct dirent **entries;
		int             n, j;

		n = scandir(dirs[i], &entries, NULL, alphasort);
		if (n < 0)
			continue;

		for (j = 0; j < n; j++) {
			const char *name = entries[j]->d_name;
			size_t      nlen = strlen(name);

			if (nlen > 5 && !strcmp(name + nlen - 5, ".hwdb")) {
				char path[PATH_MAX];

				snprintf(path, sizeof(path), "%s/%s", dirs[i], name);
				hwdb_match_file(path, key, ev);
			}
			free(entries[j]);
		}
		free(entries);
	}
}

static int builtin_hwdb(struct uevent *ev, int argc, char **argv)
{
	const char *subsys = NULL;
	const char *prefix = NULL;
	char        key[256] = "";
	int         i;

	/* Parse --subsystem=X and --lookup-prefix=Y */
	for (i = 1; i < argc; i++) {
		if (!strncmp(argv[i], "--subsystem=", 12))
			subsys = argv[i] + 12;
		else if (!strncmp(argv[i], "--lookup-prefix=", 16))
			prefix = argv[i] + 16;
	}
	if (!subsys)
		subsys = ev->subsystem;

	if (subsys && !strcmp(subsys, "input")) {
		hwdb_input_key(ev, key, sizeof(key));
	} else if (subsys && (!strcmp(subsys, "usb") ||
			      !strcmp(subsys, "usb_device"))) {
		hwdb_usb_key(ev, key, sizeof(key));
	}

	/* Fall back to MODALIAS / ev->modalias for pci, platform, etc. */
	if (!key[0]) {
		const char *m = uevent_getenv(ev, "MODALIAS");

		if (!m)
			m = ev->modalias;
		if (m)
			snprintf(key, sizeof(key), "%s", m);
	}

	if (!key[0])
		return 0;

	/* --lookup-prefix scopes the match by prepending to the key. */
	if (prefix && *prefix) {
		char tmp[sizeof(key)];

		snprintf(tmp, sizeof(tmp), "%s%s", prefix, key);
		snprintf(key, sizeof(key), "%s", tmp);
	}

	logit(LOG_DEBUG, "rules: hwdb lookup: %s", key);
	hwdb_scan(key, ev);
	return 0;
}

/* ---- path_id ----------------------------------------------------- */

/*
 * Build a stable device path ID from the sysfs topology.
 * Walks devpath from root to leaf, emitting segments for recognised
 * subsystems (pci, usb, ata, nvme, platform, acpi, virtio).
 */
static int builtin_path_id(struct uevent *ev, int argc, char **argv)
{
	char        seg[PATH_MAX] = "";
	char        tag[PATH_MAX];
	const char *dp;
	const char *p;

	(void)argc;
	(void)argv;

	dp = ev->devpath;
	if (!dp)
		return -1;

	p = dp;
	while (*p) {
		char        comp[128];
		char        cpath[PATH_MAX];
		char        subsys[64] = "";
		char        lnk[PATH_MAX];
		char        new_seg[160] = "";
		ssize_t     r;
		const char *slash;
		const char *sl;
		size_t      clen;

		while (*p == '/')
			p++;
		slash = strchr(p, '/');
		clen  = slash ? (size_t)(slash - p) : strlen(p);

		if (!clen || clen >= sizeof(comp)) {
			if (!slash)
				break;
			p = slash;
			continue;
		}

		memcpy(comp, p, clen);
		comp[clen] = '\0';

		/* sysfs path up to and including this component */
		snprintf(cpath, sizeof(cpath), "/sys%.*s",
			 (int)(p - dp + (ptrdiff_t)clen), dp);

		/* read subsystem symlink */
		{
			char slnk[PATH_MAX];

			snprintf(slnk, sizeof(slnk), "%s/subsystem", cpath);
			r = readlink(slnk, lnk, sizeof(lnk) - 1);
		}
		if (r > 0) {
			lnk[r] = '\0';
			sl = strrchr(lnk, '/');
			snprintf(subsys, sizeof(subsys), "%s",
				 sl ? sl + 1 : lnk);
		}

		if (!strcmp(subsys, "pci")) {
			snprintf(new_seg, sizeof(new_seg), "pci-%s", comp);
		} else if (!strcmp(subsys, "usb")) {
			/*
			 * Skip interfaces (':') and root hubs (usbN).
			 * Emit "usb-0:<port>" to match eudev's path_id
			 * format so by-path symlinks are portable.
			 */
			if (!strchr(comp, ':') && isdigit((unsigned char)comp[0]))
				snprintf(new_seg, sizeof(new_seg), "usb-0:%s", comp);
		} else if (!strcmp(subsys, "scsi") && is_scsi_sysname(comp)) {
			/*
			 * Generic SCSI default handler.  scsi_device sysname
			 * is H:B:T:L; scsi_host/scsi_target also live under
			 * subsystem "scsi" but their sysnames don't match
			 * the 4-tuple pattern -- the is_scsi_sysname() guard
			 * skips those.  FC, SAS, iSCSI transport-specific
			 * naming requires parent-walking we don't yet
			 * implement (audit gap #3).
			 */
			snprintf(new_seg, sizeof(new_seg), "scsi-%s", comp);
		} else if (!strncmp(comp, "ata", 3) &&
			   isdigit((unsigned char)comp[3])) {
			snprintf(new_seg, sizeof(new_seg), "ata-%s", comp + 3);
		} else if (!strncmp(comp, "nvme", 4) &&
			   strchr(comp + 4, 'n')) {
			/* nvme0n1 -> nvme-1 */
			const char *ns = strchr(comp + 4, 'n');

			snprintf(new_seg, sizeof(new_seg), "nvme-%s", ns + 1);
		} else if (!strcmp(subsys, "platform") ||
			   !strcmp(subsys, "acpi")     ||
			   !strcmp(subsys, "virtio")) {
			snprintf(new_seg, sizeof(new_seg), "%s-%s", subsys, comp);
		}

		if (new_seg[0]) {
			if (seg[0])
				strncat(seg, "-", sizeof(seg) - strlen(seg) - 1);
			strncat(seg, new_seg, sizeof(seg) - strlen(seg) - 1);
		}

		if (!slash)
			break;
		p = slash;
	}

	if (!seg[0])
		return 0;

	uevent_setenv(ev, "ID_PATH", seg);

	/*
	 * ID_PATH_TAG: same as ID_PATH but with non-alnum/non-'-' chars
	 * replaced by '_', collapsing consecutive '_' and stripping any
	 * trailing one.  Matches eudev's encoding so by-path symlinks
	 * use identical tag names across implementations.
	 */
	{
		const char *s = seg;
		char       *t = tag;
		int         last_under = 0;

		while (*s && (size_t)(t - tag) < sizeof(tag) - 1) {
			unsigned char c = *s++;

			if (isalnum(c) || c == '-') {
				*t++ = c;
				last_under = 0;
			} else if (!last_under) {
				*t++ = '_';
				last_under = 1;
			}
		}
		while (t > tag && t[-1] == '_')
			t--;
		*t = '\0';
	}
	uevent_setenv(ev, "ID_PATH_TAG", tag);

	return 0;
}

/* ---- usb_id ------------------------------------------------------ */

/*
 * Find the USB device directory (not the interface) in the sysfs devpath.
 * A USB device component matches: digits + '-' + (digits '.')* + digits,
 * with no ':' character (which would indicate an interface).
 */
static int find_usb_dev(const char *devpath, char *usbdir, size_t len)
{
	const char *p       = devpath;
	const char *last    = NULL;
	const char *lastend = NULL;

	while (*p) {
		const char *slash;
		size_t      clen;
		char        seg[64];

		while (*p == '/')
			p++;
		slash = strchr(p, '/');
		clen  = slash ? (size_t)(slash - p) : strlen(p);

		if (clen > 0 && clen < sizeof(seg) &&
		    isdigit((unsigned char)*p)) {
			memcpy(seg, p, clen);
			seg[clen] = '\0';
			if (strchr(seg, '-') && !strchr(seg, ':')) {
				last    = p;
				lastend = slash; /* NULL if at end */
			}
		}

		if (!slash)
			break;
		p = slash;
	}

	if (!last)
		return -1;

	ptrdiff_t prefix = lastend ? (lastend - devpath)
				   : (ptrdiff_t)strlen(devpath);
	snprintf(usbdir, len, "/sys%.*s", (int)prefix, devpath);
	return 0;
}

/*
 * Look up vendor and product names from a usb.ids file (hwdata package).
 *
 * Tries standard install paths; returns -1 if no file is available so the
 * caller can silently skip setting the DATABASE keys on slim systems.
 *
 * usb.ids format:
 *   VVVV  Vendor Name          (vendor line, hex at column 0)
 *     PPPP  Product Name       (product line, one TAB indent)
 *       CC PP  Interface name  (two TABs — ignored)
 *   # comment / blank line
 */
static int lookup_usb_ids(unsigned int vendor_id, unsigned int product_id,
			   char *vendor_out, size_t vsz,
			   char *product_out, size_t psz)
{
	static const char *candidates[] = {
		"/usr/share/hwdata/usb.ids",
		"/usr/share/misc/usb.ids",
		"/var/lib/usbutils/usb.ids",
		NULL
	};
	static const char *cached_path;
	char  line[512];
	FILE *fp = NULL;
	int   found_vendor = 0;

	if (cached_path) {
		fp = fopen(cached_path, "r");
	} else {
		int i;

		for (i = 0; candidates[i]; i++) {
			fp = fopen(candidates[i], "r");
			if (fp) {
				cached_path = candidates[i];
				break;
			}
		}
	}
	if (!fp)
		return -1;

	vendor_out[0]  = '\0';
	product_out[0] = '\0';

	while (fgets(line, sizeof(line), fp)) {
		unsigned int id;
		char        *name;
		size_t       nl;

		nl = strlen(line);
		while (nl > 0 && (line[nl - 1] == '\n' || line[nl - 1] == '\r'))
			line[--nl] = '\0';

		if (!line[0] || line[0] == '#')
			continue;

		if (line[0] == '\t' && line[1] == '\t')
			continue; /* interface / protocol sub-entry */

		if (line[0] == '\t') {
			/* Product line: "\tPPPP  Product Name" */
			if (!found_vendor)
				continue;
			if (sscanf(line + 1, "%4x", &id) != 1 || id != product_id)
				continue;
			name = line + 1 + 4;
			while (*name == ' ')
				name++;
			snprintf(product_out, psz, "%s", name);
			break; /* found both vendor and product */
		} else {
			/* Vendor line: "VVVV  Vendor Name" */
			if (sscanf(line, "%4x", &id) != 1)
				continue;
			if (found_vendor)
				break; /* past our vendor's section, give up */
			if (id == vendor_id) {
				name = line + 4;
				while (*name == ' ')
					name++;
				snprintf(vendor_out, vsz, "%s", name);
				found_vendor = 1;
			}
		}
	}

	fclose(fp);
	return (vendor_out[0] || product_out[0]) ? 0 : -1;
}

/*
 * Map a USB interface class to its short ID_TYPE string.
 * Mirrors eudev's set_usb_iftype().
 */
static const char *usb_iftype(int cls)
{
	switch (cls) {
	case 0x01: return "audio";
	case 0x03: return "hid";
	case 0x06: return "media";
	case 0x07: return "printer";
	case 0x08: return "storage";
	case 0x09: return "hub";
	case 0x0e: return "video";
	default:   return "generic";
	}
}

/* Mass-storage subclass → ID_TYPE refinement. */
static const char *usb_storage_subtype(int sub)
{
	switch (sub) {
	case 1:  return "rbc";
	case 2:  return "atapi";
	case 3:  return "tape";
	case 4:  return "floppy";
	case 6:  return "scsi";
	default: return "generic";
	}
}

/* True if NAME has the SCSI scsi_device sysname shape "H:B:T:L". */
static int is_scsi_sysname(const char *name)
{
	int h, b, t, l;

	return sscanf(name, "%d:%d:%d:%d", &h, &b, &t, &l) == 4;
}

/* SCSI peripheral type code (from /sys/.../<scsi_device>/type) → ID_TYPE. */
static const char *scsi_type(int n)
{
	switch (n) {
	case 0:
	case 0xe:	return "disk";
	case 1:		return "tape";
	case 4:
	case 7:
	case 0xf:	return "optical";
	case 5:		return "cd";
	default:	return "generic";
	}
}

/*
 * Walk up from /sys{devpath} looking for a directory whose basename
 * matches the SCSI sysname pattern "H:B:T:L" (4 ints colon-separated).
 * That's the scsi_device dir, which has vendor/model/type/rev attrs.
 */
static int find_scsi_device(const char *devpath, char *scsidir, size_t len)
{
	char path[PATH_MAX];
	char *slash;

	snprintf(path, sizeof(path), "/sys%s", devpath);

	while ((slash = strrchr(path, '/')) != NULL && (slash - path) > 4) {
		if (is_scsi_sysname(slash + 1)) {
			snprintf(scsidir, len, "%s", path);
			return 0;
		}
		*slash = '\0';
	}
	return -1;
}

/*
 * Walk up from /sys{devpath} until a directory containing
 * bInterfaceClass is found -- that's the USB interface dir.
 * Returns -1 if called on the usb_device itself or anything
 * without a USB interface ancestor.
 */
static int find_usb_interface(const char *devpath, char *ifdir, size_t len)
{
	char path[PATH_MAX], test[PATH_MAX];

	snprintf(path, sizeof(path), "/sys%s", devpath);

	for (;;) {
		char *slash;

		snprintf(test, sizeof(test), "%s/bInterfaceClass", path);
		if (access(test, F_OK) == 0) {
			snprintf(ifdir, len, "%s", path);
			return 0;
		}
		slash = strrchr(path, '/');
		if (!slash || (slash - path) <= 4)	/* stay below /sys */
			return -1;
		*slash = '\0';
	}
}

/*
 * Collapse whitespace runs to '_', strip leading/trailing.  Used to
 * normalize human-readable sysfs strings before they end up in
 * /dev/disk/by-id symlink names.  Mirrors eudev's util_replace_whitespace.
 */
static void usb_normalize(const char *src, char *dst, size_t len)
{
	size_t i = 0;
	int    in_space = 1;	/* skip leading whitespace */

	while (*src && i + 1 < len) {
		unsigned char c = *src++;

		if (isspace(c)) {
			in_space = 1;
		} else {
			if (in_space && i > 0)
				dst[i++] = '_';
			if (i + 1 < len)
				dst[i++] = c;
			in_space = 0;
		}
	}
	dst[i] = '\0';
}

/*
 * Parse the USB device's binary descriptors file and emit a string of
 * `:CCSSPP` interface triplets (class/subclass/protocol).  Matches
 * eudev's dev_if_packed_info().
 */
static int usb_read_interfaces(const char *usbdir, char *out, size_t len)
{
	char          path[PATH_MAX];
	unsigned char buf[4096];	/* descriptors blobs are typically <1KB */
	ssize_t       n;
	size_t        pos = 0, used = 0;
	int           fd;

	snprintf(path, sizeof(path), "%s/descriptors", usbdir);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = read(fd, buf, sizeof(buf));
	close(fd);
	if (n < 18)
		return -1;

	out[0] = '\0';
	while (pos + 9 < (size_t)n && used + 8 < len) {
		unsigned char blen  = buf[pos];
		unsigned char btype = buf[pos + 1];

		if (blen < 3)
			break;
		if (btype == 0x04) {	/* USB_DT_INTERFACE */
			char triplet[8];

			if (snprintf(triplet, sizeof(triplet), ":%02x%02x%02x",
				     buf[pos + 5], buf[pos + 6], buf[pos + 7]) == 7 &&
			    !strstr(out, triplet)) {
				memcpy(out + used, triplet, 7);
				used += 7;
				out[used] = '\0';
			}
		}
		pos += blen;
	}
	if (used && used + 1 < len) {
		out[used++] = ':';
		out[used]   = '\0';
	}
	return used ? 0 : -1;
}

static int builtin_usb_id(struct uevent *ev, int argc, char **argv)
{
	char usbdir[PATH_MAX];
	char ifdir[PATH_MAX];
	char path[PATH_MAX];
	char val[256];
	int  ms_subclass = -1;	/* mass-storage subclass (-1 = not mass-storage) */

	(void)argc;
	(void)argv;

	if (!ev->devpath)
		return -1;
	if (find_usb_dev(ev->devpath, usbdir, sizeof(usbdir)) < 0)
		return -1;

	uevent_setenv(ev, "ID_BUS", "usb");

	/*
	 * Pull per-interface info (class for ID_TYPE classification,
	 * bInterfaceNumber, driver name).  Optional -- the device may be
	 * the usb_device itself, in which case we skip this and rely on
	 * the descriptors file below.
	 */
	if (find_usb_interface(ev->devpath, ifdir, sizeof(ifdir)) == 0) {
		char cls_s[8] = "", sub_s[8] = "";

		snprintf(path, sizeof(path), "%s/bInterfaceClass", ifdir);
		sysfs_read_file(path, cls_s, sizeof(cls_s));
		snprintf(path, sizeof(path), "%s/bInterfaceSubClass", ifdir);
		sysfs_read_file(path, sub_s, sizeof(sub_s));

		if (cls_s[0]) {
			int cls = (int)strtoul(cls_s, NULL, 16);
			const char *type = usb_iftype(cls);

			if (cls == 8 && sub_s[0]) {
				ms_subclass = (int)strtoul(sub_s, NULL, 16);
				type = usb_storage_subtype(ms_subclass);
			}
			uevent_setenv(ev, "ID_TYPE", type);
		}

		snprintf(path, sizeof(path), "%s/bInterfaceNumber", ifdir);
		if (sysfs_read_file(path, val, sizeof(val)) == 0)
			uevent_setenv(ev, "ID_USB_INTERFACE_NUM", val);

		if (sysfs_read_driver(ifdir, val, sizeof(val)) == 0)
			uevent_setenv(ev, "ID_USB_DRIVER", val);
	}

	/* Aggregated class/subclass/protocol per interface */
	if (usb_read_interfaces(usbdir, val, sizeof(val)) == 0)
		uevent_setenv(ev, "ID_USB_INTERFACES", val);

	/* Plain hex IDs straight from sysfs */
#define USB_ATTR_RAW(attr, key) do {					\
	snprintf(path, sizeof(path), "%s/" attr, usbdir);		\
	if (sysfs_read_file(path, val, sizeof(val)) == 0)		\
		uevent_setenv(ev, key, val);				\
} while (0)
	USB_ATTR_RAW("idVendor",  "ID_VENDOR_ID");
	USB_ATTR_RAW("idProduct", "ID_MODEL_ID");
	USB_ATTR_RAW("bcdDevice", "ID_REVISION");
#undef USB_ATTR_RAW

	/*
	 * Human-readable strings need both whitespace-normalized form
	 * (for /dev/disk/by-id paths) and udev-encoded form (_ENC, for
	 * symlinks containing the raw string).
	 */
#define USB_ATTR_STR(attr, key) do {					\
	char raw[256];							\
	snprintf(path, sizeof(path), "%s/" attr, usbdir);		\
	if (sysfs_read_file(path, raw, sizeof(raw)) == 0) {		\
		char enc[256];						\
									\
		usb_normalize(raw, val, sizeof(val));			\
		uevent_setenv(ev, key, val);				\
		blkid_encode_string(raw, enc, sizeof(enc));		\
		snprintf(val, sizeof(val), "%s_ENC", key);		\
		uevent_setenv(ev, val, enc);				\
	}								\
} while (0)
	USB_ATTR_STR("manufacturer", "ID_VENDOR");
	USB_ATTR_STR("product",      "ID_MODEL");
	USB_ATTR_STR("serial",       "ID_SERIAL_SHORT");
#undef USB_ATTR_STR

	/*
	 * Mass storage (subclass 6 = SCSI transparent, 2 = ATAPI):
	 * SCSI inquiry data is more specific than the USB descriptor
	 * strings, so override ID_VENDOR / ID_MODEL / ID_TYPE / ID_REVISION
	 * with values from the scsi_device parent when one is present.
	 */
	if (ms_subclass == 6 || ms_subclass == 2) {
		char scsidir[PATH_MAX];

		if (find_scsi_device(ev->devpath, scsidir, sizeof(scsidir)) == 0) {
			char raw[256];

#define SCSI_STR(attr, key) do {					\
	snprintf(path, sizeof(path), "%s/" attr, scsidir);		\
	if (sysfs_read_file(path, raw, sizeof(raw)) == 0) {		\
		char enc[256];						\
									\
		usb_normalize(raw, val, sizeof(val));			\
		uevent_setenv(ev, key, val);				\
		blkid_encode_string(raw, enc, sizeof(enc));		\
		snprintf(val, sizeof(val), "%s_ENC", key);		\
		uevent_setenv(ev, val, enc);				\
	}								\
} while (0)
			SCSI_STR("vendor", "ID_VENDOR");
			SCSI_STR("model",  "ID_MODEL");
#undef SCSI_STR

			snprintf(path, sizeof(path), "%s/type", scsidir);
			if (sysfs_read_file(path, val, sizeof(val)) == 0)
				uevent_setenv(ev, "ID_TYPE",
					      scsi_type(atoi(val)));

			snprintf(path, sizeof(path), "%s/rev", scsidir);
			if (sysfs_read_file(path, val, sizeof(val)) == 0) {
				char norm[256];

				usb_normalize(val, norm, sizeof(norm));
				uevent_setenv(ev, "ID_REVISION", norm);
			}
		}
	}

	/* Build composite ID_SERIAL: vendor_model[_serial] */
	{
		const char *vendor = uevent_getenv(ev, "ID_VENDOR");
		const char *model  = uevent_getenv(ev, "ID_MODEL");
		const char *serial = uevent_getenv(ev, "ID_SERIAL_SHORT");

		if (!vendor)
			vendor = uevent_getenv(ev, "ID_VENDOR_ID");
		if (!model)
			model = uevent_getenv(ev, "ID_MODEL_ID");

		if (vendor && model) {
			if (serial)
				snprintf(val, sizeof(val), "%s_%s_%s",
					 vendor, model, serial);
			else
				snprintf(val, sizeof(val), "%s_%s",
					 vendor, model);
			uevent_setenv(ev, "ID_SERIAL", val);
		}
	}

	/* Look up human-readable names from usb.ids (hwdata); silently skipped
	 * if the file is absent — sysfs manufacturer/product strings remain. */
	{
		const char *vid_s = uevent_getenv(ev, "ID_VENDOR_ID");
		const char *pid_s = uevent_getenv(ev, "ID_MODEL_ID");

		if (vid_s && pid_s) {
			unsigned int vid = (unsigned int)strtoul(vid_s, NULL, 16);
			unsigned int pid = (unsigned int)strtoul(pid_s, NULL, 16);
			char vendor_db[128], model_db[128];

			if (!lookup_usb_ids(vid, pid,
					    vendor_db, sizeof(vendor_db),
					    model_db,  sizeof(model_db))) {
				if (vendor_db[0])
					uevent_setenv(ev, "ID_VENDOR_FROM_DATABASE",
						      vendor_db);
				if (model_db[0])
					uevent_setenv(ev, "ID_MODEL_FROM_DATABASE",
						      model_db);
			}
		}
	}

	return 0;
}

/* ---- input_id ---------------------------------------------------- */

/*
 * Input device classification.  Ports eudev's logic in
 * udev-builtin-input_id.c -- the bit positions and the conditions
 * matter, so we use the kernel-supplied constants from
 * <linux/input-event-codes.h> rather than redefining them.
 */
#define BITS_PER_LONG (sizeof(unsigned long) * 8)
#define NBITS(x)      (((x) + BITS_PER_LONG - 1) / BITS_PER_LONG)
#define test_bit(bit, arr) \
	((arr)[(bit) / BITS_PER_LONG] >> ((bit) % BITS_PER_LONG) & 1UL)

/* High-keycode blocks scanned when no low keys are found (eudev mirror). */
static const struct { unsigned start, end; } high_key_blocks[] = {
	{ KEY_OK,         BTN_DPAD_UP    },
	{ KEY_ALS_TOGGLE, BTN_TRIGGER_HAPPY },
};

/*
 * Parse a kernel capability bitmap from sysfs.  Kernel writes
 * space-separated hex words, MSW first.  We fill bitmask[] with LSW
 * at index 0, matching the kernel's in-memory layout.  text is
 * mutated in place.
 */
static void parse_cap(char *text, unsigned long *bitmask, size_t nlongs)
{
	char  *word;
	size_t i = 0;

	memset(bitmask, 0, nlongs * sizeof(unsigned long));
	if (!text || !*text)
		return;

	while ((word = strrchr(text, ' ')) != NULL) {
		if (i < nlongs)
			bitmask[i++] = strtoul(word + 1, NULL, 16);
		*word = '\0';
	}
	if (*text && i < nlongs)
		bitmask[i] = strtoul(text, NULL, 16);
}

static int read_cap(const char *base, const char *name,
		    unsigned long *bitmask, size_t nlongs)
{
	char path[PATH_MAX];
	char text[4096];

	snprintf(path, sizeof(path), "%s/capabilities/%s", base, name);
	if (sysfs_read_file(path, text, sizeof(text)) < 0) {
		memset(bitmask, 0, nlongs * sizeof(unsigned long));
		return -1;
	}
	parse_cap(text, bitmask, nlongs);
	return 0;
}

/* Classify pointer-like devices (mouse / touchpad / touchscreen / tablet /
 * joystick / pointing-stick / accelerometer).  Ports eudev's test_pointers. */
static void classify_pointer(struct uevent *ev,
			     const unsigned long *bm_ev,
			     const unsigned long *bm_abs,
			     const unsigned long *bm_key,
			     const unsigned long *bm_rel,
			     const unsigned long *bm_props)
{
	int has_keys = test_bit(EV_KEY, bm_ev);
	int has_abs  = test_bit(ABS_X, bm_abs) && test_bit(ABS_Y, bm_abs);
	int has_mt   = test_bit(ABS_MT_POSITION_X, bm_abs) &&
		       test_bit(ABS_MT_POSITION_Y, bm_abs);
	int is_direct = test_bit(INPUT_PROP_DIRECT, bm_props);
	int has_touch = test_bit(BTN_TOUCH, bm_key);
	int stylus    = test_bit(BTN_STYLUS, bm_key) ||
			test_bit(BTN_TOOL_PEN, bm_key);
	int finger_no_pen = test_bit(BTN_TOOL_FINGER, bm_key) &&
			    !test_bit(BTN_TOOL_PEN, bm_key);
	int has_rel = test_bit(EV_REL, bm_ev) &&
		      test_bit(REL_X, bm_rel) && test_bit(REL_Y, bm_rel);
	int has_mouse_button = 0;
	int has_joy = 0;
	int is_mouse = 0, is_touchpad = 0, is_touchscreen = 0;
	int is_tablet = 0, is_joystick = 0;

	if (test_bit(INPUT_PROP_ACCELEROMETER, bm_props) ||
	    (!has_keys && has_abs && test_bit(ABS_Z, bm_abs))) {
		uevent_setenv(ev, "ID_INPUT_ACCELEROMETER", "1");
		return;
	}

	if (test_bit(INPUT_PROP_POINTING_STICK, bm_props))
		uevent_setenv(ev, "ID_INPUT_POINTINGSTICK", "1");

	/* mt overrides if device claims all abs axes */
	if (has_mt && test_bit(ABS_MT_SLOT, bm_abs) &&
	    test_bit(ABS_MT_SLOT - 1, bm_abs))
		has_mt = 0;

	for (int b = BTN_MOUSE; b < BTN_JOYSTICK && !has_mouse_button; b++)
		has_mouse_button = test_bit(b, bm_key);

	/* Joystick detection -- broad button/axis sweep (eudev mirror). */
	if (!test_bit(BTN_JOYSTICK - 1, bm_key)) {
		for (int b = BTN_JOYSTICK; b < BTN_DIGI && !has_joy; b++)
			has_joy = test_bit(b, bm_key);
		for (int b = BTN_TRIGGER_HAPPY1; b <= BTN_TRIGGER_HAPPY40 && !has_joy; b++)
			has_joy = test_bit(b, bm_key);
		for (int b = BTN_DPAD_UP; b <= BTN_DPAD_RIGHT && !has_joy; b++)
			has_joy = test_bit(b, bm_key);
	}
	for (int b = ABS_RX; b < ABS_PRESSURE && !has_joy; b++)
		has_joy = test_bit(b, bm_abs);

	if (has_abs) {
		if (stylus)             is_tablet = 1;
		else if (finger_no_pen && !is_direct) is_touchpad = 1;
		else if (has_mouse_button) is_mouse = 1;	/* VMware abs-axis mouse */
		else if (has_touch || is_direct) is_touchscreen = 1;
		else if (has_joy)       is_joystick = 1;
	} else if (has_joy) {
		is_joystick = 1;
	}

	if (has_mt) {
		if (stylus)             is_tablet = 1;
		else if (finger_no_pen && !is_direct) is_touchpad = 1;
		else if (has_touch || is_direct) is_touchscreen = 1;
	}

	if (!is_tablet && !is_touchpad && !is_joystick && has_mouse_button &&
	    (has_rel || !has_abs))
		is_mouse = 1;

	if (is_mouse)       uevent_setenv(ev, "ID_INPUT_MOUSE",       "1");
	if (is_touchpad)    uevent_setenv(ev, "ID_INPUT_TOUCHPAD",    "1");
	if (is_touchscreen) uevent_setenv(ev, "ID_INPUT_TOUCHSCREEN", "1");
	if (is_tablet)      uevent_setenv(ev, "ID_INPUT_TABLET",      "1");
	if (is_joystick)    uevent_setenv(ev, "ID_INPUT_JOYSTICK",    "1");
}

/* Classify key-like devices.  Ports eudev's test_key(). */
static void classify_key(struct uevent *ev,
			 const unsigned long *bm_ev,
			 const unsigned long *bm_key)
{
	unsigned long found = 0;
	unsigned int i;

	if (!test_bit(EV_KEY, bm_ev))
		return;

	/* Any KEY_* below BTN_MISC counts as "has keys" */
	for (i = 0; i < BTN_MISC / BITS_PER_LONG; i++)
		found |= bm_key[i];

	if (!found) {
		unsigned int b;

		for (b = 0; b < sizeof(high_key_blocks) / sizeof(high_key_blocks[0]); b++) {
			unsigned int k;

			for (k = high_key_blocks[b].start;
			     k < high_key_blocks[b].end; k++) {
				if (test_bit(k, bm_key)) {
					found = 1;
					goto done;
				}
			}
		}
	}
done:
	if (found)
		uevent_setenv(ev, "ID_INPUT_KEY", "1");

	/* Full keyboard: first 32 bits are ESC, 1..0, Q..D (mask 0xFFFFFFFE -- skip KEY_RESERVED). */
	if ((bm_key[0] & 0xFFFFFFFEUL) == 0xFFFFFFFEUL)
		uevent_setenv(ev, "ID_INPUT_KEYBOARD", "1");
}

static int builtin_input_id(struct uevent *ev, int argc, char **argv)
{
	unsigned long bm_ev   [NBITS(EV_MAX)];
	unsigned long bm_abs  [NBITS(ABS_MAX)];
	unsigned long bm_key  [NBITS(KEY_MAX)];
	unsigned long bm_rel  [NBITS(REL_MAX)];
	unsigned long bm_props[NBITS(INPUT_PROP_MAX)];
	char base[PATH_MAX];

	(void)argc;
	(void)argv;

	if (!ev->devpath)
		return -1;

	/*
	 * For input/eventN nodes, capabilities live one level up under
	 * inputN/.  Try parent dir first, fall back to devpath itself
	 * (which is the input device dir for non-eventN cases).
	 */
	snprintf(base, sizeof(base), "/sys%s", ev->devpath);
	{
		char *sl = strrchr(base, '/');

		if (sl) {
			*sl = '\0';
			if (read_cap(base, "ev", bm_ev, NBITS(EV_MAX)) == 0)
				goto have_base;
			*sl = '/';	/* restore full path for retry */
		}
		if (read_cap(base, "ev", bm_ev, NBITS(EV_MAX)) < 0)
			return 0;
	}
have_base:

	read_cap(base, "abs",        bm_abs,   NBITS(ABS_MAX));
	read_cap(base, "key",        bm_key,   NBITS(KEY_MAX));
	read_cap(base, "rel",        bm_rel,   NBITS(REL_MAX));
	read_cap(base, "properties", bm_props, NBITS(INPUT_PROP_MAX));

	uevent_setenv(ev, "ID_INPUT", "1");
	classify_pointer(ev, bm_ev, bm_abs, bm_key, bm_rel, bm_props);
	classify_key(ev, bm_ev, bm_key);

	/* Devices with only a scrollwheel get ID_INPUT_KEY too. */
	if (test_bit(EV_REL, bm_ev) &&
	    (test_bit(REL_WHEEL, bm_rel) || test_bit(REL_HWHEEL, bm_rel)) &&
	    !uevent_getenv(ev, "ID_INPUT_KEY"))
		uevent_setenv(ev, "ID_INPUT_KEY", "1");

	if (test_bit(EV_SW, bm_ev))
		uevent_setenv(ev, "ID_INPUT_SWITCH", "1");

	return 0;
}

/* ---- net_id ------------------------------------------------------ */

static int builtin_net_id(struct uevent *ev, int argc, char **argv)
{
	const char *devname;
	char        path[PATH_MAX];
	char        val[64] = "";
	char        mac[32] = "";

	(void)argc;
	(void)argv;

	devname = ev->devname;
	if (!devname)
		devname = uevent_getenv(ev, "INTERFACE");
	if (!devname)
		return -1;

	/*
	 * Skip stacked devices (VLAN, bridge, bond, vlan, vrf, ...).
	 * They have ifindex != iflink because iflink points to the
	 * underlying physical device.  Renaming them would corrupt the
	 * kernel-supplied name.
	 */
	{
		char ifindex_s[16] = "", iflink_s[16] = "";

		snprintf(path, sizeof(path), "/sys/class/net/%s/ifindex", devname);
		sysfs_read_file(path, ifindex_s, sizeof(ifindex_s));
		snprintf(path, sizeof(path), "/sys/class/net/%s/iflink", devname);
		sysfs_read_file(path, iflink_s, sizeof(iflink_s));
		if (ifindex_s[0] && iflink_s[0] && strcmp(ifindex_s, iflink_s))
			return 0;
	}

	/* Onboard NIC name eno<idx> from BIOS/ACPI firmware. */
	snprintf(path, sizeof(path), "/sys/class/net/%s/device/firmware_node/acpi_index",
		 devname);
	if (sysfs_read_file(path, val, sizeof(val)) != 0) {
		val[0] = '\0';
		snprintf(path, sizeof(path), "/sys/class/net/%s/device/index", devname);
		sysfs_read_file(path, val, sizeof(val));
	}
	if (val[0]) {
		int n = atoi(val);

		if (n > 0) {
			char name[32];

			snprintf(name, sizeof(name), "eno%d", n);
			uevent_setenv(ev, "ID_NET_NAME_ONBOARD", name);
		}
	}

	/* BIOS-supplied label string (informational; surfaces in ip(8)). */
	val[0] = '\0';
	snprintf(path, sizeof(path), "/sys/class/net/%s/device/label", devname);
	if (sysfs_read_file(path, val, sizeof(val)) == 0 && val[0])
		uevent_setenv(ev, "ID_NET_LABEL_ONBOARD", val);

	/* MAC-based predictable name: enx<mac-without-colons> */
	snprintf(path, sizeof(path), "/sys/class/net/%s/address", devname);
	if (sysfs_read_file(path, mac, sizeof(mac)) == 0 && mac[0]) {
		char raw[32] = "";
		char name_mac[48];
		const char *s;
		char *d;

		for (s = mac, d = raw; *s; s++)
			if (*s != ':')
				*d++ = *s;
		*d = '\0';
		snprintf(name_mac, sizeof(name_mac), "enx%s", raw);
		uevent_setenv(ev, "ID_NET_NAME_MAC", name_mac);
	}

	/*
	 * PCI slot-based name: scan the full devpath for DDDD:BB:SS.F and take
	 * the LAST (deepest) match — that is the NIC endpoint, not a parent bridge.
	 */
	if (ev->devpath) {
		const char *p = ev->devpath;
		unsigned int last_bus = 0, last_dev = 0, last_func = 0;
		int found = 0;

		while (*p) {
			unsigned int dom, bus, dev, func;

			if (sscanf(p, "%4x:%2x:%2x.%1x", &dom, &bus, &dev, &func) == 4 &&
			    p[12] == '/') {
				(void)dom;
				last_bus  = bus;
				last_dev  = dev;
				last_func = func;
				found     = 1;
			}
			p++;
		}

		if (found) {
			char name_slot[64];

			if (last_func == 0)
				snprintf(name_slot, sizeof(name_slot),
					 "enp%us%u", last_bus, last_dev);
			else
				snprintf(name_slot, sizeof(name_slot),
					 "enp%us%uf%u", last_bus, last_dev, last_func);
			uevent_setenv(ev, "ID_NET_NAME_SLOT", name_slot);
		}
	}

	/* Driver name */
	if (ev->devpath) {
		char drv[64];
		char syspath[PATH_MAX];

		snprintf(syspath, sizeof(syspath), "/sys%s", ev->devpath);
		if (sysfs_read_driver(syspath, drv, sizeof(drv)) == 0)
			uevent_setenv(ev, "ID_NET_DRIVER", drv);
	}

	return 0;
}

/* ---- blkid ------------------------------------------------------- */

/* Publish base + base_ENC.  Safe form (control chars → '_') for rule
 * matching, encoded form (\xNN escapes) for use in symlink paths. */
static void publish_dual(struct uevent *ev, const char *base, const char *val)
{
	char s[256], key[64];

	blkid_safe_string(val, s, sizeof(s));
	uevent_setenv(ev, base, s);
	blkid_encode_string(val, s, sizeof(s));
	snprintf(key, sizeof(key), "%s_ENC", base);
	uevent_setenv(ev, key, s);
}

/* Publish a single encoded value -- used where the property goes
 * straight into a symlink path (PART_ENTRY_NAME, CD media IDs). */
static void publish_encoded(struct uevent *ev, const char *key, const char *val)
{
	char s[256];

	blkid_encode_string(val, s, sizeof(s));
	uevent_setenv(ev, key, s);
}

static void publish_blkid(struct uevent *ev, const char *name, const char *val)
{
	if (!strcmp(name, "TYPE"))
		uevent_setenv(ev, "ID_FS_TYPE", val);
	else if (!strcmp(name, "USAGE"))
		uevent_setenv(ev, "ID_FS_USAGE", val);
	else if (!strcmp(name, "VERSION"))
		uevent_setenv(ev, "ID_FS_VERSION", val);
	else if (!strcmp(name, "UUID"))
		publish_dual(ev, "ID_FS_UUID", val);
	else if (!strcmp(name, "UUID_SUB"))
		publish_dual(ev, "ID_FS_UUID_SUB", val);
	else if (!strcmp(name, "LABEL"))
		publish_dual(ev, "ID_FS_LABEL", val);
	else if (!strcmp(name, "PTTYPE"))
		uevent_setenv(ev, "ID_PART_TABLE_TYPE", val);
	else if (!strcmp(name, "PTUUID"))
		uevent_setenv(ev, "ID_PART_TABLE_UUID", val);
	else if (!strcmp(name, "PART_ENTRY_NAME"))
		publish_encoded(ev, "ID_PART_ENTRY_NAME", val);
	else if (!strcmp(name, "PART_ENTRY_TYPE"))
		publish_encoded(ev, "ID_PART_ENTRY_TYPE", val);
	else if (!strncmp(name, "PART_ENTRY_", 11)) {
		/* Generic fall-through: keep this AFTER the specific
		 * PART_ENTRY_NAME/TYPE branches above. */
		char key[64];

		snprintf(key, sizeof(key), "ID_%s", name);
		uevent_setenv(ev, key, val);
	}
	else if (!strcmp(name, "SYSTEM_ID"))
		publish_encoded(ev, "ID_FS_SYSTEM_ID", val);
	else if (!strcmp(name, "PUBLISHER_ID"))
		publish_encoded(ev, "ID_FS_PUBLISHER_ID", val);
	else if (!strcmp(name, "APPLICATION_ID"))
		publish_encoded(ev, "ID_FS_APPLICATION_ID", val);
	else if (!strcmp(name, "BOOT_SYSTEM_ID"))
		publish_encoded(ev, "ID_FS_BOOT_SYSTEM_ID", val);
}

static int builtin_blkid(struct uevent *ev, int argc, char **argv)
{
	char        devpath[PATH_MAX];
	blkid_probe pr;
	int         nvals, i;

	(void)argc;
	(void)argv;

	if (!ev->devname)
		return -1;

	snprintf(devpath, sizeof(devpath), "/dev/%s", ev->devname);

	pr = blkid_new_probe_from_filename(devpath);
	if (!pr)
		return -1;

	blkid_probe_enable_superblocks(pr, 1);
	blkid_probe_set_superblocks_flags(pr,
		BLKID_SUBLKS_LABEL    | BLKID_SUBLKS_UUID    |
		BLKID_SUBLKS_TYPE     | BLKID_SUBLKS_SECTYPE |
		BLKID_SUBLKS_USAGE    | BLKID_SUBLKS_VERSION |
		BLKID_SUBLKS_BADCSUM);

	blkid_probe_enable_partitions(pr, 1);
	blkid_probe_set_partitions_flags(pr, BLKID_PARTS_ENTRY_DETAILS);

	if (blkid_do_safeprobe(pr) == 0) {
		if (blkid_probe_has_value(pr, "SBBADCSUM"))
			logit(LOG_WARNING, "blkid: %s has bad superblock checksum",
			      devpath);

		nvals = blkid_probe_numof_values(pr);
		for (i = 0; i < nvals; i++) {
			const char *name, *val;

			if (blkid_probe_get_value(pr, i, &name, &val, NULL) == 0)
				publish_blkid(ev, name, val);
		}
	}

	blkid_free_probe(pr);
	return 0;
}

/* ---- dispatch ---------------------------------------------------- */

typedef int (*builtin_fn)(struct uevent *ev, int argc, char **argv);

static const struct {
	const char *name;
	builtin_fn  fn;
} builtin_table[] = {
	{ "kmod",     builtin_kmod     },
	{ "hwdb",     builtin_hwdb     },
	{ "path_id",  builtin_path_id  },
	{ "usb_id",   builtin_usb_id   },
	{ "input_id", builtin_input_id },
	{ "net_id",   builtin_net_id   },
	{ "blkid",    builtin_blkid    },
};

int builtin_run(struct uevent *ev, const char *cmd)
{
	char  buf[PATH_MAX];
	char *argv[16];
	int   argc = 0;
	char *p;
	size_t i;

	strncpy(buf, cmd, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';

	p = buf;
	while (argc < 15) {
		char  q   = 0;
		char *out;

		while (isspace((unsigned char)*p))
			p++;
		if (!*p)
			break;

		/* shell-style quoting: '...' or "..." consume the quotes */
		if (*p == '\'' || *p == '"') {
			q = *p++;
		}

		argv[argc++] = out = p;
		while (*p) {
			if (q) {
				if (*p == q) {
					p++;
					break;
				}
			} else if (isspace((unsigned char)*p)) {
				break;
			}
			*out++ = *p++;
		}
		if (*p)
			p++;
		*out = '\0';
	}
	argv[argc] = NULL;

	if (!argc)
		return -1;

	for (i = 0; i < sizeof(builtin_table) / sizeof(builtin_table[0]); i++) {
		if (!strcmp(argv[0], builtin_table[i].name)) {
			logit(LOG_DEBUG, "rules: builtin %s", argv[0]);
			return builtin_table[i].fn(ev, argc, argv);
		}
	}

	logit(LOG_DEBUG, "rules: unknown builtin '%s'", argv[0]);
	return -1;
}

int builtin_has(const char *name)
{
	size_t i;

	if (!name)
		return 0;
	for (i = 0; i < sizeof(builtin_table) / sizeof(builtin_table[0]); i++) {
		if (!strcmp(name, builtin_table[i].name))
			return 1;
	}
	return 0;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
