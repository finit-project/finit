/* sysfs attribute reader and parent-chain walker for keventd
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

#ifndef KEVENTD_SYSFS_H_
#define KEVENTD_SYSFS_H_

#include <stddef.h>

/*
 * Read the first line from an absolute path.
 * Returns 0 on success, -1 on failure.
 */
int sysfs_read_file(const char *path, char *buf, size_t len);

/*
 * Read a sysfs attribute for the device at /sys{devpath}.
 * attr may be a relative path like "device/vendor" or "../serial".
 * Returns 0 on success, -1 if the attribute does not exist.
 */
int sysfs_read_attr(const char *devpath, const char *attr,
		    char *buf, size_t len);

/*
 * Walk the sysfs device tree upward from devpath toward /sys/devices,
 * calling cb at each level.  cb receives the absolute syspath and the
 * caller-supplied data pointer.  Walk stops when cb returns 0 (found)
 * or the tree root is reached.
 * Returns 0 if cb returned 0, -1 if nothing matched.
 */
int sysfs_parent_walk(const char *devpath,
		      int (*cb)(const char *syspath, void *data),
		      void *data);

/*
 * Read the subsystem name at syspath by following the "subsystem"
 * symlink and returning its basename.
 * Returns 0 on success, -1 if there is no subsystem link.
 */
int sysfs_read_subsystem(const char *syspath, char *buf, size_t len);

/*
 * Read the driver name at syspath by following the "driver" symlink
 * and returning its basename.
 * Returns 0 on success, -1 if there is no driver link.
 */
int sysfs_read_driver(const char *syspath, char *buf, size_t len);

#endif /* KEVENTD_SYSFS_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
