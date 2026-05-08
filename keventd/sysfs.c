/* sysfs attribute reader and parent-chain walker
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

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef _LIBITE_LITE
# include <libite/lite.h>
#else
# include <lite/lite.h>
#endif

#include "sysfs.h"

int sysfs_read_file(const char *path, char *buf, size_t len)
{
	FILE *fp;

	fp = fopen(path, "r");
	if (!fp)
		return -1;

	if (!fgets(buf, len, fp)) {
		fclose(fp);
		return -1;
	}

	fclose(fp);
	chomp(buf);
	return 0;
}

int sysfs_read_attr(const char *devpath, const char *attr,
		    char *buf, size_t len)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "/sys%s/%s", devpath, attr);
	return sysfs_read_file(path, buf, len);
}

int sysfs_parent_walk(const char *devpath,
		      int (*cb)(const char *syspath, void *data),
		      void *data)
{
	char syspath[PATH_MAX];
	char *p;

	snprintf(syspath, sizeof(syspath), "/sys%s", devpath);

	while (1) {
		if (cb(syspath, data) == 0)
			return 0;

		/* Strip last path component */
		p = strrchr(syspath, '/');
		if (!p || p == syspath)
			break;
		*p = 0;

		/* Do not walk above /sys/devices */
		if (!strcmp(syspath, "/sys/devices") ||
		    !strcmp(syspath, "/sys"))
			break;
	}

	return -1;
}

int sysfs_read_subsystem(const char *syspath, char *buf, size_t len)
{
	char lpath[PATH_MAX], target[PATH_MAX];
	const char *p;
	ssize_t n;

	snprintf(lpath, sizeof(lpath), "%s/subsystem", syspath);
	n = readlink(lpath, target, sizeof(target) - 1);
	if (n < 0)
		return -1;
	target[n] = 0;

	p = strrchr(target, '/');
	snprintf(buf, len, "%s", p ? p + 1 : target);
	return 0;
}

int sysfs_read_driver(const char *syspath, char *buf, size_t len)
{
	char lpath[PATH_MAX], target[PATH_MAX];
	const char *p;
	ssize_t n;

	snprintf(lpath, sizeof(lpath), "%s/driver", syspath);
	n = readlink(lpath, target, sizeof(target) - 1);
	if (n < 0)
		return -1;
	target[n] = 0;

	p = strrchr(target, '/');
	snprintf(buf, len, "%s", p ? p + 1 : target);
	return 0;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
