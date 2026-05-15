/* libink — D-Bus object-path encoding for arbitrary identifiers.
 *
 * Copyright (c) 2026  Joachim Wiberg <troglobit@gmail.com>
 * SPDX-License-Identifier: MIT
 */

#include <stddef.h>

#include "path.h"

static int is_safe(unsigned char c)
{
	return (c >= 'A' && c <= 'Z')
	    || (c >= 'a' && c <= 'z')
	    || (c >= '0' && c <= '9');
}

int ink_path_encode(const char *in, char *out, size_t outsz)
{
	static const char hex[] = "0123456789abcdef";
	size_t off = 0;

	if (!in || !out || outsz == 0)
		return -1;

	for (; *in; in++) {
		unsigned char c = (unsigned char)*in;

		if (is_safe(c)) {
			if (off + 1 >= outsz)
				return -1;
			out[off++] = (char)c;
		} else {
			if (off + 3 >= outsz)
				return -1;
			out[off++] = '_';
			out[off++] = hex[c >> 4];
			out[off++] = hex[c & 0xf];
		}
	}
	out[off] = '\0';
	return (int)off;
}
