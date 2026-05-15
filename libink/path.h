/* libink — D-Bus object-path encoding for arbitrary identifiers.
 *
 * Copyright (c) 2026  Joachim Wiberg <troglobit@gmail.com>
 * SPDX-License-Identifier: MIT
 */
#ifndef LIBINK_PATH_H_
#define LIBINK_PATH_H_

#include <stddef.h>

/* Encode `in` as a D-Bus path segment.  Bytes in [A-Za-z0-9] pass
 * through unchanged; everything else (including '_' itself) becomes
 * "_HH" with lowercase hex, mirroring systemd's escape_path.
 *
 * Returns the encoded length (excluding the terminating nul), or -1
 * if the output buffer cannot fit the result.  `outsz` must
 * accommodate the encoded bytes plus a trailing nul; the worst-case
 * size for an N-byte input is 3*N + 1. */
int ink_path_encode(const char *in, char *out, size_t outsz);

#endif /* LIBINK_PATH_H_ */
