/* libink internal types — not for external consumers.
 *
 * Copyright (c) 2026  Joachim Wiberg <troglobit@gmail.com>
 * SPDX-License-Identifier: MIT
 */
#ifndef LIBINK_INK_INTERNAL_H_
#define LIBINK_INK_INTERNAL_H_

#include <stdint.h>

#include "ink.h"

typedef enum {
	INK_AUTH_NUL = 0,	/* waiting for the leading nul byte */
	INK_AUTH_LINE,		/* line-mode SASL exchange */
	INK_AUTH_DONE,		/* BEGIN received, binary mode */
	INK_AUTH_FAILED,	/* terminal: drop the connection */
} ink_auth_state_t;

/* AF_UNIX sun_path is 108 bytes on Linux, 104 on BSD — bound to the
 * Linux value, which is the maximum we'll ever encounter. */
#define INK_PATH_MAX          108
#define INK_AUTH_LINEBUF_SIZE 256

struct ink_server {
	int  fd;
	char path[INK_PATH_MAX];
};

struct ink_connection {
	int              fd;
	uid_t            peer_uid;

	/* Server-assigned GUID, 32 hex chars + nul. */
	char             guid[33];

	ink_auth_state_t auth;
	char             linebuf[INK_AUTH_LINEBUF_SIZE];
	size_t           linelen;
};

int  ink__auth_process(ink_connection_t *conn);
void ink__auth_generate_guid(char out[33]);

#endif /* LIBINK_INK_INTERNAL_H_ */
