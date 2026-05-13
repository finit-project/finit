/* libink — brokerless D-Bus server library, born inside Finit
 *
 * Copyright (c) 2026  Joachim Wiberg <troglobit@gmail.com>
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
#ifndef LIBINK_INK_H_
#define LIBINK_INK_H_

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ink_server     ink_server_t;
typedef struct ink_connection ink_connection_t;

/* Server lifecycle.  path is the AF_UNIX socket pathname to bind. */
int   ink_server_new   (ink_server_t **server, const char *path);
void  ink_server_free  (ink_server_t  *server);
int   ink_server_get_fd(const ink_server_t *server);

/* Accept a pending connection from the listening socket.  On success
 * returns 0 and stores a new connection in *conn.  Returns -1 with
 * errno set if accept() failed or memory could not be allocated.
 * Callers should use ink_connection_get_fd() to register the new
 * connection with their event loop. */
int   ink_server_accept(ink_server_t *server, ink_connection_t **conn);

/* Per-connection. */
int   ink_connection_get_fd (const ink_connection_t *conn);
uid_t ink_connection_get_uid(const ink_connection_t *conn);

/* Drive the connection state machine when its fd is readable.  Returns
 * 0 on success (keep watching), -1 on error or peer close (caller
 * should drop the connection via ink_connection_close()). */
int   ink_connection_process(ink_connection_t *conn);

void  ink_connection_close  (ink_connection_t *conn);

#ifdef __cplusplus
}
#endif

#endif /* LIBINK_INK_H_ */
