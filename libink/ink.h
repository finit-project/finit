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
typedef struct ink_call       ink_call_t;
typedef struct ink_writer     ink_writer_t;

/* ----------  server / connection lifecycle  ---------- */

int   ink_server_new   (ink_server_t **server, const char *path);
void  ink_server_free  (ink_server_t  *server);
int   ink_server_get_fd(const ink_server_t *server);

int   ink_server_accept(ink_server_t *server, ink_connection_t **conn);

int   ink_connection_get_fd  (const ink_connection_t *conn);
uid_t ink_connection_get_uid (const ink_connection_t *conn);
int   ink_connection_process (ink_connection_t *conn);
void  ink_connection_close   (ink_connection_t *conn);

/* ----------  object registration  ---------- */

typedef int (*ink_method_fn)(ink_call_t *call, void *userdata);

typedef struct {
	const char    *name;     /* member name */
	const char    *in_sig;   /* input  signature (D-Bus, e.g. "" or "s") */
	const char    *out_sig;  /* output signature */
	ink_method_fn  handler;
} ink_method_t;

typedef struct {
	const char         *interface;          /* e.g. "org.finit.Manager1" */
	const ink_method_t *methods;            /* terminated by {NULL, ...} */
} ink_vtable_t;

/* Register one (interface, methods) at `path`.  Calling repeatedly
 * with the same path and different vtables adds more interfaces at
 * that object.  The vtable pointer must outlive the server (typically
 * a static table). */
int ink_server_add_object(ink_server_t *server, const char *path,
			  const ink_vtable_t *vt, void *userdata);

/* ----------  call accessors  ---------- */

const char *ink_call_path     (const ink_call_t *call);
const char *ink_call_interface(const ink_call_t *call);
const char *ink_call_member   (const ink_call_t *call);
uid_t       ink_call_uid      (const ink_call_t *call);

/* ----------  reading method-call arguments  ----------
 *
 * Cursor starts at the beginning of the request body.  Each
 * function returns 0 on success and advances the cursor; on
 * failure it returns -1 and leaves the cursor in an error state
 * (subsequent reads also fail).  Strings reference the
 * connection's rx buffer and are valid for the duration of the
 * method handler. */

int ink_call_read_byte  (ink_call_t *call, uint8_t  *out);
int ink_call_read_bool  (ink_call_t *call, int      *out);
int ink_call_read_u32   (ink_call_t *call, uint32_t *out);
int ink_call_read_string(ink_call_t *call, const char **out);  /* "s" */
int ink_call_read_path  (ink_call_t *call, const char **out);  /* "o" */

/* ----------  reply construction  ---------- */

/* Get the writer for the reply body, write args into it, return 0
 * from the handler.  Dispatch finalizes and sends the reply with
 * the out_sig declared on the vtable.  May be called once per
 * call. */
ink_writer_t *ink_call_reply(ink_call_t *call);

/* Send a D-Bus error reply.  `name` must be a valid D-Bus error
 * name (e.g. "org.freedesktop.DBus.Error.UnknownMethod"); `message`
 * may be NULL. */
int ink_call_reply_error(ink_call_t *call, const char *name, const char *message);

/* ----------  writer (mirrors the internal marshaller)  ---------- */

void ink_w_byte    (ink_writer_t *w, uint8_t v);
void ink_w_bool    (ink_writer_t *w, int v);
void ink_w_u32     (ink_writer_t *w, uint32_t v);
void ink_w_string  (ink_writer_t *w, const char *s);  /* "s" */
void ink_w_path    (ink_writer_t *w, const char *s);  /* "o" */
void ink_w_array_begin (ink_writer_t *w, char element_sig);
void ink_w_array_end   (ink_writer_t *w);
void ink_w_struct_begin(ink_writer_t *w);
void ink_w_struct_end  (ink_writer_t *w);

#ifdef __cplusplus
}
#endif

#endif /* LIBINK_INK_H_ */
