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

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ink_server     ink_server_t;
typedef struct ink_connection ink_connection_t;
typedef struct ink_call       ink_call_t;

/* Writer is exposed so callers can stack-allocate one for marshalling
 * signal/reply bodies.  Treat the fields as opaque; use ink_writer_init
 * + the ink_w_* helpers + ink_writer_finish.  Sized for typical D-Bus
 * messages -- the array stack supports up to 8 levels of nesting. */
#define INK_WRITER_MAX_NESTING 8
typedef struct ink_writer {
	uint8_t *buf;
	size_t   cap;
	size_t   off;
	int      err;
	struct {
		size_t lenpos;
		size_t elemstart;
	}      arrays[INK_WRITER_MAX_NESTING];
	size_t array_depth;
} ink_writer_t;

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

/* Method flags for ink_method_t.flags */
#define INK_METHOD_PRIVILEGED  (1u << 0)  /* peer must be uid 0 (root) */

typedef struct {
	const char    *name;     /* member name */
	const char    *in_sig;   /* input  signature (D-Bus, e.g. "" or "s") */
	const char    *out_sig;  /* output signature */
	unsigned       flags;    /* OR of INK_METHOD_* */
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

/* Remove every vtable registered at `path` and free the object.
 * Returns 0 if the object existed, -1 (errno=ENOENT) otherwise. */
int ink_server_remove_object(ink_server_t *server, const char *path);

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

/* ----------  signal emission  ----------
 *
 * Send a signal to a single peer if its AddMatch rules accept it.
 * Callers marshal the body separately and pass the resulting bytes.
 * Returns 0 on success (or "filtered out, nothing sent"), -1 with
 * errno set on failure: EMSGSIZE and EINVAL mean nothing hit the
 * wire and the connection is still usable; anything else is a
 * transport failure that may have left a partial frame -- the
 * caller must drop the peer. */
int ink_connection_emit_signal(ink_connection_t *conn,
			       const char *path,
			       const char *interface,
			       const char *member,
			       const char *signature,
			       const uint8_t *body, size_t body_len);

/* ----------  standalone writer  ----------
 *
 * For marshalling bodies outside a method-call handler (signals,
 * pre-computed replies).  Initialise on a caller-owned buffer,
 * write args via ink_w_*, then call ink_writer_finish which
 * returns the body length or -1 on overflow. */
void    ink_writer_init  (ink_writer_t *w, uint8_t *buf, size_t cap);
ssize_t ink_writer_finish(ink_writer_t *w);

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
