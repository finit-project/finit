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
#ifndef LIBINK_LINK_H_
#define LIBINK_LINK_H_

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct link_server     link_server_t;
typedef struct link_connection link_connection_t;
typedef struct link_call       link_call_t;
typedef struct link_client     link_client_t;

/* Writer is exposed so callers can stack-allocate one for marshalling
 * signal/reply bodies.  Treat the fields as opaque; use link_writer_init
 * + the link_w_* helpers + link_writer_finish.  Sized for typical D-Bus
 * messages -- the array stack supports up to 8 levels of nesting. */
#define LINK_WRITER_MAX_NESTING 8
typedef struct link_writer {
	uint8_t *buf;
	size_t   cap;
	size_t   off;
	int      err;
	struct {
		size_t lenpos;
		size_t elemstart;
	}      arrays[LINK_WRITER_MAX_NESTING];
	size_t array_depth;
} link_writer_t;

/* ----------  server / connection lifecycle  ---------- */

int   link_server_new   (link_server_t **server, const char *path);
void  link_server_free  (link_server_t  *server);
int   link_server_get_fd(const link_server_t *server);

int   link_server_accept(link_server_t *server, link_connection_t **conn);

int   link_connection_get_fd  (const link_connection_t *conn);
uid_t link_connection_get_uid (const link_connection_t *conn);
int   link_connection_process (link_connection_t *conn);
void  link_connection_close   (link_connection_t *conn);

/* ----------  object registration  ---------- */

typedef int (*link_method_fn)(link_call_t *call, void *userdata);

/* Method flags for link_method_t.flags */
#define LINK_METHOD_PRIVILEGED  (1u << 0)  /* peer must be uid 0 (root) */

typedef struct {
	const char    *name;     /* member name */
	const char    *in_sig;   /* input  signature (D-Bus, e.g. "" or "s") */
	const char    *out_sig;  /* output signature */
	unsigned       flags;    /* OR of LINK_METHOD_* */
	link_method_fn  handler;
} link_method_t;

typedef struct {
	const char         *interface;          /* e.g. "org.finit.Manager1" */
	const link_method_t *methods;            /* terminated by {NULL, ...} */
} link_vtable_t;

/* Register one (interface, methods) at `path`.  Calling repeatedly
 * with the same path and different vtables adds more interfaces at
 * that object.  The vtable pointer must outlive the server (typically
 * a static table). */
int link_server_add_object(link_server_t *server, const char *path,
			  const link_vtable_t *vt, void *userdata);

/* Remove every vtable registered at `path` and free the object.
 * Returns 0 if the object existed, -1 (errno=ENOENT) otherwise. */
int link_server_remove_object(link_server_t *server, const char *path);

/* ----------  call accessors  ---------- */

const char *link_call_path     (const link_call_t *call);
const char *link_call_interface(const link_call_t *call);
const char *link_call_member   (const link_call_t *call);
uid_t       link_call_uid      (const link_call_t *call);

/* ----------  reading method-call arguments  ----------
 *
 * Cursor starts at the beginning of the request body.  Each
 * function returns 0 on success and advances the cursor; on
 * failure it returns -1 and leaves the cursor in an error state
 * (subsequent reads also fail).  Strings reference the
 * connection's rx buffer and are valid for the duration of the
 * method handler. */

int link_call_read_byte  (link_call_t *call, uint8_t  *out);
int link_call_read_bool  (link_call_t *call, int      *out);
int link_call_read_u32   (link_call_t *call, uint32_t *out);
int link_call_read_string(link_call_t *call, const char **out);  /* "s" */
int link_call_read_path  (link_call_t *call, const char **out);  /* "o" */

/* ----------  reply construction  ---------- */

/* Get the writer for the reply body, write args into it, return 0
 * from the handler.  Dispatch finalizes and sends the reply with
 * the out_sig declared on the vtable.  May be called once per
 * call. */
link_writer_t *link_call_reply(link_call_t *call);

/* Send a D-Bus error reply.  `name` must be a valid D-Bus error
 * name (e.g. "org.freedesktop.DBus.Error.UnknownMethod"); `message`
 * may be NULL. */
int link_call_reply_error(link_call_t *call, const char *name, const char *message);

/* ----------  signal emission  ----------
 *
 * Send a signal to a single peer if its AddMatch rules accept it.
 * Callers marshal the body separately and pass the resulting bytes.
 * Returns 0 on success (or "filtered out, nothing sent"), -1 with
 * errno set on failure: EMSGSIZE and EINVAL mean nothing hit the
 * wire and the connection is still usable; anything else is a
 * transport failure that may have left a partial frame -- the
 * caller must drop the peer. */
int link_connection_emit_signal(link_connection_t *conn,
			       const char *path,
			       const char *interface,
			       const char *member,
			       const char *signature,
			       const uint8_t *body, size_t body_len);

/* ----------  client (outgoing method calls)  ----------
 *
 * Connect, authenticate as the current effective uid, send BEGIN.
 * Returns NULL on any failure (caller can fall back to another
 * transport if it has one). */
link_client_t *link_client_open(const char *path);
void           link_client_close(link_client_t *c);

/* Status codes returned by link_client_call. */
#define LINK_CALL_OK     0   /* method-return received */
#define LINK_CALL_ERROR  1   /* server replied with an error */
#define LINK_CALL_FAIL  (-1) /* transport, parse, or invalid-arg failure */

/* Send a METHOD_CALL and read the reply synchronously.
 *
 * `signature` and `body`/`body_len` describe the outgoing body --
 * marshal it yourself with link_writer_init + the link_w_* helpers
 * + link_writer_finish.  Pass signature=NULL and body=NULL for
 * methods that take no arguments.
 *
 * On LINK_CALL_ERROR the peer's org.* error name is copied into
 * err_buf (truncated if needed; pass NULL if you don't care). */
int link_client_call(link_client_t *c,
		     const char *obj_path,
		     const char *interface,
		     const char *member,
		     const char *signature,
		     const uint8_t *body, size_t body_len,
		     char *err_buf, size_t err_buf_sz);

/* ----------  standalone writer  ----------
 *
 * For marshalling bodies outside a method-call handler (signals,
 * pre-computed replies).  Initialise on a caller-owned buffer,
 * write args via link_w_*, then call link_writer_finish which
 * returns the body length or -1 on overflow. */
void    link_writer_init  (link_writer_t *w, uint8_t *buf, size_t cap);
ssize_t link_writer_finish(link_writer_t *w);

/* ----------  writer (mirrors the internal marshaller)  ---------- */

void link_w_byte    (link_writer_t *w, uint8_t v);
void link_w_bool    (link_writer_t *w, int v);
void link_w_u32     (link_writer_t *w, uint32_t v);
void link_w_string  (link_writer_t *w, const char *s);  /* "s" */
void link_w_path    (link_writer_t *w, const char *s);  /* "o" */
void link_w_array_begin (link_writer_t *w, char element_sig);
void link_w_array_end   (link_writer_t *w);
void link_w_struct_begin(link_writer_t *w);
void link_w_struct_end  (link_writer_t *w);

#ifdef __cplusplus
}
#endif

#endif /* LIBINK_LINK_H_ */
