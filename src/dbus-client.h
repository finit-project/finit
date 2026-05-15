/* Minimal D-Bus client used by initctl when /run/finit/bus is
 * available.  This is the client side of the protocol implemented
 * by libink server-side; we don't link libink because that would
 * pull dispatch + builtins + match into initctl unnecessarily.
 *
 * Copyright (c) 2026  Joachim Wiberg <troglobit@gmail.com>
 * SPDX-License-Identifier: MIT
 */
#ifndef FINIT_DBUS_CLIENT_H_
#define FINIT_DBUS_CLIENT_H_

#include <stddef.h>
#include <stdint.h>

#ifdef HAVE_DBUS

typedef struct dbusc dbusc_t;

/* Connect, AUTH EXTERNAL with the caller's real uid, send BEGIN.
 * Returns NULL on any failure (no warning printed -- caller is
 * expected to fall back to a different transport). */
dbusc_t *dbusc_open(const char *path);

void     dbusc_close(dbusc_t *c);

/* Send a method call, await reply.  arg_sig must be "" (no body),
 * "s" (one string argument), or "u" (one uint32 argument).  On an
 * error reply, the error name is copied into err_buf (which may be
 * NULL).
 *
 * Returns:
 *    0  method return (success)
 *    1  error reply  -- err_buf has the org.* error name
 *   -1  transport / parse failure
 */
int dbusc_call(dbusc_t *c,
	       const char *obj_path,
	       const char *iface,
	       const char *method,
	       const char *arg_sig,
	       const char *arg_str,
	       uint32_t    arg_u32,
	       char       *err_buf,
	       size_t      err_buf_sz);

#endif	/* HAVE_DBUS */

#endif	/* FINIT_DBUS_CLIENT_H_ */
