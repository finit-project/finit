/* libink — D-Bus body marshalling (writer side).
 *
 * Copyright (c) 2026  Joachim Wiberg <troglobit@gmail.com>
 * SPDX-License-Identifier: MIT
 */
#ifndef LIBINK_MARSHAL_H_
#define LIBINK_MARSHAL_H_

#include <stddef.h>
#include <stdint.h>

/* struct link_writer is defined in ink.h (public).  Field layout is
 * "opaque" per the public contract; this file's helpers manipulate
 * the fields directly. */
#include "ink.h"

void    link__w_init  (struct link_writer *w, uint8_t *buf, size_t cap);
ssize_t link__w_finish(struct link_writer *w);

void link__w_byte    (struct link_writer *w, uint8_t v);
void link__w_bool    (struct link_writer *w, int v);
void link__w_u32     (struct link_writer *w, uint32_t v);
void link__w_string  (struct link_writer *w, const char *s);  /* "s" */
void link__w_path    (struct link_writer *w, const char *s);  /* "o" */
void link__w_sig     (struct link_writer *w, const char *s);  /* "g" */

/* element_sig_first_char drives the alignment padding inserted
 * between the array length prefix and the first element. */
void link__w_array_begin (struct link_writer *w, char element_sig_first_char);
void link__w_array_end   (struct link_writer *w);

void link__w_struct_begin(struct link_writer *w);
void link__w_struct_end  (struct link_writer *w);

/* ---- reader ----
 *
 * Reads from a message body pointer + length, advancing a cursor.
 * String pointers returned by link__r_string reference the input
 * buffer and are valid for the lifetime of that buffer (i.e. for
 * the duration of the current call dispatch). */
struct link_reader {
	const uint8_t *base;
	size_t         off;
	size_t         cap;
	int            err;	/* sticky */
};

void link__r_init  (struct link_reader *r, const uint8_t *body, size_t len);
int  link__r_byte  (struct link_reader *r, uint8_t *out);
int  link__r_bool  (struct link_reader *r, int      *out);
int  link__r_u32   (struct link_reader *r, uint32_t *out);
int  link__r_string(struct link_reader *r, const char **out);  /* "s" */
int  link__r_path  (struct link_reader *r, const char **out);  /* "o" */
int  link__r_done  (const struct link_reader *r);

#endif /* LIBINK_MARSHAL_H_ */
