/* libink — D-Bus body marshalling (writer side).
 *
 * Copyright (c) 2026  Joachim Wiberg <troglobit@gmail.com>
 * SPDX-License-Identifier: MIT
 */
#ifndef LIBINK_MARSHAL_H_
#define LIBINK_MARSHAL_H_

#include <stddef.h>
#include <stdint.h>

/* struct ink_writer is defined in ink.h (public).  Field layout is
 * "opaque" per the public contract; this file's helpers manipulate
 * the fields directly. */
#include "ink.h"

void    ink__w_init  (struct ink_writer *w, uint8_t *buf, size_t cap);
ssize_t ink__w_finish(struct ink_writer *w);

void ink__w_byte    (struct ink_writer *w, uint8_t v);
void ink__w_bool    (struct ink_writer *w, int v);
void ink__w_u32     (struct ink_writer *w, uint32_t v);
void ink__w_string  (struct ink_writer *w, const char *s);  /* "s" */
void ink__w_path    (struct ink_writer *w, const char *s);  /* "o" */
void ink__w_sig     (struct ink_writer *w, const char *s);  /* "g" */

/* element_sig_first_char drives the alignment padding inserted
 * between the array length prefix and the first element. */
void ink__w_array_begin (struct ink_writer *w, char element_sig_first_char);
void ink__w_array_end   (struct ink_writer *w);

void ink__w_struct_begin(struct ink_writer *w);
void ink__w_struct_end  (struct ink_writer *w);

/* ---- reader ----
 *
 * Reads from a message body pointer + length, advancing a cursor.
 * String pointers returned by ink__r_string reference the input
 * buffer and are valid for the lifetime of that buffer (i.e. for
 * the duration of the current call dispatch). */
struct ink_reader {
	const uint8_t *base;
	size_t         off;
	size_t         cap;
	int            err;	/* sticky */
};

void ink__r_init  (struct ink_reader *r, const uint8_t *body, size_t len);
int  ink__r_byte  (struct ink_reader *r, uint8_t *out);
int  ink__r_bool  (struct ink_reader *r, int      *out);
int  ink__r_u32   (struct ink_reader *r, uint32_t *out);
int  ink__r_string(struct ink_reader *r, const char **out);  /* "s" */
int  ink__r_path  (struct ink_reader *r, const char **out);  /* "o" */
int  ink__r_done  (const struct ink_reader *r);

#endif /* LIBINK_MARSHAL_H_ */
