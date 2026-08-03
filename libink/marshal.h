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
#include "link.h"

void    __w_init  (struct link_writer *w, uint8_t *buf, size_t cap);
ssize_t __w_finish(struct link_writer *w);

void __w_byte    (struct link_writer *w, uint8_t v);
void __w_bool    (struct link_writer *w, int v);
void __w_u32     (struct link_writer *w, uint32_t v);
void __w_string  (struct link_writer *w, const char *s);  /* "s" */
void __w_path    (struct link_writer *w, const char *s);  /* "o" */
void __w_sig     (struct link_writer *w, const char *s);  /* "g" */
void __w_variant_string(struct link_writer *w, const char *s);  /* "v" containing "s" */

/* element_sig_first_char drives the alignment padding inserted
 * between the array length prefix and the first element. */
void __w_array_begin (struct link_writer *w, char element_sig_first_char);
void __w_array_end   (struct link_writer *w);

void __w_struct_begin(struct link_writer *w);
void __w_struct_end  (struct link_writer *w);

/* ---- reader ----
 *
 * Reads from a message body pointer + length, advancing a cursor.
 * struct link_reader is defined in link.h (public, opaque); the
 * helpers here manipulate the fields directly. */
void __r_init  (struct link_reader *r, const uint8_t *body, size_t len);
int  __r_byte  (struct link_reader *r, uint8_t *out);
int  __r_bool  (struct link_reader *r, int      *out);
int  __r_u32   (struct link_reader *r, uint32_t *out);
int  __r_string(struct link_reader *r, const char **out);  /* "s" */
int  __r_path  (struct link_reader *r, const char **out);  /* "o" */
int  __r_variant_begin (struct link_reader *r, char *type);       /* sig header, cursor at value */
int  __r_skip_basic    (struct link_reader *r, char type);        /* skip one basic value */
int  __r_variant_string(struct link_reader *r, const char **out); /* "v" containing "s" */
int  __r_variant_u32   (struct link_reader *r, uint32_t *out);    /* "v" containing "u" */
int  __r_align (struct link_reader *r, size_t n);  /* skip to n-byte boundary */
int  __r_array_begin(struct link_reader *r, size_t *out_end);
int  __r_done  (const struct link_reader *r);

#endif /* LIBINK_MARSHAL_H_ */
