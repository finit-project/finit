/* libink — D-Bus body marshalling (writer side).
 *
 * Copyright (c) 2026  Joachim Wiberg <troglobit@gmail.com>
 * SPDX-License-Identifier: MIT
 */

#include <string.h>
#include <sys/types.h>

#include "marshal.h"

#define ALIGN_UP(x, n) (((x) + (n) - 1) & ~((size_t)((n) - 1)))

void ink__w_init(struct ink_writer *w, uint8_t *buf, size_t cap)
{
	w->buf         = buf;
	w->cap         = cap;
	w->off         = 0;
	w->err         = 0;
	w->array_depth = 0;
}

ssize_t ink__w_finish(struct ink_writer *w)
{
	if (w->err || w->array_depth != 0)
		return -1;
	return (ssize_t)w->off;
}

static int reserve(struct ink_writer *w, size_t align, size_t bytes)
{
	size_t pad;

	if (w->err)
		return -1;

	pad = ALIGN_UP(w->off, align) - w->off;
	if (w->off + pad + bytes > w->cap) {
		w->err = 1;
		return -1;
	}
	while (pad-- > 0)
		w->buf[w->off++] = 0;
	return 0;
}

static void put_u32_at(struct ink_writer *w, size_t pos, uint32_t v)
{
	w->buf[pos]     = (uint8_t)(v       & 0xff);
	w->buf[pos + 1] = (uint8_t)((v >> 8)  & 0xff);
	w->buf[pos + 2] = (uint8_t)((v >> 16) & 0xff);
	w->buf[pos + 3] = (uint8_t)((v >> 24) & 0xff);
}

static void put_u32(struct ink_writer *w, uint32_t v)
{
	put_u32_at(w, w->off, v);
	w->off += 4;
}

void ink__w_byte(struct ink_writer *w, uint8_t v)
{
	if (reserve(w, 1, 1) < 0)
		return;
	w->buf[w->off++] = v;
}

void ink__w_bool(struct ink_writer *w, int v)
{
	if (reserve(w, 4, 4) < 0)
		return;
	put_u32(w, v ? 1u : 0u);
}

void ink__w_u32(struct ink_writer *w, uint32_t v)
{
	if (reserve(w, 4, 4) < 0)
		return;
	put_u32(w, v);
}

static void write_lenprefixed(struct ink_writer *w, const char *s, int onebyte_len)
{
	size_t len = s ? strlen(s) : 0;

	if (onebyte_len) {
		if (reserve(w, 1, 1 + len + 1) < 0)
			return;
		w->buf[w->off++] = (uint8_t)len;
	} else {
		if (reserve(w, 4, 4 + len + 1) < 0)
			return;
		put_u32(w, (uint32_t)len);
	}
	if (s && len)
		memcpy(w->buf + w->off, s, len);
	w->off += len;
	w->buf[w->off++] = 0;
}

void ink__w_string(struct ink_writer *w, const char *s) { write_lenprefixed(w, s, 0); }
void ink__w_path  (struct ink_writer *w, const char *s) { write_lenprefixed(w, s, 0); }
void ink__w_sig   (struct ink_writer *w, const char *s) { write_lenprefixed(w, s, 1); }

static size_t element_align(char c)
{
	switch (c) {
	case 'y': case 'g': case 'v':           return 1;
	case 'n': case 'q':                     return 2;
	case 'b': case 'i': case 'u':
	case 's': case 'o': case 'h': case 'a': return 4;
	case 'x': case 't': case 'd':
	case '(': case '{':                     return 8;
	default:                                return 1;
	}
}

void ink__w_array_begin(struct ink_writer *w, char element_sig_first_char)
{
	size_t lenpos;

	if (w->err)
		return;
	if (w->array_depth >= INK_WRITER_MAX_NESTING) {
		w->err = 1;
		return;
	}

	if (reserve(w, 4, 4) < 0)
		return;
	lenpos    = w->off;
	put_u32(w, 0);	/* placeholder */

	/* Pad to the element's alignment.  These pad bytes are NOT
	 * counted in the array length per the D-Bus spec. */
	if (reserve(w, element_align(element_sig_first_char), 0) < 0)
		return;

	w->arrays[w->array_depth].lenpos    = lenpos;
	w->arrays[w->array_depth].elemstart = w->off;
	w->array_depth++;
}

void ink__w_array_end(struct ink_writer *w)
{
	size_t   elemstart, lenpos;
	uint32_t actual;

	if (w->err || w->array_depth == 0) {
		w->err = 1;
		return;
	}
	w->array_depth--;
	lenpos    = w->arrays[w->array_depth].lenpos;
	elemstart = w->arrays[w->array_depth].elemstart;
	actual    = (uint32_t)(w->off - elemstart);
	put_u32_at(w, lenpos, actual);
}

void ink__w_struct_begin(struct ink_writer *w)
{
	reserve(w, 8, 0);
}

void ink__w_struct_end(struct ink_writer *w)
{
	(void)w;
}

/* ---- reader ---- */

void ink__r_init(struct ink_reader *r, const uint8_t *body, size_t len)
{
	r->base = body;
	r->off  = 0;
	r->cap  = len;
	r->err  = 0;
}

static int r_skip_align(struct ink_reader *r, size_t align)
{
	size_t pad;

	if (r->err)
		return -1;
	pad = ALIGN_UP(r->off, align) - r->off;
	if (r->off + pad > r->cap) {
		r->err = 1;
		return -1;
	}
	r->off += pad;
	return 0;
}

static uint32_t rd_u32(const uint8_t *p)
{
	return (uint32_t)p[0]
	     | ((uint32_t)p[1] << 8)
	     | ((uint32_t)p[2] << 16)
	     | ((uint32_t)p[3] << 24);
}

int ink__r_byte(struct ink_reader *r, uint8_t *out)
{
	if (r_skip_align(r, 1) < 0 || r->off + 1 > r->cap) {
		r->err = 1;
		return -1;
	}
	*out = r->base[r->off++];
	return 0;
}

int ink__r_u32(struct ink_reader *r, uint32_t *out)
{
	if (r_skip_align(r, 4) < 0 || r->off + 4 > r->cap) {
		r->err = 1;
		return -1;
	}
	*out = rd_u32(r->base + r->off);
	r->off += 4;
	return 0;
}

int ink__r_bool(struct ink_reader *r, int *out)
{
	uint32_t v;

	if (ink__r_u32(r, &v) < 0)
		return -1;
	*out = v ? 1 : 0;
	return 0;
}

static int read_string_like(struct ink_reader *r, const char **out)
{
	uint32_t len;

	if (ink__r_u32(r, &len) < 0)
		return -1;
	if (r->off + (size_t)len + 1 > r->cap) {
		r->err = 1;
		return -1;
	}
	/* Spec requires nul terminator at base[off + len]. */
	if (r->base[r->off + len] != 0) {
		r->err = 1;
		return -1;
	}
	*out = (const char *)(r->base + r->off);
	r->off += (size_t)len + 1;
	return 0;
}

int ink__r_string(struct ink_reader *r, const char **out) { return read_string_like(r, out); }
int ink__r_path  (struct ink_reader *r, const char **out) { return read_string_like(r, out); }

int ink__r_done(const struct ink_reader *r)
{
	return !r->err && r->off == r->cap;
}
