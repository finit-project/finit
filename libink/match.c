/* libink — D-Bus AddMatch / RemoveMatch rule parsing and matching.
 *
 * Subset of the spec: type, interface, member, path.  Each entry is
 * a key='value' pair with single-quoted value, separated by commas.
 * Backslash escapes inside values (\\ and \') are not interpreted —
 * a peer needing them will get unexpected literal content.  Unknown
 * keys cause the whole rule to be rejected so a peer learns its
 * filter didn't take, rather than silently receiving everything.
 *
 * Copyright (c) 2026  Joachim Wiberg <troglobit@gmail.com>
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "ink-internal.h"

static char *dup_range(const char *p, size_t n)
{
	char *s = malloc(n + 1);

	if (!s)
		return NULL;
	memcpy(s, p, n);
	s[n] = '\0';
	return s;
}

/* Parse one key='value' entry starting at *p.  On success advances
 * *p past the trailing quote and any comma, returns 0.  On malformed
 * input, returns -1. */
static int parse_kv(const char **p, char **out_key, char **out_value)
{
	const char *q = *p;
	const char *key_start, *val_start;

	while (*q == ' ' || *q == '\t')
		q++;
	key_start = q;
	while ((*q >= 'a' && *q <= 'z') || (*q >= 'A' && *q <= 'Z') || *q == '_')
		q++;
	if (q == key_start || *q != '=')
		return -1;
	*out_key = dup_range(key_start, (size_t)(q - key_start));
	if (!*out_key)
		return -1;
	q++;

	if (*q != '\'') {
		free(*out_key);
		return -1;
	}
	q++;
	val_start = q;
	while (*q && *q != '\'')
		q++;
	if (*q != '\'') {
		free(*out_key);
		return -1;
	}
	*out_value = dup_range(val_start, (size_t)(q - val_start));
	if (!*out_value) {
		free(*out_key);
		return -1;
	}
	q++;

	while (*q == ' ' || *q == '\t' || *q == ',')
		q++;
	*p = q;
	return 0;
}

struct ink_match *ink__match_parse(const char *rule)
{
	struct ink_match *m;
	const char       *p;

	if (!rule || strlen(rule) >= INK_MATCH_RULE_MAX) {
		errno = EINVAL;
		return NULL;
	}

	m = calloc(1, sizeof(*m));
	if (!m)
		return NULL;
	m->raw = strdup(rule);
	if (!m->raw) {
		free(m);
		return NULL;
	}

	for (p = rule; *p; ) {
		char *key = NULL, *value = NULL;
		char **slot = NULL;

		if (parse_kv(&p, &key, &value) < 0)
			goto bad;

		if (!strcmp(key, "type"))           slot = &m->type;
		else if (!strcmp(key, "interface")) slot = &m->interface;
		else if (!strcmp(key, "member"))    slot = &m->member;
		else if (!strcmp(key, "path"))      slot = &m->path;
		else {
			free(key);
			free(value);
			goto bad;
		}

		if (*slot) {
			/* Duplicate key. */
			free(key);
			free(value);
			goto bad;
		}
		*slot = value;
		free(key);
	}

	/* No need to default m->type: when it's NULL the matcher below
	 * treats it as "match any", and the only thing libink emits via
	 * the match table is signals, so the effective filter is
	 * already "signal" without the explicit assignment. */
	return m;

bad:
	ink__match_free(m);
	errno = EINVAL;
	return NULL;
}

void ink__match_free(struct ink_match *m)
{
	if (!m)
		return;
	free(m->raw);
	free(m->type);
	free(m->interface);
	free(m->member);
	free(m->path);
	free(m);
}

static int field_matches(const char *want, const char *got)
{
	if (!want)
		return 1;	/* no filter on this field */
	if (!got)
		return 0;
	return strcmp(want, got) == 0;
}

int ink__match_matches(const struct ink_match *m,
		       const char *path, const char *iface,
		       const char *member)
{
	/* Type filter: only signals get delivered through this path. */
	if (m->type && strcmp(m->type, "signal") != 0)
		return 0;

	return field_matches(m->path,      path)
	    && field_matches(m->interface, iface)
	    && field_matches(m->member,    member);
}

int ink__match_add(ink_connection_t *conn, const char *rule)
{
	struct ink_match *m;

	if (conn->matches_count >= INK_MATCH_PEER_CAP) {
		errno = ENOSPC;
		return -1;
	}

	m = ink__match_parse(rule);
	if (!m)
		return -1;

	conn->matches[conn->matches_count++] = m;
	return 0;
}

int ink__match_remove(ink_connection_t *conn, const char *rule)
{
	size_t i;

	for (i = 0; i < conn->matches_count; i++) {
		if (strcmp(conn->matches[i]->raw, rule) == 0) {
			ink__match_free(conn->matches[i]);
			conn->matches[i] = conn->matches[conn->matches_count - 1];
			conn->matches_count--;
			return 0;
		}
	}
	errno = ENOENT;
	return -1;
}
