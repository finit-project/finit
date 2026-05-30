/* udev rules file parser and matcher for keventd
 *
 * Copyright (c) 2025  Joachim Wiberg <troglobit@gmail.com>
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

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#ifdef _LIBITE_LITE
# include <libite/lite.h>
#else
# include <lite/lite.h>
#endif

#include "builtin.h"
#include "rules.h"
#include "sysfs.h"
#include "udevdb.h"

/* Forward declaration from keventd.c */
void logit(int prio, const char *fmt, ...);

/* ----- key-name lookup -------------------------------------------------- */

static const struct {
	const char       *name;
	rule_key_class_t  cls;
} key_map[] = {
	{ "ACTION",     KEY_ACTION     },
	{ "DEVPATH",    KEY_DEVPATH    },
	{ "KERNEL",     KEY_KERNEL     },
	{ "KERNELS",    KEY_KERNELS    },
	{ "NAME",       KEY_NAME       },
	{ "SUBSYSTEM",  KEY_SUBSYSTEM  },
	{ "SUBSYSTEMS", KEY_SUBSYSTEMS },
	{ "DRIVER",     KEY_DRIVER     },
	{ "DRIVERS",    KEY_DRIVERS    },
	{ "ATTR",       KEY_ATTR       },
	{ "ATTRS",      KEY_ATTRS      },
	{ "SYSCTL",     KEY_SYSCTL     },
	{ "ENV",        KEY_ENV        },
	{ "CONST",      KEY_CONST      },
	{ "TAG",        KEY_TAG        },
	{ "TAGS",       KEY_TAGS       },
	{ "TEST",       KEY_TEST       },
	{ "PROGRAM",    KEY_PROGRAM    },
	{ "RESULT",     KEY_RESULT     },
	{ "SYMLINK",    KEY_SYMLINK    },
	{ "OWNER",      KEY_OWNER      },
	{ "GROUP",      KEY_GROUP      },
	{ "MODE",       KEY_MODE       },
	{ "SECLABEL",   KEY_SECLABEL   },
	{ "RUN",        KEY_RUN        },
	{ "LABEL",      KEY_LABEL      },
	{ "GOTO",       KEY_GOTO       },
	{ "IMPORT",     KEY_IMPORT     },
	{ "OPTIONS",    KEY_OPTIONS    },
};

static rule_key_class_t lookup_key(const char *name)
{
	size_t i;

	for (i = 0; i < NELEMS(key_map); i++) {
		if (!strcmp(key_map[i].name, name))
			return key_map[i].cls;
	}
	return KEY_UNKNOWN;
}

/* ----- helpers ---------------------------------------------------------- */

static pat_type_t detect_pat_type(const char *val)
{
	if (strchr(val, '|'))
		return PAT_SPLIT;
	if (strpbrk(val, "*?["))
		return PAT_GLOB;
	return PAT_PLAIN;
}

static import_type_t parse_import_type(const char *attr)
{
	if (!attr || !*attr)                return IMPORT_PROGRAM;
	if (!strcmp(attr, "program"))       return IMPORT_PROGRAM;
	if (!strcmp(attr, "file"))          return IMPORT_FILE;
	if (!strcmp(attr, "db"))            return IMPORT_DB;
	if (!strcmp(attr, "builtin"))       return IMPORT_BUILTIN;
	if (!strcmp(attr, "parent"))        return IMPORT_PARENT;
	if (!strcmp(attr, "cmdline"))       return IMPORT_CMDLINE;
	return IMPORT_PROGRAM;
}

static run_type_t parse_run_type(const char *attr)
{
	if (!attr || !*attr)                return RUN_PROGRAM;
	if (!strcmp(attr, "program"))       return RUN_PROGRAM;
	if (!strcmp(attr, "builtin"))       return RUN_BUILTIN;
	return RUN_PROGRAM;
}

/* ----- tokenizer -------------------------------------------------------- */

static char *skip_space(char *p)
{
	while (*p == ' ' || *p == '\t')
		p++;
	return p;
}

/* Strip inline comment: first '#' not inside double quotes */
static void strip_comment(char *line)
{
	int in_quote = 0;
	char *p;

	for (p = line; *p; p++) {
		if (*p == '"')
			in_quote ^= 1;
		else if (*p == '#' && !in_quote) {
			*p = 0;
			break;
		}
	}
}

/*
 * Parse the key name (uppercase letters and '_') and optional {attr}
 * suffix.  Advances *pp past the parsed portion.
 */
static int parse_key_name(char **pp,
			   char *name, size_t namesz,
			   char *attr, size_t attrsz)
{
	char *p = *pp, *end;
	size_t n;

	end = p;
	while (*end && (isupper((unsigned char)*end) || *end == '_'))
		end++;

	n = (size_t)(end - p);
	if (!n || n >= namesz)
		return -1;

	memcpy(name, p, n);
	name[n] = 0;
	p = end;

	if (*p == '{') {
		p++;
		end = strchr(p, '}');
		if (!end)
			return -1;
		n = (size_t)(end - p);
		if (n >= attrsz)
			return -1;
		memcpy(attr, p, n);
		attr[n] = 0;
		p = end + 1;
	} else {
		attr[0] = 0;
	}

	*pp = p;
	return 0;
}

static rule_op_t parse_op(char **pp)
{
	char *p = *pp;
	rule_op_t op;

	if      (p[0] == '=' && p[1] == '=') { op = OP_MATCH_EQ;     *pp = p + 2; }
	else if (p[0] == '!' && p[1] == '=') { op = OP_MATCH_NE;     *pp = p + 2; }
	else if (p[0] == '+' && p[1] == '=') { op = OP_ASSIGN_ADD;   *pp = p + 2; }
	else if (p[0] == '-' && p[1] == '=') { op = OP_ASSIGN_DEL;   *pp = p + 2; }
	else if (p[0] == ':' && p[1] == '=') { op = OP_ASSIGN_FINAL; *pp = p + 2; }
	else if (p[0] == '=')                { op = OP_ASSIGN;        *pp = p + 1; }
	else                                  { op = OP_INVALID;                    }

	return op;
}

/* Parse a double-quoted value, advancing *pp past the closing '"'. */
static int parse_value(char **pp, char *val, size_t valsz)
{
	char *p = *pp, *end;
	size_t n;

	if (*p != '"')
		return -1;
	p++;

	end = strchr(p, '"');
	if (!end)
		return -1;

	n = (size_t)(end - p);
	if (n >= valsz)
		n = valsz - 1;

	memcpy(val, p, n);
	val[n] = 0;
	*pp = end + 1;
	return 0;
}

/* Free key resources within a rule without freeing the rule itself. */
static void rule_keys_free(struct rule *r)
{
	int j;

	for (j = 0; j < r->nkeys; j++) {
		free(r->keys[j].attr);
		free(r->keys[j].value);
		r->keys[j].attr  = NULL;
		r->keys[j].value = NULL;
	}
	r->nkeys = 0;
}

/*
 * Parse one logical rule line into r.
 * Returns 0 if at least one key was successfully parsed.
 */
static int parse_rule_line(struct rule *r, char *src)
{
	char buf[4096];
	char *p;
	size_t slen;

	slen = strlen(src);
	if (slen >= sizeof(buf))
		slen = sizeof(buf) - 1;
	memcpy(buf, src, slen);
	buf[slen] = 0;

	p = skip_space(buf);
	strip_comment(p);
	p = skip_space(p);

	if (!*p)
		return -1;

	while (*p) {
		char name[64], attr[256], val[1024];
		rule_key_class_t cls;
		rule_op_t op;
		struct rule_key *k;

		p = skip_space(p);
		if (!*p)
			break;

		if (parse_key_name(&p, name, sizeof(name), attr, sizeof(attr)) < 0) {
			logit(LOG_DEBUG, "rules:%s:%d: parse error near '%s'",
			      r->filename, r->lineno, p);
			return -1;
		}

		cls = lookup_key(name);
		if (cls == KEY_UNKNOWN) {
			logit(LOG_DEBUG, "rules:%s:%d: unknown key '%s'",
			      r->filename, r->lineno, name);
			return -1;
		}

		p = skip_space(p);
		op = parse_op(&p);
		if (op == OP_INVALID) {
			logit(LOG_DEBUG, "rules:%s:%d: bad operator after '%s'",
			      r->filename, r->lineno, name);
			return -1;
		}

		p = skip_space(p);
		if (parse_value(&p, val, sizeof(val)) < 0) {
			logit(LOG_DEBUG, "rules:%s:%d: missing value for '%s'",
			      r->filename, r->lineno, name);
			return -1;
		}

		if (r->nkeys >= RULE_KEY_MAX) {
			logit(LOG_WARNING, "rules:%s:%d: too many keys, truncating",
			      r->filename, r->lineno);
			break;
		}

		k = &r->keys[r->nkeys];
		k->cls   = cls;
		k->op    = op;
		k->attr  = attr[0] ? strdup(attr) : NULL;
		k->value = strdup(val);

		if (!k->value) {
			free(k->attr);
			k->attr = NULL;
			break;
		}

		k->pat_type    = (op == OP_MATCH_EQ || op == OP_MATCH_NE)
				 ? detect_pat_type(val) : PAT_PLAIN;
		k->import_type = (cls == KEY_IMPORT) ? parse_import_type(attr) : IMPORT_PROGRAM;
		k->run_type    = (cls == KEY_RUN)    ? parse_run_type(attr)    : RUN_PROGRAM;

		r->nkeys++;

		p = skip_space(p);
		if (*p == ',')
			p++;
	}

	return r->nkeys > 0 ? 0 : -1;
}

/* ----- file loading ----------------------------------------------------- */

static int rules_dirent_filter(const struct dirent *e)
{
	size_t l = strlen(e->d_name);
	return l > 6 && !strcmp(e->d_name + l - 6, ".rules");
}

int rules_load(struct rule_list *list, const char *path)
{
	char line[2048], cont[4096];
	int lineno = 0, nrules = 0;
	FILE *fp;

	fp = fopen(path, "r");
	if (!fp)
		return -1;

	cont[0] = 0;

	while (fgets(line, sizeof(line), fp)) {
		struct rule *r;
		size_t clen, l;
		char *p;

		lineno++;
		chomp(line);

		/* Accumulate continuation lines */
		l = strlen(line);
		if (l > 0 && line[l - 1] == '\\') {
			line[l - 1] = 0;
			clen = strlen(cont);
			snprintf(cont + clen, sizeof(cont) - clen, "%s", line);
			continue;
		}
		clen = strlen(cont);
		snprintf(cont + clen, sizeof(cont) - clen, "%s", line);

		/* Skip blank lines and full-line comments */
		p = cont;
		while (*p == ' ' || *p == '\t')
			p++;
		if (!*p || *p == '#') {
			cont[0] = 0;
			continue;
		}

		r = calloc(1, sizeof(*r));
		if (!r)
			break;

		r->filename = strdup(path);
		r->lineno   = lineno;

		if (r->filename && parse_rule_line(r, cont) == 0) {
			TAILQ_INSERT_TAIL(list, r, link);
			nrules++;
		} else {
			rule_keys_free(r);
			free(r->filename);
			free(r);
		}

		cont[0] = 0;
	}

	fclose(fp);
	return nrules;
}

int rules_load_all(struct rule_list *list, const char *extra_dir)
{
	static const char *std_dirs[] = {
		"/lib/udev/rules.d",
		"/run/udev/rules.d",
		"/etc/udev/rules.d",
		NULL
	};
	const char *dirs[8];
	int ndirs = 0, total = 0, d;

	for (d = 0; std_dirs[d]; d++)
		dirs[ndirs++] = std_dirs[d];

	if (extra_dir)
		dirs[ndirs++] = extra_dir;
	dirs[ndirs] = NULL;

	for (d = 0; d < ndirs; d++) {
		struct dirent **ents = NULL;
		char path[PATH_MAX];
		int n, i;

		n = scandir(dirs[d], &ents, rules_dirent_filter, alphasort);
		if (n < 0)
			continue;

		for (i = 0; i < n; i++) {
			int rc;

			snprintf(path, sizeof(path), "%s/%s", dirs[d], ents[i]->d_name);
			rc = rules_load(list, path);
			if (rc > 0) {
				logit(LOG_DEBUG, "rules: %d rules from %s", rc, path);
				total += rc;
			}
			free(ents[i]);
		}
		free(ents);
	}

	if (total)
		logit(LOG_NOTICE, "rules: %d rules loaded", total);

	return total;
}

void rules_free(struct rule_list *list)
{
	struct rule *r, *tmp;

	TAILQ_FOREACH_SAFE(r, list, link, tmp) {
		TAILQ_REMOVE(list, r, link);
		rule_keys_free(r);
		free(r->filename);
		free(r);
	}
}

/* ===== Phase 3: full matcher ============================================ */

/* ----- variable substitution ------------------------------------------- */

static void append_str(char *buf, size_t *pos, size_t bufsz, const char *s)
{
	size_t l;

	if (!s || !*s)
		return;
	l = strlen(s);
	if (*pos + l >= bufsz)
		l = bufsz - *pos - 1;
	if (l) {
		memcpy(buf + *pos, s, l);
		*pos += l;
		buf[*pos] = 0;
	}
}

/*
 * Expand udev-format substitution operators from src into buf.
 * Handles both the %X short form and the $name long form.
 */
static void subst_value(const char *src, char *buf, size_t bufsz,
			 const struct uevent *ev)
{
	const char *p = src;
	size_t pos = 0;

	buf[0] = 0;
	if (!src)
		return;

	while (*p && pos + 1 < bufsz) {
		char tmp[256];

		if (*p != '%' && *p != '$') {
			buf[pos++] = *p++;
			buf[pos] = 0;
			continue;
		}

		if (*p == '%') {
			char c = *++p;

			switch (c) {
			case '%':
				buf[pos++] = '%'; buf[pos] = 0; p++;
				break;
			case 'k':
				append_str(buf, &pos, bufsz, uevent_sysname(ev));
				p++;
				break;
			case 'p':
				append_str(buf, &pos, bufsz, ev->devpath);
				p++;
				break;
			case 'D': case 'N':
				append_str(buf, &pos, bufsz, ev->devname);
				p++;
				break;
			case 'M':
				snprintf(tmp, sizeof(tmp), "%d", ev->major);
				append_str(buf, &pos, bufsz, tmp);
				p++;
				break;
			case 'm':
				snprintf(tmp, sizeof(tmp), "%d", ev->minor);
				append_str(buf, &pos, bufsz, tmp);
				p++;
				break;
			case 'b':
				snprintf(tmp, sizeof(tmp), "%d:%d", ev->major, ev->minor);
				append_str(buf, &pos, bufsz, tmp);
				p++;
				break;
			case 'd':
				append_str(buf, &pos, bufsz, ev->driver);
				p++;
				break;
			case 'n': {
				/* trailing digit suffix of sysname */
				const char *sn = uevent_sysname(ev);
				if (sn) {
					const char *e = sn + strlen(sn);
					while (e > sn && isdigit((unsigned char)*(e - 1)))
						e--;
					append_str(buf, &pos, bufsz, e);
				}
				p++;
				break;
			}
			case 's':
				/* %s{attr} — sysfs attribute of current device */
				if (p[1] == '{') {
					const char *as = p + 2;
					const char *ae = strchr(as, '}');

					if (ae && ev->devpath) {
						char attr[256];
						size_t al = (size_t)(ae - as);

						if (al >= sizeof(attr))
							al = sizeof(attr) - 1;
						memcpy(attr, as, al);
						attr[al] = 0;
						if (!sysfs_read_attr(ev->devpath, attr,
								     tmp, sizeof(tmp)))
							append_str(buf, &pos, bufsz, tmp);
						p = ae + 1;
					} else {
						buf[pos++] = '%'; buf[pos] = 0;
					}
				} else {
					buf[pos++] = '%'; buf[pos] = 0;
				}
				break;
			case 'c':
				/* %c or %c{n} — PROGRAM result or nth space-separated field */
				if (ev->result) {
					if (p[1] == '{') {
						const char *ns = p + 2;
						const char *ne = strchr(ns, '}');

						if (ne) {
							int field = atoi(ns);
							const char *rp = ev->result;
							int f = 0;

							while (*rp && f < field) {
								while (*rp && *rp != ' ')
									rp++;
								while (*rp == ' ')
									rp++;
								f++;
							}
							const char *re = rp;
							while (*re && *re != ' ')
								re++;
							size_t fl = (size_t)(re - rp);
							if (fl >= sizeof(tmp))
								fl = sizeof(tmp) - 1;
							memcpy(tmp, rp, fl);
							tmp[fl] = 0;
							append_str(buf, &pos, bufsz, tmp);
							p = ne + 1;
						} else {
							append_str(buf, &pos, bufsz, ev->result);
							p++;
						}
					} else {
						append_str(buf, &pos, bufsz, ev->result);
						p++;
					}
				} else {
					p++;
				}
				break;
			default:
				/* unknown specifier — pass '%' through, re-parse next char */
				buf[pos++] = '%'; buf[pos] = 0;
				break;
			}

		} else { /* '$' */
			const char *kw = ++p;

			if (*kw == '$') {
				buf[pos++] = '$'; buf[pos] = 0;
				p++;
			} else if (!strncmp(kw, "attr{", 5)) {
				int off = 5;
				const char *as = kw + off;
				const char *ae = strchr(as, '}');

				if (ae && ev->devpath) {
					char attr[256];
					size_t al = (size_t)(ae - as);

					if (al >= sizeof(attr))
						al = sizeof(attr) - 1;
					memcpy(attr, as, al);
					attr[al] = 0;
					if (!sysfs_read_attr(ev->devpath, attr, tmp, sizeof(tmp)))
						append_str(buf, &pos, bufsz, tmp);
					p = ae + 1;
				} else {
					buf[pos++] = '$'; buf[pos] = 0;
				}
			} else if (!strncmp(kw, "env{", 4)) {
				const char *ks = kw + 4;
				const char *ke = strchr(ks, '}');

				if (ke) {
					char key[256];
					size_t kl = (size_t)(ke - ks);

					if (kl >= sizeof(key))
						kl = sizeof(key) - 1;
					memcpy(key, ks, kl);
					key[kl] = 0;
					append_str(buf, &pos, bufsz, uevent_getenv(ev, key));
					p = ke + 1;
				} else {
					buf[pos++] = '$'; buf[pos] = 0;
				}
			} else {
				/* Named scalar variables */
				static const struct {
					const char *name;
					size_t      len;
				} named[] = {
					{ "kernel",  6 }, { "name",    4 },
					{ "devpath", 7 }, { "driver",  6 },
					{ "result",  6 }, { "root",    4 },
					{ "sys",     3 }, { "major",   5 },
					{ "minor",   5 },
				};
				size_t i;
				int handled = 0;

				for (i = 0; i < NELEMS(named); i++) {
					if (strncmp(kw, named[i].name, named[i].len))
						continue;
					switch (i) {
					case 0:
						append_str(buf, &pos, bufsz, uevent_sysname(ev));
						break;
					case 1:
						append_str(buf, &pos, bufsz, ev->devname);
						break;
					case 2:
						append_str(buf, &pos, bufsz, ev->devpath);
						break;
					case 3:
						append_str(buf, &pos, bufsz, ev->driver);
						break;
					case 4:
						append_str(buf, &pos, bufsz, ev->result);
						break;
					case 5:
						append_str(buf, &pos, bufsz, "/dev");
						break;
					case 6:
						append_str(buf, &pos, bufsz, "/sys");
						break;
					case 7:
						snprintf(tmp, sizeof(tmp), "%d", ev->major);
						append_str(buf, &pos, bufsz, tmp);
						break;
					case 8:
						snprintf(tmp, sizeof(tmp), "%d", ev->minor);
						append_str(buf, &pos, bufsz, tmp);
						break;
					}
					p = kw + named[i].len;
					handled = 1;
					break;
				}
				if (!handled) {
					buf[pos++] = '$'; buf[pos] = 0;
					/* don't advance p — let next iter handle kw[0] */
				}
			}
		}
	}
}

/* ----- pattern matching ------------------------------------------------- */

/*
 * Match subject against a single pattern (no pipe splitting).
 * Always uses fnmatch so that plain strings and globs work uniformly.
 */
static int pattern_match_one(const char *pat, const char *subject)
{
	return fnmatch(pat, subject, 0) == 0;
}

static int pattern_match(const char *pat, const char *subject, pat_type_t type)
{
	if (type == PAT_PLAIN)
		return !strcmp(pat, subject);

	if (type == PAT_SPLIT) {
		char copy[1024];
		char *p, *tok;

		snprintf(copy, sizeof(copy), "%s", pat);
		p = copy;
		while ((tok = strsep(&p, "|")) != NULL) {
			if (pattern_match_one(tok, subject))
				return 1;
		}
		return 0;
	}

	/* PAT_GLOB */
	return pattern_match_one(pat, subject);
}

/* ----- program execution ------------------------------------------------ */

/* Fork and exec cmd via /bin/sh, capture stdout into result. */
static int run_program(const char *cmd, char *result, size_t rlen)
{
	int pipefd[2];
	pid_t pid;
	int rc = -1;

	if (!cmd || !*cmd)
		return -1;

	if (pipe(pipefd) < 0)
		return -1;

	pid = fork();
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return -1;
	}

	if (pid == 0) {
		close(pipefd[0]);
		dup2(pipefd[1], STDOUT_FILENO);
		close(pipefd[1]);
		execl("/bin/sh", "sh", "-c", cmd, NULL);
		_exit(127);
	}

	close(pipefd[1]);

	{
		ssize_t n = read(pipefd[0], result, rlen - 1);
		if (n < 0)
			n = 0;
		result[n] = 0;
		chomp(result);
	}
	close(pipefd[0]);

	{
		int status;

		if (waitpid(pid, &status, 0) > 0)
			rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
	}

	return rc;
}

/* ----- parent-chain matching -------------------------------------------- */

struct parent_ctx {
	const struct rule_key *k;
	const struct uevent   *ev;
	int                    found;
};

static int parent_cb(const char *syspath, void *data)
{
	struct parent_ctx *ctx = data;
	const struct rule_key *k = ctx->k;
	char buf[256];
	const char *subject = NULL;

	switch (k->cls) {
	case KEY_KERNELS: {
		const char *p = strrchr(syspath, '/');
		subject = p ? p + 1 : syspath;
		break;
	}
	case KEY_SUBSYSTEMS:
		if (sysfs_read_subsystem(syspath, buf, sizeof(buf)) < 0)
			return 1;
		subject = buf;
		break;
	case KEY_DRIVERS:
		if (sysfs_read_driver(syspath, buf, sizeof(buf)) < 0)
			return 1;
		subject = buf;
		break;
	case KEY_ATTRS: {
		/* Read sysfs attribute directly from this level of the tree */
		char path[PATH_MAX];
		FILE *fp;

		snprintf(path, sizeof(path), "%s/%s", syspath, k->attr ?: "");
		fp = fopen(path, "r");
		if (!fp)
			return 1;
		if (!fgets(buf, sizeof(buf), fp)) {
			fclose(fp);
			return 1;
		}
		fclose(fp);
		chomp(buf);
		subject = buf;
		break;
	}
	default:
		return 1;
	}

	if (!subject)
		return 1;

	if (pattern_match(k->value, subject, k->pat_type)) {
		ctx->found = 1;
		return 0;	/* stop walking */
	}
	return 1;		/* keep walking */
}

static int match_parent_chain(const struct rule_key *k, const struct uevent *ev)
{
	struct parent_ctx ctx = { k, ev, 0 };
	int matched;

	if (!ev->devpath)
		return (k->op == OP_MATCH_NE);

	sysfs_parent_walk(ev->devpath, parent_cb, &ctx);

	matched = ctx.found;
	return (k->op == OP_MATCH_EQ) ? matched : !matched;
}

/* ----- per-key dispatch ------------------------------------------------- */

/*
 * Read one line from path into buf (for SYSCTL matching).
 */
static int read_oneline(const char *path, char *buf, size_t len)
{
	FILE *fp = fopen(path, "r");

	if (!fp)
		return -1;
	if (!fgets(buf, len, fp)) {
		fclose(fp);
		return -1;
	}
	fclose(fp);
	chomp(buf);
	return 0;
}

/*
 * Test one key against the event.
 * Returns 1 if the key condition is satisfied, 0 if not.
 */
static int match_key(const struct rule *r, const struct rule_key *k,
		     struct uevent *ev)
{
	char subj_buf[1024] = "";
	const char *subject = NULL;
	int matched;

	/* Parent-chain keys have their own walk logic */
	switch (k->cls) {
	case KEY_KERNELS:
	case KEY_SUBSYSTEMS:
	case KEY_DRIVERS:
	case KEY_ATTRS:
	case KEY_TAGS:
		return match_parent_chain(k, ev);
	default:
		break;
	}

	/* PROGRAM= and TEST= have dedicated logic */
	if (k->cls == KEY_PROGRAM) {
		char cmd[PATH_MAX], out[1024];
		int rc;

		subst_value(k->value, cmd, sizeof(cmd), ev);
		rc = run_program(cmd, out, sizeof(out));
		free(ev->result);
		ev->result = strdup(out);
		matched = (rc == 0);
		return (k->op == OP_MATCH_EQ) ? matched : !matched;
	}

	if (k->cls == KEY_TEST) {
		char path[PATH_MAX];
		struct stat st;

		subst_value(k->value, path, sizeof(path), ev);
		if (stat(path, &st) < 0) {
			matched = 0;
		} else if (k->attr && k->attr[0]) {
			mode_t req = (mode_t)strtoul(k->attr, NULL, 8);
			matched = ((st.st_mode & req) == req);
		} else {
			matched = 1;
		}
		return (k->op == OP_MATCH_EQ) ? matched : !matched;
	}

	/* All other match keys: compute subject string, then pattern match */
	switch (k->cls) {
	case KEY_ACTION:
		subject = uevent_action_str(ev->action);
		break;
	case KEY_DEVPATH:
		subject = ev->devpath;
		break;
	case KEY_KERNEL:
		subject = uevent_sysname(ev);
		break;
	case KEY_NAME:
		subject = ev->devname;
		break;
	case KEY_SUBSYSTEM:
		subject = ev->subsystem;
		break;
	case KEY_DRIVER:
		subject = ev->driver;
		break;
	case KEY_ATTR:
		if (!k->attr || !ev->devpath)
			return (k->op == OP_MATCH_NE);
		if (sysfs_read_attr(ev->devpath, k->attr, subj_buf, sizeof(subj_buf)) < 0)
			return (k->op == OP_MATCH_NE);
		subject = subj_buf;
		break;
	case KEY_SYSCTL: {
		char path[PATH_MAX];
		char *dp;

		if (!k->attr)
			return (k->op == OP_MATCH_NE);
		snprintf(path, sizeof(path), "/proc/sys/%s", k->attr);
		for (dp = path + 10; *dp; dp++)
			if (*dp == '.')
				*dp = '/';
		if (read_oneline(path, subj_buf, sizeof(subj_buf)) < 0)
			return (k->op == OP_MATCH_NE);
		subject = subj_buf;
		break;
	}
	case KEY_ENV:
		if (!k->attr)
			return (k->op == OP_MATCH_NE);
		subject = uevent_getenv(ev, k->attr);
		break;
	case KEY_CONST: {
		if (!k->attr) {
			subject = "";
		} else if (!strcmp(k->attr, "arch")) {
			struct utsname uts;
			if (uname(&uts) == 0)
				snprintf(subj_buf, sizeof(subj_buf), "%s", uts.machine);
			subject = subj_buf;
		} else if (!strcmp(k->attr, "virt")) {
			subject = (fexist("/.dockerenv") ||
				   fexist("/run/.containerenv")) ? "container" : "";
		} else {
			subject = "";
		}
		break;
	}
	case KEY_TAG: {
		int i;
		matched = 0;
		for (i = 0; i < ev->ntags; i++) {
			if (pattern_match(k->value, ev->tags[i], k->pat_type)) {
				matched = 1;
				break;
			}
		}
		return (k->op == OP_MATCH_EQ) ? matched : !matched;
	}
	case KEY_RESULT:
		subject = ev->result;
		break;
	default:
		/* Assignment-only key encountered in match position: skip */
		logit(LOG_DEBUG, "rules:%s:%d: skipping non-match key %d in match phase",
		      r->filename, r->lineno, k->cls);
		return 1;
	}

	if (!subject)
		return (k->op == OP_MATCH_NE);

	matched = pattern_match(k->value, subject, k->pat_type);
	return (k->op == OP_MATCH_EQ) ? matched : !matched;
}

/* ----- rule-level AND logic --------------------------------------------- */

/*
 * Returns 1 if all match-op keys in the rule are satisfied.
 */
static int rule_matches(const struct rule *r, struct uevent *ev)
{
	int i;

	for (i = 0; i < r->nkeys; i++) {
		const struct rule_key *k = &r->keys[i];

		/* Skip assignment-only operators */
		if (k->op != OP_MATCH_EQ && k->op != OP_MATCH_NE)
			continue;

		if (!match_key(r, k, ev))
			return 0;
	}
	return 1;
}

/* ===== Phase 4: executor ================================================ */

/* ----- UID/GID resolution ----------------------------------------------- */

static uid_t resolve_uid(const char *s)
{
	if (!s || !*s)
		return 0;
	if (*s >= '0' && *s <= '9')
		return (uid_t)atoi(s);
	{
		struct passwd *pw = getpwnam(s);
		return pw ? pw->pw_uid : 0;
	}
}

static gid_t resolve_gid(const char *s)
{
	if (!s || !*s)
		return 0;
	if (*s >= '0' && *s <= '9')
		return (gid_t)atoi(s);
	{
		struct group *gr = getgrnam(s);
		return gr ? gr->gr_gid : 0;
	}
}

/* ----- IMPORT helpers --------------------------------------------------- */

/*
 * Fork, exec cmd, parse stdout as KEY=VALUE (or KEY="VALUE") pairs
 * and import them into ev's env store.
 */
/*
 * Helper-first, builtin-fallback for IMPORT{program}= / RUN+="...".
 *
 * Stock udev rules invoke /lib/udev/<helper> (path_id, usb_id, blkid, ...)
 * via IMPORT{program}=.  keventd ships compatible builtins for many of
 * those.  If the helper is absent on this system, fall back to the
 * matching builtin so the rule still works.  If the helper exists, run
 * it as-is -- this lets users override our builtins by dropping a
 * custom helper into /lib/udev/.
 *
 * Returns 1 if the builtin handled the command, 0 if the caller should
 * proceed with the normal fork+exec path.
 */
static int try_builtin_fallback(const char *cmd, struct uevent *ev)
{
	char first[PATH_MAX], rebuilt[PATH_MAX];
	const char *space, *base;
	size_t len;

	space = strchr(cmd, ' ');
	len = space ? (size_t)(space - cmd) : strlen(cmd);
	if (len == 0 || len >= sizeof(first))
		return 0;
	memcpy(first, cmd, len);
	first[len] = '\0';

	/* Helper exists -- let caller fork+exec it (allows user override). */
	if (access(first, X_OK) == 0)
		return 0;

	base = strrchr(first, '/');
	base = base ? base + 1 : first;

	if (!builtin_has(base))
		return 0;

	if (space)
		snprintf(rebuilt, sizeof(rebuilt), "%s%s", base, space);
	else
		snprintf(rebuilt, sizeof(rebuilt), "%s", base);

	logit(LOG_DEBUG, "rules: %s not found, falling back to builtin %s", first, base);
	builtin_run(ev, rebuilt);
	return 1;
}

static void import_from_program(const char *cmd, struct uevent *ev)
{
	struct sigaction sa_dfl, sa_old;
	int pipefd[2];
	pid_t pid;
	FILE *fp;
	char line[512];

	if (!cmd || !*cmd)
		return;
	if (try_builtin_fallback(cmd, ev))
		return;
	if (pipe(pipefd) < 0)
		return;

	sigemptyset(&sa_dfl.sa_mask);
	sa_dfl.sa_flags   = 0;
	sa_dfl.sa_handler = SIG_DFL;
	sigaction(SIGCHLD, &sa_dfl, &sa_old);

	pid = fork();
	if (pid < 0) {
		sigaction(SIGCHLD, &sa_old, NULL);
		close(pipefd[0]);
		close(pipefd[1]);
		return;
	}

	if (pid == 0) {
		close(pipefd[0]);
		dup2(pipefd[1], STDOUT_FILENO);
		close(pipefd[1]);
		execl("/bin/sh", "sh", "-c", cmd, NULL);
		_exit(127);
	}

	close(pipefd[1]);
	fp = fdopen(pipefd[0], "r");
	if (fp) {
		while (fgets(line, sizeof(line), fp)) {
			char *eq, *val;

			chomp(line);
			if (!*line)
				continue;
			eq = strchr(line, '=');
			if (!eq)
				continue;
			*eq++ = 0;
			val = eq;
			/* Strip surrounding quotes from value */
			if (*val == '"') {
				val++;
				char *end = strrchr(val, '"');
				if (end)
					*end = 0;
			}
			uevent_setenv(ev, line, val);
		}
		fclose(fp);
	} else {
		close(pipefd[0]);
	}

	{
		int status;
		waitpid(pid, &status, 0);
	}
	sigaction(SIGCHLD, &sa_old, NULL);
}

/*
 * Read KEY=VALUE (or KEY="VALUE") pairs from a file into ev's env store.
 */
static void import_from_file(const char *path, struct uevent *ev)
{
	FILE *fp;
	char line[512];

	fp = fopen(path, "r");
	if (!fp)
		return;

	while (fgets(line, sizeof(line), fp)) {
		char *eq, *val;

		chomp(line);
		if (!*line || *line == '#')
			continue;
		eq = strchr(line, '=');
		if (!eq)
			continue;
		*eq++ = 0;
		val = eq;
		if (*val == '"') {
			val++;
			char *end = strrchr(val, '"');
			if (end)
				*end = 0;
		}
		uevent_setenv(ev, line, val);
	}

	fclose(fp);
}

/*
 * Import a matching key (or key=value) from /proc/cmdline.
 * The pattern in val is matched against each key on the cmdline.
 */
static void import_from_cmdline(const char *key_pattern, struct uevent *ev)
{
	FILE *fp;
	char line[2048];
	char *p, *tok;

	fp = fopen("/proc/cmdline", "r");
	if (!fp)
		return;

	if (!fgets(line, sizeof(line), fp)) {
		fclose(fp);
		return;
	}
	fclose(fp);

	p = line;
	while ((tok = strsep(&p, " \t\n")) != NULL) {
		char *eq = strchr(tok, '=');

		if (eq) {
			*eq++ = 0;
			if (fnmatch(key_pattern, tok, 0) == 0)
				uevent_setenv(ev, tok, eq);
		} else if (*tok && fnmatch(key_pattern, tok, 0) == 0) {
			uevent_setenv(ev, tok, "1");
		}
	}
}

static void exec_import(const struct rule_key *k, struct uevent *ev,
			const char *val)
{
	switch (k->import_type) {
	case IMPORT_PROGRAM:
		import_from_program(val, ev);
		break;
	case IMPORT_FILE:
		import_from_file(val, ev);
		break;
	case IMPORT_DB:
		udevdb_read(ev);
		break;
	case IMPORT_PARENT:
		udevdb_read_parent(ev);
		break;
	case IMPORT_CMDLINE:
		import_from_cmdline(val, ev);
		break;
	case IMPORT_BUILTIN:
		builtin_run(ev, val);
		break;
	}
}

/* ----- assignment executor ---------------------------------------------- */

static void exec_rule(const struct rule *r, struct uevent *ev)
{
	int i;

	for (i = 0; i < r->nkeys; i++) {
		const struct rule_key *k = &r->keys[i];
		char val[PATH_MAX];

		/* Skip match-only operators */
		if (k->op == OP_MATCH_EQ || k->op == OP_MATCH_NE)
			continue;

		subst_value(k->value, val, sizeof(val), ev);

		switch (k->cls) {
		case KEY_MODE:
			if (!ev->applied.final_mode) {
				ev->applied.mode     = (mode_t)strtoul(val, NULL, 8);
				ev->applied.has_mode = 1;
				if (k->op == OP_ASSIGN_FINAL)
					ev->applied.final_mode = 1;
			}
			break;

		case KEY_OWNER:
			if (!ev->applied.final_owner) {
				ev->applied.uid       = resolve_uid(val);
				ev->applied.has_owner = 1;
				if (k->op == OP_ASSIGN_FINAL)
					ev->applied.final_owner = 1;
			}
			break;

		case KEY_GROUP:
			if (!ev->applied.final_group) {
				ev->applied.gid       = resolve_gid(val);
				ev->applied.has_group = 1;
				if (k->op == OP_ASSIGN_FINAL)
					ev->applied.final_group = 1;
			}
			break;

		case KEY_NAME:
			if (k->op == OP_ASSIGN || k->op == OP_ASSIGN_FINAL) {
				free(ev->applied.name);
				ev->applied.name = strdup(val);
			}
			break;

		case KEY_SYMLINK:
			if (k->op == OP_ASSIGN) {
				/* Clear existing, set single entry */
				int j;
				for (j = 0; j < ev->applied.nsymlinks; j++) {
					free(ev->applied.symlinks[j]);
					ev->applied.symlinks[j] = NULL;
				}
				ev->applied.nsymlinks = 0;
				/* Fall through to add */
			}
			if (k->op == OP_ASSIGN || k->op == OP_ASSIGN_ADD) {
				/* Value may be space-separated list */
				char copy[PATH_MAX], *p, *tok;
				snprintf(copy, sizeof(copy), "%s", val);
				p = copy;
				while ((tok = strsep(&p, " ")) != NULL) {
					if (!*tok)
						continue;
					if (ev->applied.nsymlinks >= RULE_SYMLINK_MAX)
						break;
					ev->applied.symlinks[ev->applied.nsymlinks] = strdup(tok);
					if (ev->applied.symlinks[ev->applied.nsymlinks])
						ev->applied.nsymlinks++;
				}
			}
			break;

		case KEY_ENV:
			if (!k->attr)
				break;
			if (k->op == OP_ASSIGN || k->op == OP_ASSIGN_FINAL) {
				uevent_setenv(ev, k->attr, val);
			} else if (k->op == OP_ASSIGN_ADD) {
				const char *cur = uevent_getenv(ev, k->attr);
				if (cur && *cur) {
					char combined[1024];
					snprintf(combined, sizeof(combined), "%s%s", cur, val);
					uevent_setenv(ev, k->attr, combined);
				} else {
					uevent_setenv(ev, k->attr, val);
				}
			} else if (k->op == OP_ASSIGN_DEL) {
				uevent_setenv(ev, k->attr, "");
			}
			break;

		case KEY_TAG:
			if (k->op == OP_ASSIGN_ADD &&
			    ev->ntags < UEVENT_TAG_MAX) {
				ev->tags[ev->ntags] = strdup(val);
				if (ev->tags[ev->ntags])
					ev->ntags++;
			} else if (k->op == OP_ASSIGN_DEL) {
				int j;
				for (j = 0; j < ev->ntags; j++) {
					if (!strcmp(ev->tags[j], val)) {
						free(ev->tags[j]);
						ev->tags[j] = ev->tags[--ev->ntags];
						ev->tags[ev->ntags] = NULL;
						break;
					}
				}
			}
			break;

		case KEY_RUN:
			if ((k->op == OP_ASSIGN_ADD || k->op == OP_ASSIGN) &&
			    ev->applied.nruncmds < RULE_RUN_MAX) {
				/* Store raw value; substitution happens at execution time */
				ev->applied.run_cmds[ev->applied.nruncmds] = strdup(k->value);
				if (ev->applied.run_cmds[ev->applied.nruncmds]) {
					ev->applied.run_types[ev->applied.nruncmds] = k->run_type;
					ev->applied.nruncmds++;
				}
			}
			break;

		case KEY_IMPORT:
			exec_import(k, ev, val);
			break;

		case KEY_ATTR:
			/* ATTR{file}= writes value to sysfs attribute */
			if (k->attr && ev->devpath) {
				char path[PATH_MAX];
				FILE *fp;

				snprintf(path, sizeof(path), "/sys%s/%s",
					 ev->devpath, k->attr);
				fp = fopen(path, "w");
				if (fp) {
					fputs(val, fp);
					fclose(fp);
				}
			}
			break;

		case KEY_SYSCTL:
			/* SYSCTL{param}= writes value to /proc/sys/ */
			if (k->attr) {
				char path[PATH_MAX];
				char *dp;
				FILE *fp;

				snprintf(path, sizeof(path), "/proc/sys/%s", k->attr);
				for (dp = path + 10; *dp; dp++)
					if (*dp == '.')
						*dp = '/';
				fp = fopen(path, "w");
				if (fp) {
					fputs(val, fp);
					fclose(fp);
				}
			}
			break;

		case KEY_SECLABEL:
			logit(LOG_DEBUG, "rules: %s:%d: SECLABEL not supported",
			      r->filename, r->lineno);
			break;

		case KEY_OPTIONS:
			logit(LOG_DEBUG, "rules: %s:%d: OPTIONS not supported: %s",
			      r->filename, r->lineno, k->value ?: "");
			break;

		case KEY_LABEL:
		case KEY_GOTO:
			/* Handled at loop level in rules_apply() */
			break;

		default:
			break;
		}
	}
}

/* ----- post-event RUN executor ------------------------------------------ */

void rules_run_cmds(struct uevent *ev)
{
	int i;

	for (i = 0; i < ev->applied.nruncmds; i++) {
		char cmd[PATH_MAX];

		if (!ev->applied.run_cmds[i])
			continue;

		subst_value(ev->applied.run_cmds[i], cmd, sizeof(cmd), ev);
		logit(LOG_DEBUG, "rules: RUN %s", cmd);

		if (ev->applied.run_types[i] == RUN_BUILTIN) {
			builtin_run(ev, cmd);
		} else if (!try_builtin_fallback(cmd, ev)) {
			pid_t pid = fork();

			if (pid == 0) {
				execl("/bin/sh", "sh", "-c", cmd, NULL);
				_exit(127);
			}
			/* Parent: SIGCHLD=SIG_IGN in keventd auto-reaps the child */
		}
	}
}

/* ----- main applier ----------------------------------------------------- */

int rules_apply(struct rule_list *list, struct uevent *ev)
{
	const char *goto_label = NULL;
	struct rule *r;
	int i;

	TAILQ_FOREACH(r, list, link) {
		/* GOTO: skip rules until matching LABEL= is found */
		if (goto_label) {
			const char *lbl = NULL;

			for (i = 0; i < r->nkeys; i++) {
				if (r->keys[i].cls == KEY_LABEL &&
				    r->keys[i].op == OP_ASSIGN)
					lbl = r->keys[i].value;
			}
			if (!lbl || strcmp(lbl, goto_label))
				continue;
			goto_label = NULL;
		}

		if (!rule_matches(r, ev))
			continue;

		logit(LOG_DEBUG, "rules: %s:%d matched %s@%s",
		      r->filename, r->lineno,
		      uevent_action_str(ev->action), ev->devpath ?: "");

		exec_rule(r, ev);

		/* GOTO takes effect after this rule's assignments are applied */
		goto_label = NULL;
		for (i = 0; i < r->nkeys; i++) {
			if (r->keys[i].cls == KEY_GOTO &&
			    r->keys[i].op == OP_ASSIGN) {
				goto_label = r->keys[i].value;
				break;
			}
		}
	}

	return 0;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
