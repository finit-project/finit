/* Misc. utility functions and C-library extensions for finit and its plugins
 *
 * Copyright (c) 2008-2010  Claudio Matsuoka <cmatsuoka@gmail.com>
 * Copyright (c) 2008-2025  Joachim Wiberg <troglobit@gmail.com>
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

#ifndef FINIT_HELPERS_H_
#define FINIT_HELPERS_H_

#include <ctype.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ttydefaults.h>	/* Not included by default in musl libc */
#include <termios.h>
#ifdef _LIBITE_LITE
# include <libite/lite.h>
#else
# include <lite/lite.h>
#endif

#define PROGRESS_DEFAULT PROGRESS_MODERN

typedef enum {
	PROGRESS_SILENT,
	PROGRESS_CLASSIC,
	PROGRESS_MODERN,
} pstyle_t;

char   *console         (void);
void    console_init    (void);
ssize_t cprintf         (const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));

void    tabstospaces    (char *line);
char   *strip_line      (char *line);

void    enable_progress (int onoff);
void    show_progress   (pstyle_t style);

char   *release_heading (void);

speed_t stty_parse_speed(char *baud);
void    stty            (int fd, speed_t speed);

void    print_banner    (const char *heading);
void    printv          (const char *fmt, va_list ap);
void    print           (int action, const char *fmt, ...) __attribute__ ((format (printf, 2, 3)));
void    print_desc      (char *action, char *desc);
int     print_result    (int fail);
void    print_exit      (void);

void    set_hostname    (char **hostname);
void    networking      (int updown);
int     in_container    (void);
void    setprocnm       (const char *name);

int     complete        (char *cmd, int pid);
int     run             (char *cmd, char *log);
int     run_interactive (char *cmd, char *fmt, ...) __attribute__ ((format (printf, 2, 3)));
int     exec_runtask    (char *cmd, char *args[]);
pid_t   run_getty       (char *tty, char *cmd, char *args[], int noclear, int nowait, struct rlimit rlimit[]);
pid_t   run_sh          (char *tty, int noclear, int nowait, struct rlimit rlimit[]);
pid_t   run_bg          (char *cmd, char *args[]);
int     run_parts       (char *dir, char *cmd, const char *env[], int progress, int sysv);


static inline int checkenv(const char *env)
{
	const char *val = getenv(env);

	if (!val || !val[0])
		return 0;

	return 1;
}

static inline int dprint(int fd, const char *s, size_t len)
{
	size_t loop = 3;
	int rc = -1;

	if (!len)
		len = strlen(s);

	while (loop--) {
		rc = write(fd, s, len);
		if (rc == -1 && errno == EINTR)
			continue;
		break;
	}

	return rc;
}

static inline char *fgetval(const char *line, const char *key, char *sep)
{
	char *ptr, *str, *copy;
	size_t len;

	str = copy = strdup(line);
	if (!copy)
		return NULL;

	ptr = strsep(&str, sep);
	if (!str || strcmp(ptr, key)) {
		free(copy);
		return NULL;
	}

	/* strip optional separators, e.g., 'foo = bar' => 'bar' */
	ptr = str + strspn(str, sep);

	if (*ptr == '"' || *ptr == '\'') {
		char *end = &ptr[strlen(ptr) - 1];
		char q = *ptr;

		while (end > ptr && isspace(*end))
			*end-- = 0;

		if (*end == q) {
			*end = 0;
			ptr++;
		}
	}

	len = strlen(ptr) + 1;
	memmove(copy, ptr, len);

	return realloc(copy, len);
}

#endif /* FINIT_HELPERS_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
