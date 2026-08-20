/* Finit PAM session support
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

#ifndef FINIT_PAM_H_
#define FINIT_PAM_H_

#include <string.h>		/* strchr(), strlen(), strstr() */
#include <sys/types.h>

#include "svc.h"

/*
 * A pam value names a file in /etc/pam.d, it is not a path, and conf.c
 * stores an over-long value truncated, so a value filling the buffer
 * must not be passed on as some other, shorter name that happens to
 * exist.  Both users share this one definition: service_start(), which
 * refuses the service outright, log line and a visible state, and
 * pamsess_open(), which every fork funnels through, including the pre:,
 * post:, ready:, cleanup:, stop and reload scripts that run before
 * service_start() ever does.
 *
 * Returns why the value cannot be used, or NULL when it can.
 */
static inline const char *pam_invalid(const char *pam)
{
	if (!pam[0])
		return NULL;

	if (strlen(pam) >= MAX_ARG_LEN - 1)
		return "is too long";

	if (strchr(pam, '/') || strstr(pam, ".."))
		return "names a file in /etc/pam.d, not a path";

	return NULL;
}

int pamsess_open(svc_t *svc, uid_t uid, gid_t gid, char ***envp);

#endif /* FINIT_PAM_H_ */
