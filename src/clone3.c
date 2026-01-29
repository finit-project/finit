/* Portable clone3() wrapper with fallback to fork()
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

#include "config.h"

#include <errno.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "clone3.h"
#include "finit.h"
#include "log.h"

/* clone3() was added in Linux 5.3, syscall number 435 on all archs */
#ifndef __NR_clone3
#define __NR_clone3 435
#endif

/* Clone3 flags from linux/sched.h */
#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP 0x200000000ULL
#endif

/* Linux kernel struct clone_args for clone3() syscall */
struct clone3_args {
	uint64_t flags;            /* Flags bit mask */
	uint64_t pidfd;            /* File descriptor for PID */
	uint64_t child_tid;        /* Child TID */
	uint64_t parent_tid;       /* Parent TID */
	uint64_t exit_signal;      /* Signal to deliver on exit */
	uint64_t stack;            /* Stack address */
	uint64_t stack_size;       /* Stack size */
	uint64_t tls;              /* TLS descriptor */
	uint64_t set_tid;          /* Set PID */
	uint64_t set_tid_size;     /* Number of set_tid entries */
	uint64_t cgroup;           /* Cgroup file descriptor */
} __attribute__((aligned(8)));

static int use_clone3 = 1;

int has_clone3(void)
{
	return use_clone3 == 1;
}

pid_t call_clone3(uint64_t flags,  int cgroup_fd)
{
	struct clone3_args cl = {
		.flags = flags,
		.exit_signal = SIGCHLD,
	};
	pid_t pid;

	if (!use_clone3)
		goto fallback;

	if (cgroup_fd >= 0) {
		cl.flags |= CLONE_INTO_CGROUP;
		cl.cgroup = cgroup_fd;
	}

	pid = syscall(__NR_clone3, &cl, sizeof(cl));
	if (pid != -1)
		return pid;

	logit(LOG_WARNING, "clone3() failed, falling back to fork(): %s", strerror(errno));
	use_clone3 = 0;
fallback:
	return fork();
}
