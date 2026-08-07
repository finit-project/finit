/* libink — optional debug tracing, routed to whoever embeds us.
 *
 * libink has no logger of its own by design: it must not depend on the
 * host's logging, and PID 1 already has one.  The embedder installs a
 * callback and gets a line per connection, call, and authorization
 * decision.  Formatting happens before the callback, so an embedder
 * that wants tracing off should uninstall rather than filter.
 *
 * Copyright (c) 2026  Joachim Wiberg <troglobit@gmail.com>
 * SPDX-License-Identifier: MIT
 */

#include <stdarg.h>
#include <stdio.h>

#include "internal.h"

static link_log_cb_t  logger;
static void          *logger_userdata;

void link_set_logger(link_log_cb_t cb, void *userdata)
{
	logger          = cb;
	logger_userdata = userdata;
}

void __log(const char *func, const char *fmt, ...)
{
	char    msg[256];
	va_list ap;

	if (!logger)
		return;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	logger(logger_userdata, func, msg);
}
