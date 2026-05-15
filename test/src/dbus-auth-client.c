/* Minimal D-Bus client used by the libink smoke tests.
 *
 * Modes:
 *   dbus-auth-client auth   <sock> <uid>
 *       Send the SASL handshake claiming <uid>; print server reply line.
 *       Exit 0 if reply begins "OK ", 1 if "REJECTED ", 2 otherwise.
 *       (Manual SASL: this mode exists *to* test AUTH itself.)
 *
 *   dbus-auth-client hello  <sock>
 *       Call org.freedesktop.DBus.Hello, print the assigned unique name.
 *
 *   dbus-auth-client introspect <sock> <object-path>
 *       Call org.freedesktop.DBus.Introspectable.Introspect, print XML.
 *
 *   dbus-auth-client liststrings <sock> <object-path> <interface> <method>
 *       Call method expecting reply signature "as", print one per line.
 *
 *   dbus-auth-client call-s    <sock> <obj> <iface> <method> <string>
 *   dbus-auth-client call-void <sock> <obj> <iface> <method>
 *       Issue method call with the given (or no) argument; "OK" or
 *       "ERROR: <name>" on stderr.
 *
 *   dbus-auth-client call-{s,void}-as-uid <uid> <sock> <obj> <iface> ...
 *       As above, but setuid(<uid>) first so AUTH EXTERNAL claims <uid>.
 *
 *   dbus-auth-client get-service <sock> <identity>
 *       Manager1.GetService(identity) -> print the encoded path.
 *
 *   dbus-auth-client monitor-signal <sock> <match-rule> <timeout-ms>
 *       AddMatch + wait for one SIGNAL.  Print "SIGNAL <iface> <member>"
 *       then any string-typed body args.  Exit 0 on signal, 1 on timeout.
 *
 *   dbus-auth-client unknown <sock>
 *       Call a bogus method, exit 0 iff the server replies with an
 *       org.freedesktop.DBus.Error.* error.
 *
 * Exit codes for the non-auth modes: 0 on success, 1 on server-side
 * error reply, 2 on transport / parse / arg error.
 *
 * Copyright (c) 2026  Joachim Wiberg <troglobit@gmail.com>
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "link.h"

/* ---------- manual SASL: only mode_auth uses this ---------- */

static const char hex[] = "0123456789abcdef";

static int write_all_fd(int fd, const void *buf, size_t len)
{
	const char *p = buf;

	while (len > 0) {
		ssize_t n = write(fd, p, len);
		if (n < 0) {
			if (errno == EINTR) continue;
			return -1;
		}
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

static ssize_t read_line_fd(int fd, char *buf, size_t bufsz)
{
	size_t off = 0;

	while (off + 1 < bufsz) {
		ssize_t n = read(fd, buf + off, 1);
		if (n == 0) return -1;
		if (n < 0) {
			if (errno == EINTR) continue;
			return -1;
		}
		if (buf[off] == '\n') {
			buf[off] = '\0';
			if (off > 0 && buf[off - 1] == '\r')
				buf[--off] = '\0';
			return (ssize_t)off;
		}
		off++;
	}
	return -1;
}

static int mode_auth(int argc, char *argv[])
{
	struct sockaddr_un sun = { .sun_family = AF_UNIX };
	char hexuid[32], line[64], reply[256];
	const char *path, *claimed;
	size_t i, claimed_len, plen;
	int fd, rc;

	if (argc != 4) return 2;
	path    = argv[2];
	claimed = argv[3];

	plen = strlen(path);
	if (plen >= sizeof(sun.sun_path)) return 2;
	claimed_len = strlen(claimed);
	if (claimed_len * 2 >= sizeof(hexuid)) return 2;
	for (i = 0; i < claimed_len; i++) {
		unsigned c = (unsigned char)claimed[i];

		hexuid[i * 2]     = hex[c >> 4];
		hexuid[i * 2 + 1] = hex[c & 0xf];
	}
	hexuid[claimed_len * 2] = '\0';

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) { perror("socket"); return 2; }
	memcpy(sun.sun_path, path, plen + 1);
	if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		perror("connect"); close(fd); return 2;
	}
	if (write_all_fd(fd, "\0", 1) < 0) { close(fd); return 2; }
	rc = snprintf(line, sizeof(line), "AUTH EXTERNAL %s\r\n", hexuid);
	if (rc < 0 || (size_t)rc >= sizeof(line)) { close(fd); return 2; }
	if (write_all_fd(fd, line, (size_t)rc) < 0) { close(fd); return 2; }
	if (read_line_fd(fd, reply, sizeof(reply)) < 0) { close(fd); return 2; }
	printf("%s\n", reply);
	close(fd);
	if (strncmp(reply, "OK ", 3) == 0)        return 0;
	if (strncmp(reply, "REJECTED ", 9) == 0)  return 1;
	return 2;
}

/* ---------- libink-driven modes ---------- */

/* Convert link_client_call rc to the test client's 0/1/2 convention,
 * printing the error name on stderr for ERROR replies. */
static int report_rc(link_client_t *c, int rc)
{
	if (rc == LINK_CALL_OK)
		return 0;
	if (rc == LINK_CALL_ERROR) {
		const link_reply_t *r = link_client_reply(c);
		fprintf(stderr, "ERROR: %s\n",
			(r && r->error_name) ? r->error_name : "<no-name>");
		return 1;
	}
	return 2;
}

/* Drop effective uid to argv-supplied value (decimal). */
static int drop_uid(const char *uid_arg, const char *progname)
{
	char *ep = NULL;
	long  v;

	errno = 0;
	v = strtol(uid_arg, &ep, 10);
	if (errno || !ep || *ep != '\0' || v < 0 || v > 65535) {
		fprintf(stderr, "%s: bad uid: %s\n", progname, uid_arg);
		return 2;
	}
	if (setuid((uid_t)v) < 0) {
		perror("setuid");
		return 2;
	}
	return 0;
}

static int mode_hello(int argc, char *argv[])
{
	link_client_t *c;
	const link_reply_t *r;
	link_reader_t reader;
	const char *name;
	int rc;

	if (argc != 3) return 2;
	c = link_client_open(argv[2]);
	if (!c) return 2;

	rc = link_client_call_v(c, "/org/freedesktop/DBus",
				"org.freedesktop.DBus", "Hello", NULL);
	rc = report_rc(c, rc);
	if (rc == 0) {
		r = link_client_reply(c);
		link_reader_init(&reader, r->body, r->body_len);
		if (link_r_string(&reader, &name) == 0)
			printf("%s\n", name);
		else
			rc = 2;
	}
	link_client_close(c);
	return rc;
}

static int mode_introspect(int argc, char *argv[])
{
	link_client_t *c;
	const link_reply_t *r;
	link_reader_t reader;
	const char *xml;
	int rc;

	if (argc != 4) return 2;
	c = link_client_open(argv[2]);
	if (!c) return 2;

	rc = link_client_call_v(c, argv[3],
				"org.freedesktop.DBus.Introspectable",
				"Introspect", NULL);
	rc = report_rc(c, rc);
	if (rc == 0) {
		r = link_client_reply(c);
		link_reader_init(&reader, r->body, r->body_len);
		if (link_r_string(&reader, &xml) == 0)
			printf("%s\n", xml);
		else
			rc = 2;
	}
	link_client_close(c);
	return rc;
}

/* Decode body with signature "as" -- u32 array byte-len, then "s" strings.
 * libink's public reader doesn't yet have an array helper, so we walk
 * the wire form with link_r_u32 + link_r_string + link_r_pos. */
static int print_string_array(const link_reply_t *r)
{
	link_reader_t reader;
	uint32_t      array_len;
	size_t        end;

	if (!r || !r->signature || strcmp(r->signature, "as") != 0)
		return -1;

	link_reader_init(&reader, r->body, r->body_len);
	if (link_r_u32(&reader, &array_len) < 0)
		return -1;
	end = link_r_pos(&reader) + array_len;
	if (end > r->body_len)
		return -1;

	while (link_r_pos(&reader) < end) {
		const char *s;

		if (link_r_string(&reader, &s) < 0)
			return -1;
		printf("%s\n", s);
	}
	return 0;
}

static int mode_liststrings(int argc, char *argv[])
{
	link_client_t *c;
	int rc;

	if (argc != 6) return 2;
	c = link_client_open(argv[2]);
	if (!c) return 2;

	rc = link_client_call_v(c, argv[3], argv[4], argv[5], NULL);
	rc = report_rc(c, rc);
	if (rc == 0 && print_string_array(link_client_reply(c)) < 0)
		rc = 2;
	link_client_close(c);
	return rc;
}

/* Shared call helpers used by both the plain and the -as-uid modes.
 * `arg` may be NULL (void method); when non-NULL the call signature
 * is "s" with `arg` as the single string argument. */
static int do_call(const char *sock, const char *obj, const char *iface,
		   const char *method, const char *arg)
{
	link_client_t *c;
	int rc;

	c = link_client_open(sock);
	if (!c) return 2;

	rc = arg
		? link_client_call_v(c, obj, iface, method, "s", arg)
		: link_client_call_v(c, obj, iface, method, NULL);
	rc = report_rc(c, rc);
	if (rc == 0)
		printf("OK\n");
	link_client_close(c);
	return rc;
}

static int mode_call_s(int argc, char *argv[])
{
	if (argc != 7) return 2;
	return do_call(argv[2], argv[3], argv[4], argv[5], argv[6]);
}

static int mode_call_void(int argc, char *argv[])
{
	if (argc != 6) return 2;
	return do_call(argv[2], argv[3], argv[4], argv[5], NULL);
}

static int mode_call_s_as_uid(int argc, char *argv[])
{
	int rc;

	if (argc != 8) return 2;
	if ((rc = drop_uid(argv[2], argv[0])) != 0)
		return rc;
	return do_call(argv[3], argv[4], argv[5], argv[6], argv[7]);
}

static int mode_call_void_as_uid(int argc, char *argv[])
{
	int rc;

	if (argc != 7) return 2;
	if ((rc = drop_uid(argv[2], argv[0])) != 0)
		return rc;
	return do_call(argv[3], argv[4], argv[5], argv[6], NULL);
}

static int mode_get_service(int argc, char *argv[])
{
	link_client_t *c;
	const link_reply_t *r;
	link_reader_t reader;
	const char *path;
	int rc;

	if (argc != 4) return 2;
	c = link_client_open(argv[2]);
	if (!c) return 2;

	rc = link_client_call_v(c, "/org/finit/manager",
				"org.finit.Manager1", "GetService",
				"s", argv[3]);
	rc = report_rc(c, rc);
	if (rc == 0) {
		r = link_client_reply(c);
		link_reader_init(&reader, r->body, r->body_len);
		/* Reply signature is "o" but link_r_path / link_r_string
		 * have the same wire form. */
		if (link_r_path(&reader, &path) == 0)
			printf("%s\n", path);
		else
			rc = 2;
	}
	link_client_close(c);
	return rc;
}

static int mode_monitor_signal(int argc, char *argv[])
{
	link_client_t *c;
	const link_reply_t *r;
	link_reader_t reader;
	char *ep = NULL;
	long  v;
	int   timeout_ms;
	int   rc;

	if (argc != 5) return 2;

	errno = 0;
	v = strtol(argv[4], &ep, 10);
	if (errno || !ep || *ep != '\0' || v <= 0 || v > 600000) {
		fprintf(stderr, "%s: bad timeout: %s\n", argv[0], argv[4]);
		return 2;
	}
	timeout_ms = (int)v;

	c = link_client_open(argv[2]);
	if (!c) return 2;

	rc = link_client_call_v(c, "/org/freedesktop/DBus",
				"org.freedesktop.DBus", "AddMatch",
				"s", argv[3]);
	if (rc != LINK_CALL_OK) {
		rc = report_rc(c, rc);
		link_client_close(c);
		return rc;
	}

	for (;;) {
		rc = link_client_wait(c, timeout_ms);
		if (rc != 0) {
			link_client_close(c);
			return 1;	/* timeout or transport */
		}
		r = link_client_reply(c);
		if (!r || r->type != LINK_MSG_SIGNAL)
			continue;

		printf("SIGNAL %s %s\n",
		       r->interface ? r->interface : "<no-iface>",
		       r->member    ? r->member    : "<no-member>");
		/* Print any leading "s" args (other types are silently
		 * skipped -- callers test for the strings only). */
		link_reader_init(&reader, r->body, r->body_len);
		if (r->signature) {
			const char *s;
			const char *p;

			for (p = r->signature; *p == 's'; p++) {
				if (link_r_string(&reader, &s) < 0)
					break;
				printf("%s\n", s);
			}
		}
		link_client_close(c);
		return 0;
	}
}

static int mode_unknown(int argc, char *argv[])
{
	link_client_t *c;
	const link_reply_t *r;
	int rc;

	if (argc != 3) return 2;
	c = link_client_open(argv[2]);
	if (!c) return 2;

	rc = link_client_call_v(c, "/org/finit/manager",
				"org.finit.Manager1", "NotARealMethod", NULL);
	if (rc != LINK_CALL_ERROR) {
		link_client_close(c);
		return rc == LINK_CALL_OK ? 1 : 2;
	}

	r = link_client_reply(c);
	{
		static const char prefix[] = "org.freedesktop.DBus.Error.";
		rc = (r && r->error_name &&
		      strncmp(r->error_name, prefix, sizeof(prefix) - 1) == 0)
			? 0 : 1;
	}
	link_client_close(c);
	return rc;
}

int main(int argc, char *argv[])
{
	if (argc < 2)                                    return 2;
	if (!strcmp(argv[1], "auth"))             return mode_auth            (argc, argv);
	if (!strcmp(argv[1], "hello"))            return mode_hello           (argc, argv);
	if (!strcmp(argv[1], "introspect"))       return mode_introspect      (argc, argv);
	if (!strcmp(argv[1], "liststrings"))      return mode_liststrings     (argc, argv);
	if (!strcmp(argv[1], "call-s"))           return mode_call_s          (argc, argv);
	if (!strcmp(argv[1], "call-void"))        return mode_call_void       (argc, argv);
	if (!strcmp(argv[1], "call-s-as-uid"))    return mode_call_s_as_uid   (argc, argv);
	if (!strcmp(argv[1], "call-void-as-uid")) return mode_call_void_as_uid(argc, argv);
	if (!strcmp(argv[1], "get-service"))      return mode_get_service     (argc, argv);
	if (!strcmp(argv[1], "monitor-signal"))   return mode_monitor_signal  (argc, argv);
	if (!strcmp(argv[1], "unknown"))          return mode_unknown         (argc, argv);
	fprintf(stderr, "%s: unknown mode '%s'\n", argv[0], argv[1]);
	return 2;
}
