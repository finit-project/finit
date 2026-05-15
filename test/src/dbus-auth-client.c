/* Minimal D-Bus client used by the libink smoke tests.
 *
 * Modes:
 *   dbus-auth-client auth   <sock> <uid>
 *       Send the SASL handshake claiming <uid>; print server reply line.
 *       Exit 0 if reply begins "OK ", 1 if "REJECTED ", 2 otherwise.
 *
 *   dbus-auth-client hello  <sock>
 *       Auth as own uid; call org.freedesktop.DBus.Hello on
 *       /org/freedesktop/DBus.  Print the assigned unique name.
 *
 *   dbus-auth-client introspect <sock> <object-path>
 *       Auth + org.freedesktop.DBus.Introspectable.Introspect.
 *       Print the XML reply.
 *
 *   dbus-auth-client liststrings <sock> <object-path> <interface> <method>
 *       Auth + method call expecting reply signature "as"; print one
 *       string per line.
 *
 *   dbus-auth-client unknown <sock>
 *       Auth + call a bogus method; exits 0 only if the server replies
 *       with an "org.freedesktop.DBus.Error.*" error.
 *
 * In every non-auth mode the program exits 0 on a successful method
 * reply, 1 on a server-side error reply, 2 on transport / parse error.
 *
 * Copyright (c) 2026  Joachim Wiberg <troglobit@gmail.com>
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdint.h>

static const char hex[] = "0123456789abcdef";

#define ALIGN_UP(x, n) (((x) + (n) - 1) & ~((size_t)((n) - 1)))

/* ---------- low level I/O ---------- */

static int write_all(int fd, const void *buf, size_t len)
{
	const char *p = buf;

	while (len > 0) {
		ssize_t n = write(fd, p, len);

		if (n < 0) {
			if (errno == EINTR) continue;
			return -1;
		}
		p   += n;
		len -= (size_t)n;
	}
	return 0;
}

static int read_full(int fd, void *buf, size_t len)
{
	char *p = buf;

	while (len > 0) {
		ssize_t n = read(fd, p, len);

		if (n == 0) return -1;
		if (n < 0) {
			if (errno == EINTR) continue;
			return -1;
		}
		p   += n;
		len -= (size_t)n;
	}
	return 0;
}

static ssize_t read_line(int fd, char *buf, size_t bufsz)
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

/* ---------- connect + AUTH ---------- */

static int connect_and_auth(const char *path, uid_t claimed_uid)
{
	struct sockaddr_un sun = { .sun_family = AF_UNIX };
	char uidstr[16];
	char hexuid[32];
	char line[64];
	char reply[256];
	size_t i, n;
	int fd, rc;

	if (strlen(path) >= sizeof(sun.sun_path))
		return -1;
	memcpy(sun.sun_path, path, strlen(path) + 1);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) return -1;
	if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		close(fd);
		return -1;
	}

	n = (size_t)snprintf(uidstr, sizeof(uidstr), "%u", (unsigned)claimed_uid);
	for (i = 0; i < n; i++) {
		unsigned c = (unsigned char)uidstr[i];

		hexuid[i * 2]     = hex[c >> 4];
		hexuid[i * 2 + 1] = hex[c & 0xf];
	}
	hexuid[n * 2] = '\0';

	if (write_all(fd, "\0", 1) < 0) goto io;

	rc = snprintf(line, sizeof(line), "AUTH EXTERNAL %s\r\n", hexuid);
	if (rc < 0 || (size_t)rc >= sizeof(line)) goto io;
	if (write_all(fd, line, (size_t)rc) < 0) goto io;

	if (read_line(fd, reply, sizeof(reply)) < 0) goto io;
	if (strncmp(reply, "OK ", 3) != 0) {
		fprintf(stderr, "auth failed: %s\n", reply);
		close(fd);
		return -1;
	}

	if (write_all(fd, "BEGIN\r\n", 7) < 0) goto io;
	return fd;

io:
	perror("auth handshake");
	close(fd);
	return -1;
}

/* ---------- D-Bus message build / parse ---------- */

struct buf {
	uint8_t *p;
	size_t   cap;
	size_t   off;
	int      err;
};

static int b_reserve(struct buf *b, size_t align, size_t bytes)
{
	size_t pad = ALIGN_UP(b->off, align) - b->off;

	if (b->err || b->off + pad + bytes > b->cap) {
		b->err = 1;
		return -1;
	}
	while (pad--) b->p[b->off++] = 0;
	return 0;
}

static void b_put_u32(struct buf *b, uint32_t v)
{
	if (b_reserve(b, 4, 4) < 0) return;
	b->p[b->off++] = (uint8_t)(v       & 0xff);
	b->p[b->off++] = (uint8_t)((v >>  8) & 0xff);
	b->p[b->off++] = (uint8_t)((v >> 16) & 0xff);
	b->p[b->off++] = (uint8_t)((v >> 24) & 0xff);
}

static void b_put_byte(struct buf *b, uint8_t v)
{
	if (b_reserve(b, 1, 1) < 0) return;
	b->p[b->off++] = v;
}

static void b_put_string(struct buf *b, const char *s)
{
	size_t len = strlen(s);

	if (b_reserve(b, 4, 4 + len + 1) < 0) return;
	b_put_u32(b, (uint32_t)len);
	memcpy(b->p + b->off, s, len);
	b->off += len;
	b->p[b->off++] = 0;
}

static void b_put_signature(struct buf *b, const char *s)
{
	size_t len = strlen(s);

	if (b_reserve(b, 1, 1 + len + 1) < 0) return;
	b->p[b->off++] = (uint8_t)len;
	memcpy(b->p + b->off, s, len);
	b->off += len;
	b->p[b->off++] = 0;
}

/* Send a method call with an optional argument.
 *   arg_sig == NULL or ""    -> no body
 *   arg_sig == "s"           -> arg_string used
 *   arg_sig == "u"           -> arg_u32 used
 */
static int send_method_call_with_arg(int fd,
				     const char *path,
				     const char *interface,
				     const char *member,
				     const char *arg_sig,
				     const char *arg_string,
				     uint32_t    arg_u32);

static int send_method_call(int fd,
			    const char *path,
			    const char *interface,
			    const char *member)
{
	return send_method_call_with_arg(fd, path, interface, member,
					 NULL, NULL, 0);
}

static int send_method_call_with_arg(int fd,
				     const char *path,
				     const char *interface,
				     const char *member,
				     const char *arg_sig,
				     const char *arg_string,
				     uint32_t    arg_u32)
{
	uint8_t  hdr[2048];
	uint8_t  body[1024];
	struct buf b = { .p = hdr, .cap = sizeof(hdr) };
	struct buf bb = { .p = body, .cap = sizeof(body) };
	size_t   fields_start, fields_end, padded_end;
	uint32_t body_len = 0;

	/* Build body first so its length and the signature are known
	 * before we write the header. */
	if (arg_sig && *arg_sig) {
		if (strcmp(arg_sig, "s") == 0) {
			b_put_string(&bb, arg_string ? arg_string : "");
		} else if (strcmp(arg_sig, "u") == 0) {
			b_put_u32(&bb, arg_u32);
		} else {
			return -1;
		}
		if (bb.err) return -1;
		body_len = (uint32_t)bb.off;
	}

	/* Fixed header */
	memset(hdr, 0, 16);
	hdr[0] = 'l';
	hdr[1] = 1;          /* METHOD_CALL */
	hdr[2] = 0;          /* flags */
	hdr[3] = 1;          /* protocol */
	hdr[4] = (uint8_t)( body_len        & 0xff);
	hdr[5] = (uint8_t)((body_len >>  8) & 0xff);
	hdr[6] = (uint8_t)((body_len >> 16) & 0xff);
	hdr[7] = (uint8_t)((body_len >> 24) & 0xff);
	hdr[8] = 1;          /* serial */
	b.off = 16;
	fields_start = b.off;

	/* PATH */
	b_reserve(&b, 8, 0);
	b_put_byte(&b, 1);
	b_put_signature(&b, "o");
	b_put_string(&b, path);

	if (interface) {
		b_reserve(&b, 8, 0);
		b_put_byte(&b, 2);
		b_put_signature(&b, "s");
		b_put_string(&b, interface);
	}

	b_reserve(&b, 8, 0);
	b_put_byte(&b, 3);
	b_put_signature(&b, "s");
	b_put_string(&b, member);

	if (arg_sig && *arg_sig) {
		b_reserve(&b, 8, 0);
		b_put_byte(&b, 8);
		b_put_signature(&b, "g");
		/* SIGNATURE wire form: 1-byte len, bytes, nul */
		b_put_byte(&b, (uint8_t)strlen(arg_sig));
		if (b.off + strlen(arg_sig) + 1 > b.cap) return -1;
		memcpy(b.p + b.off, arg_sig, strlen(arg_sig));
		b.off += strlen(arg_sig);
		b.p[b.off++] = 0;
	}

	fields_end = b.off;
	{
		uint32_t flen = (uint32_t)(fields_end - fields_start);
		hdr[12] = (uint8_t)( flen        & 0xff);
		hdr[13] = (uint8_t)((flen >>  8) & 0xff);
		hdr[14] = (uint8_t)((flen >> 16) & 0xff);
		hdr[15] = (uint8_t)((flen >> 24) & 0xff);
	}

	padded_end = ALIGN_UP(fields_end, 8);
	while (b.off < padded_end) hdr[b.off++] = 0;

	if (b.err) return -1;

	if (write_all(fd, hdr, b.off) < 0) return -1;
	if (body_len > 0 && write_all(fd, body, body_len) < 0) return -1;
	return 0;
}

/* Read one D-Bus message header + body into msg/body buffers.
 * Returns 0 on success.  Caller-supplied buffers must be large
 * enough; we set them generously. */
struct reply {
	uint8_t  type;
	uint32_t serial;
	uint32_t body_len;
	char     signature[64];
	char     error_name[128];
	uint8_t  body[8192];
};

static int read_reply(int fd, struct reply *r)
{
	uint8_t hdr_fixed[16];
	uint8_t hdr_fields[2048];
	uint32_t fields_len;
	size_t   body_off;
	size_t   pos;

	memset(r, 0, sizeof(*r));

	if (read_full(fd, hdr_fixed, 16) < 0) return -1;
	if (hdr_fixed[0] != 'l') return -1;
	r->type     = hdr_fixed[1];
	r->body_len = (uint32_t)hdr_fixed[4]
		    | ((uint32_t)hdr_fixed[5] << 8)
		    | ((uint32_t)hdr_fixed[6] << 16)
		    | ((uint32_t)hdr_fixed[7] << 24);
	r->serial   = (uint32_t)hdr_fixed[8]
		    | ((uint32_t)hdr_fixed[9]  << 8)
		    | ((uint32_t)hdr_fixed[10] << 16)
		    | ((uint32_t)hdr_fixed[11] << 24);
	fields_len  = (uint32_t)hdr_fixed[12]
		    | ((uint32_t)hdr_fixed[13] << 8)
		    | ((uint32_t)hdr_fixed[14] << 16)
		    | ((uint32_t)hdr_fixed[15] << 24);
	if (fields_len > sizeof(hdr_fields)) return -1;
	if (read_full(fd, hdr_fields, fields_len) < 0) return -1;

	/* Skip header padding to 8 bytes. */
	body_off = (size_t)ALIGN_UP(16 + fields_len, 8);
	if (body_off > 16 + fields_len) {
		uint8_t pad[8];
		if (read_full(fd, pad, body_off - 16 - fields_len) < 0)
			return -1;
	}

	/* Walk header fields, capture SIGNATURE and ERROR_NAME. */
	pos = 0;
	while (pos < fields_len) {
		uint8_t code;
		size_t  vsig_len;

		pos = ALIGN_UP(pos, 8);
		if (pos >= fields_len) break;
		code = hdr_fields[pos++];
		vsig_len = hdr_fields[pos++];
		if (pos + vsig_len + 1 > fields_len) return -1;
		const char *vsig = (const char *)(hdr_fields + pos);
		pos += vsig_len + 1;

		if (vsig[0] == 's' || vsig[0] == 'o') {
			uint32_t slen;
			pos = ALIGN_UP(pos, 4);
			if (pos + 4 > fields_len) return -1;
			slen = (uint32_t)hdr_fields[pos]
			     | ((uint32_t)hdr_fields[pos + 1] << 8)
			     | ((uint32_t)hdr_fields[pos + 2] << 16)
			     | ((uint32_t)hdr_fields[pos + 3] << 24);
			pos += 4;
			if (pos + slen + 1 > fields_len) return -1;
			if (code == 4 && slen < sizeof(r->error_name)) {
				memcpy(r->error_name, hdr_fields + pos, slen);
				r->error_name[slen] = '\0';
			}
			pos += slen + 1;
		} else if (vsig[0] == 'g') {
			uint32_t slen = hdr_fields[pos++];
			if (pos + slen + 1 > fields_len) return -1;
			if (code == 8 && slen < sizeof(r->signature)) {
				memcpy(r->signature, hdr_fields + pos, slen);
				r->signature[slen] = '\0';
			}
			pos += slen + 1;
		} else if (vsig[0] == 'u') {
			pos = ALIGN_UP(pos, 4);
			pos += 4;
		} else {
			return -1;
		}
	}

	if (r->body_len > sizeof(r->body)) return -1;
	if (r->body_len > 0 && read_full(fd, r->body, r->body_len) < 0)
		return -1;
	return 0;
}

/* Decode a body containing exactly one "s" — write into out, return 0. */
static int decode_string(struct reply *r, char *out, size_t outsz)
{
	uint32_t len;

	if (strcmp(r->signature, "s") != 0 || r->body_len < 5)
		return -1;
	len = (uint32_t)r->body[0]
	    | ((uint32_t)r->body[1] << 8)
	    | ((uint32_t)r->body[2] << 16)
	    | ((uint32_t)r->body[3] << 24);
	if (4 + len + 1 > r->body_len) return -1;
	if (len + 1 > outsz) return -1;
	memcpy(out, r->body + 4, len);
	out[len] = '\0';
	return 0;
}

/* Decode a body with signature "as", print one string per line. */
static int decode_array_of_strings(struct reply *r)
{
	uint32_t array_len;
	size_t   pos;

	if (strcmp(r->signature, "as") != 0 || r->body_len < 4)
		return -1;
	array_len = (uint32_t)r->body[0]
		  | ((uint32_t)r->body[1] << 8)
		  | ((uint32_t)r->body[2] << 16)
		  | ((uint32_t)r->body[3] << 24);
	pos = ALIGN_UP(4, 4);
	if (pos + array_len > r->body_len) return -1;

	while (pos < 4 + array_len) {
		uint32_t slen;
		pos = ALIGN_UP(pos, 4);
		if (pos + 4 > r->body_len) return -1;
		slen = (uint32_t)r->body[pos]
		     | ((uint32_t)r->body[pos + 1] << 8)
		     | ((uint32_t)r->body[pos + 2] << 16)
		     | ((uint32_t)r->body[pos + 3] << 24);
		pos += 4;
		if (pos + slen + 1 > r->body_len) return -1;
		printf("%.*s\n", (int)slen, r->body + pos);
		pos += slen + 1;
	}
	return 0;
}

/* ---------- modes ---------- */

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
	if (write_all(fd, "\0", 1) < 0) { close(fd); return 2; }
	rc = snprintf(line, sizeof(line), "AUTH EXTERNAL %s\r\n", hexuid);
	if (rc < 0 || (size_t)rc >= sizeof(line)) { close(fd); return 2; }
	if (write_all(fd, line, (size_t)rc) < 0) { close(fd); return 2; }
	if (read_line(fd, reply, sizeof(reply)) < 0) { close(fd); return 2; }
	printf("%s\n", reply);
	close(fd);
	if (strncmp(reply, "OK ", 3) == 0)        return 0;
	if (strncmp(reply, "REJECTED ", 9) == 0)  return 1;
	return 2;
}

static int do_call_arg(const char *path, const char *obj_path,
		       const char *iface, const char *method,
		       const char *arg_sig, const char *arg_string,
		       uint32_t arg_u32, struct reply *r)
{
	int fd = connect_and_auth(path, getuid());

	if (fd < 0) return 2;
	if (send_method_call_with_arg(fd, obj_path, iface, method,
				      arg_sig, arg_string, arg_u32) < 0) {
		fprintf(stderr, "send: %s\n", strerror(errno));
		close(fd);
		return 2;
	}
	if (read_reply(fd, r) < 0) {
		fprintf(stderr, "read_reply\n");
		close(fd);
		return 2;
	}
	close(fd);
	if (r->type == 3) {
		fprintf(stderr, "ERROR: %s\n", r->error_name);
		return 1;
	}
	return 0;
}

static int do_call(const char *path, const char *obj_path,
		   const char *iface, const char *method,
		   struct reply *r)
{
	return do_call_arg(path, obj_path, iface, method, NULL, NULL, 0, r);
}

static int mode_hello(int argc, char *argv[])
{
	struct reply r;
	char name[256];
	int rc;

	if (argc != 3) return 2;
	rc = do_call(argv[2], "/org/freedesktop/DBus",
		     "org.freedesktop.DBus", "Hello", &r);
	if (rc != 0) return rc;
	if (decode_string(&r, name, sizeof(name)) < 0) return 2;
	printf("%s\n", name);
	return 0;
}

static int mode_introspect(int argc, char *argv[])
{
	struct reply r;
	char xml[8192];
	int rc;

	if (argc != 4) return 2;
	rc = do_call(argv[2], argv[3],
		     "org.freedesktop.DBus.Introspectable", "Introspect", &r);
	if (rc != 0) return rc;
	if (decode_string(&r, xml, sizeof(xml)) < 0) return 2;
	printf("%s\n", xml);
	return 0;
}

static int mode_liststrings(int argc, char *argv[])
{
	struct reply r;
	int rc;

	if (argc != 6) return 2;
	rc = do_call(argv[2], argv[3], argv[4], argv[5], &r);
	if (rc != 0) return rc;
	if (decode_array_of_strings(&r) < 0) return 2;
	return 0;
}

/* call-s:    method taking one string arg, void/error reply.
 * call-void: method taking no args, void/error reply. */
static int mode_call_s(int argc, char *argv[])
{
	struct reply r;
	int rc;

	if (argc != 7) return 2;
	rc = do_call_arg(argv[2], argv[3], argv[4], argv[5],
			 "s", argv[6], 0, &r);
	if (rc == 0)
		printf("OK\n");
	return rc;
}

static int mode_call_void(int argc, char *argv[])
{
	struct reply r;
	int rc;

	if (argc != 6) return 2;
	rc = do_call_arg(argv[2], argv[3], argv[4], argv[5],
			 NULL, NULL, 0, &r);
	if (rc == 0)
		printf("OK\n");
	return rc;
}

/* call-s-as-uid <uid> <sock> <obj> <iface> <method> <arg>
 *
 * Drops effective uid to <uid> (must work inside the test
 * namespace where additional uids are mapped) before connecting,
 * so AUTH EXTERNAL captures <uid> as the peer's real identity.
 * Used to verify per-method authorization gating. */
static int mode_call_s_as_uid(int argc, char *argv[])
{
	struct reply r;
	uid_t  drop_to;
	char  *ep = NULL;
	long   v;
	int    rc;

	if (argc != 8) return 2;

	errno = 0;
	v = strtol(argv[2], &ep, 10);
	if (errno || !ep || *ep != '\0' || v < 0 || v > 65535) {
		fprintf(stderr, "%s: bad uid: %s\n", argv[0], argv[2]);
		return 2;
	}
	drop_to = (uid_t)v;

	if (setuid(drop_to) < 0) {
		perror("setuid");
		return 2;
	}

	rc = do_call_arg(argv[3], argv[4], argv[5], argv[6],
			 "s", argv[7], 0, &r);
	if (rc == 0)
		printf("OK\n");
	return rc;
}

static int mode_unknown(int argc, char *argv[])
{
	struct reply r;
	int rc;

	if (argc != 3) return 2;
	rc = do_call(argv[2], "/org/finit/manager",
		     "org.finit.Manager1", "NotARealMethod", &r);
	if (rc == 1 && strstr(r.error_name, "org.freedesktop.DBus.Error.") == r.error_name)
		return 0;
	if (rc == 1)
		return 1;
	return 2;
}

int main(int argc, char *argv[])
{
	if (argc < 2)                                    return 2;
	if (strcmp(argv[1], "auth")        == 0) return mode_auth(argc, argv);
	if (strcmp(argv[1], "hello")       == 0) return mode_hello(argc, argv);
	if (strcmp(argv[1], "introspect")  == 0) return mode_introspect(argc, argv);
	if (strcmp(argv[1], "liststrings") == 0) return mode_liststrings(argc, argv);
	if (strcmp(argv[1], "call-s")        == 0) return mode_call_s(argc, argv);
	if (strcmp(argv[1], "call-void")     == 0) return mode_call_void(argc, argv);
	if (strcmp(argv[1], "call-s-as-uid") == 0) return mode_call_s_as_uid(argc, argv);
	if (strcmp(argv[1], "unknown")     == 0) return mode_unknown(argc, argv);
	fprintf(stderr, "%s: unknown mode '%s'\n", argv[0], argv[1]);
	return 2;
}
