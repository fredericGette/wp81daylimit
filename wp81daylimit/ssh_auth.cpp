/*
* ssh_auth.c  -  SSH-2 user authentication (RFC 4252)
* Password method only.  C89 compliant.
*/

#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0603
#endif
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif

#include <stdio.h>
#include <string.h>

#include "ssh_client.h"
#include "ssh_auth.h"
#include "ssh_transport.h"


static int request_service(SshSession *s, const char *service)
{
	uint8_t pkt[256];
	uint8_t buf[512];
	size_t  off = 0;
	size_t  len = 0;

	pkt[off++] = SSH_MSG_SERVICE_REQUEST;
	if (buf_put_string(pkt, sizeof(pkt), &off,
		(const uint8_t *)service, strlen(service)) != 0) return -1;

	if (ssh_send_packet(s, pkt, off) != 0) {
		fprintf(stderr, "[auth] ssh_send_packet failed\n");
		return -1;
	}

	if (ssh_recv_packet(s, buf, sizeof(buf), &len) != 0) {
		fprintf(stderr, "[auth] ssh_recv_packet failed\n");
		return -1;
	}
	if (len < 1 || buf[0] != SSH_MSG_SERVICE_ACCEPT) {
		fprintf(stderr, "[auth] expected SERVICE_ACCEPT, got %u\n", buf[0]);
		return -1;
	}

	return 0;
}

int ssh_userauth_password(SshSession *s,
	const char *username,
	const char *password)
{
	uint8_t buf[SSH_MAX_PACKET];
	int     attempt;

	if (request_service(s, "ssh-userauth") != 0) {
		fprintf(stderr, "[auth] request_service ssh-userauth failed\n");
		return -1;
	}

	for (attempt = 0; attempt < 4; attempt++) {
		uint8_t pkt[SSH_MAX_PACKET];
		size_t  off = 0;
		size_t  len = 0;

		pkt[off++] = SSH_MSG_USERAUTH_REQUEST;
		if (buf_put_string(pkt, sizeof(pkt), &off,
			(const uint8_t *)username, strlen(username)) != 0) return -1;
		if (buf_put_string(pkt, sizeof(pkt), &off,
			(const uint8_t *)"ssh-connection", 14) != 0) return -1;
		if (buf_put_string(pkt, sizeof(pkt), &off,
			(const uint8_t *)"password", 8) != 0) return -1;
		pkt[off++] = 0;   /* boolean FALSE: not a password change */
		if (buf_put_string(pkt, sizeof(pkt), &off,
			(const uint8_t *)password, strlen(password)) != 0) return -1;

		if (ssh_send_packet(s, pkt, off) != 0) {
			fprintf(stderr, "[auth] ssh_send_packet failed\n");
			return -1;
		}

		if (ssh_recv_packet(s, buf, sizeof(buf), &len) != 0) {
			fprintf(stderr, "[auth] ssh_recv_packet failed\n");
			return -1;
		}

		if (len < 1) return -1;

		switch (buf[0]) {
		case SSH_MSG_USERAUTH_SUCCESS:
			return 0;

		case SSH_MSG_USERAUTH_FAILURE:
			fprintf(stderr, "[auth] authentication failed for user '%s'\n", username);
			return -1;

		case SSH_MSG_USERAUTH_BANNER: {
			size_t         boff = 1;
			const uint8_t *msg;
			size_t         msg_len;
			if (buf_get_string(buf, len, &boff, &msg, &msg_len) == 0 && msg_len > 0)
				fprintf(stderr, "[auth banner] %.*s\n", (int)msg_len, msg);
			continue;   /* re-send auth request */
		}

		default:
			fprintf(stderr, "[auth] unexpected packet type %u\n", buf[0]);
			return -1;
		}
	}

	fprintf(stderr, "[auth] too many banner retries\n");
	return -1;
}