/*
* ssh_channel.c  -  SSH-2 connection protocol (RFC 4254)
* Session channel: open -> pty-req -> shell -> interactive I/O.
* Windows 8.1 / Winsock2.  C89 compliant.
*/

#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0603
#endif
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ssh_client.h"
#include "ssh_channel.h"
#include "ssh_transport.h"
#include "Win32Api.h"

static Win32Api api_ssh_channel;

#define LOCAL_WINDOW_SIZE  (1 << 20)
#define LOCAL_MAX_PACKET   32768
#define STDIN_BUF_SIZE     4096

/* Growable append helper — call instead of WriteFile */
static int buf_append(uint8_t **buf, size_t *len, size_t *cap,
	const uint8_t *data, size_t data_len)
{
	if (*len + data_len > *cap) {
		size_t new_cap = (*cap + data_len) * 2;
		uint8_t *p = (uint8_t *)realloc(*buf, new_cap);
		if (!p) return -1;
		*buf = p;
		*cap = new_cap;
	}
	memcpy(*buf + *len, data, data_len);
	*len += data_len;
	return 0;
}

/* Send CHANNEL_DATA, respecting remote window */
static int channel_send_data(SshSession *s, const uint8_t *data, size_t len)
{
	uint8_t pkt[STDIN_BUF_SIZE + 64];
	size_t  off = 0;

	if (s->remote_window == 0) return 0;
	if (len > s->remote_window) len = s->remote_window;

	pkt[off++] = SSH_MSG_CHANNEL_DATA;
	buf_put_u32(pkt + off, s->remote_channel); off += 4;
	if (buf_put_string(pkt, sizeof(pkt), &off, data, len) != 0) return -1;

	if (ssh_send_packet(s, pkt, off) != 0) return -1;
	s->remote_window -= (uint32_t)len;
	return (int)len;
}

static int channel_window_adjust(SshSession *s, uint32_t add)
{
	uint8_t pkt[9];
	size_t  off = 0;
	pkt[off++] = SSH_MSG_CHANNEL_WINDOW_ADJUST;
	buf_put_u32(pkt + off, s->remote_channel); off += 4;
	buf_put_u32(pkt + off, add);               off += 4;
	return ssh_send_packet(s, pkt, off);
}

static int ssh_recv_skip_global_requests(SshSession *s,
	uint8_t *buf, size_t buf_size,
	size_t *out_len)
{
	for (;;) {
		if (ssh_recv_packet(s, buf, buf_size, out_len) != 0) return -1;
		if (*out_len < 1) return -1;

		if (buf[0] != SSH_MSG_GLOBAL_REQUEST) {
			return 0;   /* caller's message — hand it up */
		}

		/* Parse want_reply flag:
		byte      SSH_MSG_GLOBAL_REQUEST (80)
		string    name  (4-byte length + data)
		boolean   want_reply  */
		if (*out_len >= 6) {
			size_t   boff = 1;
			uint32_t name_len = buf_get_u32(buf + boff); boff += 4;
			boff += name_len;   /* skip name */
			if (boff < *out_len) {
				uint8_t want_reply = buf[boff];
				if (want_reply) {
					/* Send SSH_MSG_REQUEST_FAILURE (82) */
					uint8_t reply = SSH_MSG_REQUEST_FAILURE;
					if (ssh_send_packet(s, &reply, 1) != 0) return -1;
				}
			}
		}
		/* Loop: read the next packet */
	}
}

static int ssh_recv_expect_channel(SshSession *s,
	uint8_t *buf, size_t buf_size,
	size_t *out_len,
	uint8_t expected)
{
	for (;;) {
		if (ssh_recv_skip_global_requests(s, buf, buf_size, out_len) != 0)
			return -1;
		if (*out_len < 1) return -1;

		uint8_t msg = buf[0];

		if (msg == expected) {
			return 0;   /* caller's message */
		}

		if (msg == SSH_MSG_CHANNEL_WINDOW_ADJUST) {
			/* byte     type  (93)
			uint32   recipient channel
			uint32   bytes to add        */
			if (*out_len >= 9) {
				uint32_t add = buf_get_u32(buf + 5);
				s->remote_window += add;
			}
			continue;
		}

		if (msg == SSH_MSG_CHANNEL_DATA) {
			/* Buffer or print it — do not discard silently in a real client,
			but for bootstrapping just consume and continue */
			fprintf(stderr, "[channel] received SSH_MSG_CHANNEL_DATA\n");
			continue;
		}

		if (msg == SSH_MSG_CHANNEL_EXTENDED_DATA) {
			/* stderr data from the server — consume */
			continue;
		}

		if (msg == SSH_MSG_CHANNEL_EOF || msg == SSH_MSG_CHANNEL_CLOSE) {
			fprintf(stderr, "[channel] received %s while waiting for type %u\n",
				msg == SSH_MSG_CHANNEL_EOF ? "EOF" : "CLOSE", expected);
			return -1;
		}

		/* Unknown — log and skip */
		fprintf(stderr, "[channel] skipping unexpected msg type %u\n", msg);
	}
}

static int channel_request(SshSession *s, const char *req_type,
	int want_reply,
	const uint8_t *extra, size_t extra_len)
{
	uint8_t pkt[512];
	uint8_t rbuf[256];
	size_t  off = 0;
	size_t  rlen = 0;

	pkt[off++] = SSH_MSG_CHANNEL_REQUEST;
	buf_put_u32(pkt + off, s->remote_channel); off += 4;
	buf_put_string(pkt, sizeof(pkt), &off,
		(const uint8_t *)req_type, strlen(req_type));
	pkt[off++] = (uint8_t)(want_reply ? 1 : 0);
	if (extra && extra_len > 0) {
		if (off + extra_len > sizeof(pkt)) return -1;
		memcpy(pkt + off, extra, extra_len); off += extra_len;
	}
	if (ssh_send_packet(s, pkt, off) != 0) return -1;
	if (!want_reply) return 0;

	if (ssh_recv_expect_channel(s, rbuf, sizeof(rbuf), &rlen, SSH_MSG_CHANNEL_SUCCESS) != 0)
		return -1;

	if (rbuf[0] == SSH_MSG_CHANNEL_FAILURE) {
		fprintf(stderr, "[channel] shell request denied\n");
		return -1;
	}
	if (rlen < 1) return -1;
	if (rbuf[0] == SSH_MSG_CHANNEL_SUCCESS) return 0;
	fprintf(stderr, "[channel] request '%s' rejected (type=%u)\n", req_type, rbuf[0]);
	return -1;
}

int ssh_open_channel(SshSession *s)
{
	uint8_t  pkt[128];
	uint8_t  buf[4096];
	size_t   off = 0;
	size_t   len = 0;

	s->local_channel = 0;

	pkt[off++] = SSH_MSG_CHANNEL_OPEN;
	buf_put_string(pkt, sizeof(pkt), &off, (const uint8_t *)"session", 7);
	buf_put_u32(pkt + off, s->local_channel);  off += 4;
	buf_put_u32(pkt + off, LOCAL_WINDOW_SIZE); off += 4;
	buf_put_u32(pkt + off, LOCAL_MAX_PACKET);  off += 4;
	if (ssh_send_packet(s, pkt, off) != 0) return -1;

	if (ssh_recv_skip_global_requests(s, buf, sizeof(buf), &len) != 0) return -1;
	if (len < 1) return -1;

	if (buf[0] == SSH_MSG_CHANNEL_OPEN_FAILURE) {
		size_t         boff = 1;
		uint32_t       reason = 0;
		const uint8_t *desc;
		size_t         desc_len;
		if (boff + 4 <= len) { reason = buf_get_u32(buf + boff); boff += 4; }
		buf_get_string(buf, len, &boff, &desc, &desc_len);
		fprintf(stderr, "[channel] OPEN_FAILURE reason=%u: %.*s\n",
			(unsigned)reason, (int)desc_len, desc ? desc : (const uint8_t *)"");
		return -1;
	}
	if (buf[0] != SSH_MSG_CHANNEL_OPEN_CONFIRM) {
		fprintf(stderr, "[channel] expected OPEN_CONFIRM, got %u\n", buf[0]);
		return -1;
	}
	if (len < 17) return -1;

	{
		size_t   boff = 1;
		uint32_t recipient;
		recipient = buf_get_u32(buf + boff); boff += 4;
		s->remote_channel = buf_get_u32(buf + boff); boff += 4;
		s->remote_window = buf_get_u32(buf + boff); boff += 4;
		(void)recipient;
	}

	s->channel_open = 1;
	return 0;
}


/* Send an "exec" channel request for the given command.
Returns 0 on success, -1 on failure. */
static int ssh_channel_exec(SshSession *s, const char *cmd)
{
	size_t   cmd_len = strlen(cmd);
	/* 1 (msg) + 4 (recipient) + 4+7 ("exec" type len+"exec") + 1 (want_reply) + 4+cmd_len */
	size_t   pkt_len = 1 + 4 + 4 + 4 + 1 + 4 + cmd_len;
	uint8_t *pkt = (uint8_t *)malloc(pkt_len);
	if (!pkt) return -1;

	size_t o = 0;
	pkt[o++] = SSH_MSG_CHANNEL_REQUEST;
	buf_put_u32(pkt + o, s->remote_channel);  o += 4;
	/* request-type: "exec" */
	buf_put_u32(pkt + o, 4);                  o += 4;
	memcpy(pkt + o, "exec", 4);               o += 4;
	pkt[o++] = 1;                              /* want_reply = TRUE */
	buf_put_u32(pkt + o, (uint32_t)cmd_len);  o += 4;
	memcpy(pkt + o, cmd, cmd_len);

	int rc = ssh_send_packet(s, pkt, pkt_len);
	free(pkt);
	return rc;
}

/* Execute a single command and stream its output to stdout.
No stdin thread, no console mode fiddling.
Returns 0 on clean exit, -1 on error. */
int ssh_exec_loop(SshSession *s, const char *cmd, uint8_t **out_buf, size_t *out_len)
{
	SOCKET   sock = (SOCKET)(intptr_t)s->fd;
	HANDLE   hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
	uint8_t  recv_buf[SSH_MAX_PACKET];
	uint32_t consumed = 0;
	int      got_reply = 0;   /* set once we see CHANNEL_SUCCESS/FAILURE */
	int      remote_eof = 0;
	size_t    out_cap = 0;

	/* ── 1. Send the exec request ─────────────────────────────────────── */
	if (ssh_channel_exec(s, cmd) != 0) {
		fprintf(stderr, "[exec] failed to send exec request\n");
		return -1;
	}

	/* ── 2. Set up a WSA event on the socket (same pattern as before) ─── */
	WSAEVENT sock_event = WSACreateEvent();
	if (sock_event == WSA_INVALID_EVENT) {
		fprintf(stderr, "[exec] WSACreateEvent failed: %d\n", WSAGetLastError());
		return -1;
	}
	if (WSAEventSelect(sock, sock_event, FD_READ | FD_CLOSE) == SOCKET_ERROR) {
		fprintf(stderr, "[exec] WSAEventSelect failed: %d\n", WSAGetLastError());
		WSACloseEvent(sock_event);
		return -1;
	}
	u_long nb = 1;
	ioctlsocket(sock, FIONBIO, &nb);

	/* ── 3. Drain loop ────────────────────────────────────────────────── */
	for (;;) {
		DWORD ret = WaitForSingleObject(sock_event, INFINITE);
		if (ret != WAIT_OBJECT_0) {
			fprintf(stderr, "[exec] wait failed: %lu\n", GetLastError());
			goto done_err;
		}
		WSAResetEvent(sock_event);

		/* Consume all complete packets available right now */
		for (;;) {
			size_t pkt_len = 0;
			int rc = ssh_recv_packet(s, recv_buf, sizeof(recv_buf), &pkt_len);
			if (rc != 0) {
				if (WSAGetLastError() == WSAEWOULDBLOCK)
					break;   /* drained, go back to WaitForSingleObject */
				fprintf(stderr, "[exec] recv error\n");
				goto done_err;
			}

			switch (recv_buf[0]) {

				/* ── exec request outcome ──────────────────────────────── */
			case SSH_MSG_CHANNEL_SUCCESS:
				if (!got_reply) {
					got_reply = 1;   /* this is the exec confirmation, good */
				}
				/* ignore subsequent CHANNEL_SUCCESS (shouldn't happen, but safe) */
				break;

			case SSH_MSG_CHANNEL_FAILURE:
				if (!got_reply) {
					/* exec itself was rejected — bail */
					fprintf(stderr, "[exec] server rejected exec request\n");
					got_reply = 1;
					goto send_close;
				}
				/* ignore CHANNEL_FAILURE for subsequent sub-requests (e.g. exit-status) */
				break;

				/* ── command output ────────────────────────────────────── */
			case SSH_MSG_CHANNEL_DATA: {
				const uint8_t *data;
				size_t         data_len;
				size_t         boff = 5;
				DWORD          written = 0;
				if (buf_get_string(recv_buf, pkt_len, &boff, &data, &data_len) != 0)
					break;
				buf_append(out_buf, out_len, &out_cap, data, data_len);
				consumed += (uint32_t)data_len;
				if (consumed >= LOCAL_WINDOW_SIZE / 2) {
					channel_window_adjust(s, consumed);
					consumed = 0;
				}
				break;
			}

									   /* ── stderr (extended data type 1) ─────────────────────── */
			case SSH_MSG_CHANNEL_EXTENDED_DATA: {
				/* type field at bytes 5-8, then the string */
				const uint8_t *data;
				size_t         data_len;
				size_t         boff = 9;   /* skip msg(1)+recipient(4)+type(4) */
				DWORD          written = 0;
				if (buf_get_string(recv_buf, pkt_len, &boff, &data, &data_len) != 0)
					break;
				/* write stderr to our own stderr */
				WriteFile(GetStdHandle(STD_ERROR_HANDLE),
					data, (DWORD)data_len, &written, NULL);
				break;
			}

			case SSH_MSG_CHANNEL_WINDOW_ADJUST:
				if (pkt_len >= 9) s->remote_window += buf_get_u32(recv_buf + 5);
				break;

			case SSH_MSG_CHANNEL_EOF:
				remote_eof = 1;
				break;

			case SSH_MSG_CHANNEL_CLOSE:
				goto send_close;

				/* exit-status carries the remote process exit code */
			case SSH_MSG_CHANNEL_REQUEST: {
				if (pkt_len < 6) break;
				size_t         boff = 5;
				const uint8_t *rtype;
				size_t         rtype_len;
				buf_get_string(recv_buf, pkt_len, &boff, &rtype, &rtype_len);
				uint8_t want_reply = (boff < pkt_len) ? recv_buf[boff++] : 0;

				if (rtype_len == 11 && memcmp(rtype, "exit-status", 11) == 0) {
					if (boff + 4 <= pkt_len) {
						uint32_t exit_code = buf_get_u32(recv_buf + boff);
						if (exit_code != 0) {
							fprintf(stderr, "Remote commande, exit code: %u", exit_code);
						}
					}
				}
				/* send failure reply if server asked for one */
				if (want_reply) {
					uint8_t fp[5]; size_t fo = 0;
					fp[fo++] = SSH_MSG_CHANNEL_FAILURE;
					buf_put_u32(fp + fo, s->remote_channel);
					ssh_send_packet(s, fp, 5);
				}
				break;
			}

			default:
				break;
			}
		}

		/* Clean exit condition: server sent EOF then CLOSE (or just CLOSE) */
		if (remote_eof && !s->channel_open)
			goto send_close;
	}

send_close:

	{
	uint8_t cp[5]; size_t co = 0;
	cp[co++] = SSH_MSG_CHANNEL_CLOSE;
	buf_put_u32(cp + co, s->remote_channel);
	ssh_send_packet(s, cp, 5);
	s->channel_open = 0;
	}

	WSAEventSelect(sock, sock_event, 0);
	WSACloseEvent(sock_event);
	return 0;

done_err:
	WSAEventSelect(sock, sock_event, 0);
	WSACloseEvent(sock_event);
	return -1;
}