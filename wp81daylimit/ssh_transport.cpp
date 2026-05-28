/*
* ssh_transport.c  -  SSH-2 binary packet protocol (RFC 4253)
*
* TCP via Winsock2.
* Cipher  : AES-256-CTR   (ssh_client.h / aes256.h)
* MAC     : HMAC-SHA-256  (sha256.h)
* No zlib compression.
*/

/* Target Windows 8.1 / _WIN32_WINNT = 0x0603 */
#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0603
#endif
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ssh_client.h"
#include "ssh_transport.h"
#include "crypto/aes256.h"
#include "crypto/sha256.h"
#include "Win32Api.h"

/* ---- internal: reliable send / recv on a Winsock socket ----------------- */

static int sock_send_all(SOCKET fd, const uint8_t *buf, size_t len)
{
	size_t sent = 0;
	while (sent < len) {
		int n = send((SOCKET)fd, (const char *)(buf + sent), (int)(len - sent), 0);
		if (n == SOCKET_ERROR || n <= 0) return -1;
		sent += (size_t)n;
	}
	return 0;
}

static int sock_recv_all(SOCKET fd, uint8_t *buf, size_t len)
{
	size_t got = 0;
	while (got < len) {
		int n = recv((SOCKET)fd, (char *)(buf + got), (int)(len - got), 0);
		if (n == SOCKET_ERROR || n <= 0) {
			return -1;
		}
		got += (size_t)n;
	}
	return 0;
}

/* ---- TCP connect --------------------------------------------------------- */

int ssh_tcp_connect(const char *host, uint16_t port)
{
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		fprintf(stderr, "[transport] WSAStartup failed: %d\n", WSAGetLastError());
		return -1;
	}

	struct addrinfo hints, *res = NULL;
	char port_str[8];
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	_snprintf_s(port_str, sizeof(port_str), _TRUNCATE, "%u", (unsigned)port);

	if (getaddrinfo(host, port_str, &hints, &res) != 0) {
		fprintf(stderr, "[transport] getaddrinfo failed: %d\n", WSAGetLastError());
		WSACleanup();
		return -1;
	}

	SOCKET fd = INVALID_SOCKET;
	struct addrinfo *p;
	for (p = res; p != NULL; p = p->ai_next) {
		fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (fd == INVALID_SOCKET) continue;
		if (connect(fd, p->ai_addr, (int)p->ai_addrlen) == 0) break;
		closesocket(fd);
		fd = INVALID_SOCKET;
	}
	freeaddrinfo(res);

	if (fd == INVALID_SOCKET) {
		fprintf(stderr, "[transport] connect to %s:%u failed: %d\n",
			host, (unsigned)port, WSAGetLastError());
		WSACleanup();
		return -1;
	}

	/* Cast SOCKET (UINT_PTR) to int — safe for passing around as fd
	on 64-bit Windows as long as we cast back before Winsock calls. */
	return (int)(intptr_t)fd;
}

/* ---- Banner exchange ----------------------------------------------------- */

int ssh_banner_exchange(SshSession *s)
{
	/* Send our banner */
	const char *banner = SSH_ID_STRING "\r\n";
	SOCKET fd = (SOCKET)(intptr_t)s->fd;
	if (sock_send_all(fd, (const uint8_t *)banner, strlen(banner)) != 0) {
		fprintf(stderr, "[transport] failed to send banner\n");
		return -1;
	}
	/* Store client version (without CRLF) */
	strncpy_s(s->client_version, SSH_BANNER_MAX, SSH_ID_STRING, _TRUNCATE);

	/* Read server banner — may be preceded by informational lines */
	char line[SSH_BANNER_MAX];
	for (;;) {
		size_t pos = 0;
		/* Read byte-by-byte until \n */
		for (;;) {
			uint8_t c;
			if (sock_recv_all(fd, &c, 1) != 0) {
				fprintf(stderr, "[transport] connection closed reading banner\n");
				return -1;
			}
			if (c == '\n') break;
			if (c != '\r' && pos < sizeof(line) - 1)
				line[pos++] = (char)c;
		}
		line[pos] = '\0';
		if (strncmp(line, "SSH-", 4) == 0) break;
		/* Skip non-SSH lines (pre-banner comments allowed by RFC 4253 §4.2) */
	}

	strncpy_s(s->server_version, SSH_BANNER_MAX, line, _TRUNCATE);

	return 0;
}

/* ---- Buffer helpers ------------------------------------------------------ */

void buf_put_u32(uint8_t *b, uint32_t v)
{
	b[0] = (uint8_t)(v >> 24);
	b[1] = (uint8_t)(v >> 16);
	b[2] = (uint8_t)(v >> 8);
	b[3] = (uint8_t)(v);
}

uint32_t buf_get_u32(const uint8_t *b)
{
	return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16)
		| ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

int buf_put_string(uint8_t *b, size_t b_size, size_t *off,
	const uint8_t *data, size_t data_len)
{
	if (*off + 4 + data_len > b_size) return -1;
	buf_put_u32(b + *off, (uint32_t)data_len);
	*off += 4;
	if (data_len > 0) memcpy(b + *off, data, data_len);
	*off += data_len;
	return 0;
}

int buf_get_string(const uint8_t *b, size_t b_size, size_t *off,
	const uint8_t **out_ptr, size_t *out_len)
{
	if (*off + 4 > b_size) return -1;
	uint32_t len = buf_get_u32(b + *off);
	*off += 4;
	if ((size_t)len > b_size - *off) return -1;
	*out_ptr = b + *off;
	*out_len = (size_t)len;
	*off += (size_t)len;
	return 0;
}

void hexdump(const char *label, const uint8_t *data, size_t len)
{
	fprintf(stderr, "[%s] (%u bytes)\n", label, len);
	for (size_t i = 0; i < len; i++) {
		fprintf(stderr, "%02x", data[i]);
	}
	fprintf(stderr, "\n");
}

/* ---- Packet send --------------------------------------------------------- */

/*
* SSH binary packet layout (RFC 4253 §6):
*
*   uint32  packet_length   (= 1 + payload_len + padding_len)
*   byte    padding_length
*   byte[n] payload
*   byte[p] random_padding  (p = padding_length)
*   byte[m] mac             (HMAC-SHA-256, not included in packet_length)
*
* Block size = max(8, cipher_block_size) = 16 (AES).
* Minimum padding = 4, padding makes (4 + payload_len + padding_len) % 16 == 0.
*/

#define BLOCK_SIZE  16   /* AES block size */
#define MAC_SIZE    32   /* HMAC-SHA-256 */

int ssh_send_packet(SshSession *s, const uint8_t *payload, size_t payload_len)
{
	/* Compute padding */
	size_t   overhead = 5 + payload_len;   /* 4-byte len + 1-byte padlen + payload */
	size_t   pad = BLOCK_SIZE - (overhead % BLOCK_SIZE);
	if (pad < 4) pad += BLOCK_SIZE;

	size_t   packet_len = 1 + payload_len + pad;  /* padlen byte + payload + pad */
	size_t   total = 4 + packet_len;          /* uint32 header + rest */

											  /* Assemble plaintext packet */
	uint8_t  pkt[SSH_MAX_PACKET + MAC_SIZE];
	if (total + MAC_SIZE > sizeof(pkt)) return -1;

	buf_put_u32(pkt, (uint32_t)packet_len);
	pkt[4] = (uint8_t)pad;
	memcpy(pkt + 5, payload, payload_len);

	/* Random padding: use CSPRNG.
	* On Windows 8.1 RtlGenRandom is available via Winsock/Bcrypt.
	* We use a simple XOR-shift seeded from GetTickCount as fallback —
	* padding bytes are not secret, only the content matters. */
	{
		DWORD tick = GetTickCount();
		for (size_t i = 0; i < pad; i++) {
			tick ^= tick << 13; tick ^= tick >> 17; tick ^= tick << 5;
			pkt[5 + payload_len + i] = (uint8_t)tick;
		}
	}

	SOCKET fd = (SOCKET)(intptr_t)s->fd;

	if (!s->keys_active) {
		/* Plaintext */
		if (sock_send_all(fd, pkt, total) != 0) {
			fprintf(stderr, "[transport/send] send Plaintext failed\n");
			return -1;
		}
	}
	else {
		/* Compute MAC over: uint32(seq) || plaintext_packet */
		uint8_t mac_buf[MAC_SIZE];
		{
			HmacSha256Ctx hctx;
			hmac_sha256_init(&hctx, s->enc.mac_key, SHA256_LEN);
			uint8_t seq_be[4];
			buf_put_u32(seq_be, (uint32_t)s->enc.seq);
			hmac_sha256_update(&hctx, seq_be, 4);
			hmac_sha256_update(&hctx, pkt, total);
			hmac_sha256_final(&hctx, mac_buf);
		}

		/* Encrypt in-place with AES-256-CTR */
		Aes256Ctx aes;
		aes256_key_expand(&aes, s->enc.key);
		aes256_ctr_crypt(&aes, s->enc.iv, pkt, pkt, total);

		/* Send ciphertext then MAC */
		if (sock_send_all(fd, pkt, total) != 0) {
			fprintf(stderr, "[transport/send] send ciphertext failed\n");
			return -1;
		}
		if (sock_send_all(fd, mac_buf, MAC_SIZE) != 0) {
			fprintf(stderr, "[transport/send] send MAC failed\n");
			return -1;
		}
	}

	s->enc.seq++;
	return 0;
}

/* ---- Packet receive ------------------------------------------------------ */

int ssh_recv_packet(SshSession *s, uint8_t *buf, size_t buf_size, size_t *out_len)
{
	SOCKET fd = (SOCKET)(intptr_t)s->fd;

	for (;;) {   /* loop to skip IGNORE/DEBUG transparently */

		uint8_t hdr[BLOCK_SIZE];   /* first block (contains length + padlen) */

		if (!s->keys_active) {
			/* Plaintext: read first 4 bytes to get packet_length */
			if (sock_recv_all(fd, hdr, 4) != 0) return -1;
			uint32_t pkt_len = buf_get_u32(hdr);
			if (pkt_len < 2 || pkt_len > SSH_MAX_PACKET) return -1;

			if (4 + pkt_len > buf_size) return -1;
			buf_put_u32(buf, pkt_len);
			if (sock_recv_all(fd, buf + 4, pkt_len) != 0) return -1;

			uint8_t pad_len = buf[4];
			size_t  pay_len = pkt_len - 1 - pad_len;
			if (pay_len > pkt_len) return -1;

			/* Shift payload to buf[0] */
			memmove(buf, buf + 5, pay_len);
			*out_len = pay_len;
		}
		else {
			/* Encrypted: read first BLOCK_SIZE bytes, decrypt, get length */
			if (sock_recv_all(fd, hdr, BLOCK_SIZE) != 0) {
				return -1;
			}

			Aes256Ctx aes;
			aes256_key_expand(&aes, s->dec.key);

			/* Decrypt first block into a temp buffer */
			uint8_t dec_hdr[BLOCK_SIZE];
			aes256_ctr_crypt(&aes, s->dec.iv, hdr, dec_hdr, BLOCK_SIZE);

			uint32_t pkt_len = buf_get_u32(dec_hdr);
			if (pkt_len < 2 || pkt_len > SSH_MAX_PACKET) {
				fprintf(stderr, "[transport/recv] wrong packet length: %u\n", pkt_len);
				return -1;
			}

			size_t total = 4 + pkt_len;  /* complete packet bytes on wire */
			size_t rest_len = total - BLOCK_SIZE;

			if (total > buf_size) {
				fprintf(stderr, "[transport/recv] total %u > buf_size %u\n", total, buf_size);
				return -1;
			}

			/* Copy decrypted first block into buf */
			memcpy(buf, dec_hdr, BLOCK_SIZE);

			/* Read and decrypt remaining blocks */
			if (rest_len > 0) {
				if (sock_recv_all(fd, buf + BLOCK_SIZE, rest_len) != 0) {
					return -1;
				}
				aes256_ctr_crypt(&aes, s->dec.iv, buf + BLOCK_SIZE, buf + BLOCK_SIZE, rest_len);
			}

			/* Read and verify MAC */
			uint8_t mac_got[MAC_SIZE], mac_exp[MAC_SIZE];
			if (sock_recv_all(fd, mac_got, MAC_SIZE) != 0) {
				return -1;
			}

			{
				HmacSha256Ctx hctx;
				hmac_sha256_init(&hctx, s->dec.mac_key, SHA256_LEN);
				uint8_t seq_be[4];
				buf_put_u32(seq_be, (uint32_t)s->dec.seq);

				/* MAC is over seq || plaintext packet.
				* buf currently holds the decrypted packet, but we need
				* the plaintext that the sender MACed — which is the same
				* plaintext we just decrypted. */
				hmac_sha256_update(&hctx, seq_be, 4);
				hmac_sha256_update(&hctx, buf, total);
				hmac_sha256_final(&hctx, mac_exp);
			}

			/* Constant-time compare */
			uint8_t diff = 0;
			for (int i = 0; i < MAC_SIZE; i++) diff |= mac_got[i] ^ mac_exp[i];
			if (diff != 0) {
				fprintf(stderr, "[transport] MAC verification failed (seq=%llu)\n",
					(unsigned long long)s->dec.seq);
				return -1;
			}

			uint8_t pad_len = buf[4];
			size_t  pay_len = pkt_len - 1 - pad_len;
			if (pad_len < 4 || pay_len > pkt_len) {
				return -1;
			}

			memmove(buf, buf + 5, pay_len);
			*out_len = pay_len;
		}

		s->dec.seq++;

		/* Transparently skip IGNORE and DEBUG packets */
		if (*out_len > 0 &&
			(buf[0] == SSH_MSG_IGNORE || buf[0] == SSH_MSG_DEBUG))
			continue;

		return 0;
	}
}

/* ---- Disconnect ---------------------------------------------------------- */

void ssh_disconnect(SshSession *s, const char *reason)
{
	uint8_t  pkt[512];
	size_t   off = 0;
	size_t   reason_len = reason ? strlen(reason) : 0;

	pkt[off++] = SSH_MSG_DISCONNECT;
	buf_put_u32(pkt + off, 11); off += 4;   /* SSH_DISCONNECT_BY_APPLICATION */
	buf_put_string(pkt, sizeof(pkt), &off,
		(const uint8_t *)reason, reason_len);
	/* language tag: empty string */
	buf_put_string(pkt, sizeof(pkt), &off, (const uint8_t *)"", 0);

	ssh_send_packet(s, pkt, off);

	closesocket((SOCKET)(intptr_t)s->fd);
	s->fd = (int)(intptr_t)INVALID_SOCKET;
	WSACleanup();

	if (s->client_kexinit) { free(s->client_kexinit); s->client_kexinit = NULL; }
	if (s->server_kexinit) { free(s->server_kexinit); s->server_kexinit = NULL; }
}
