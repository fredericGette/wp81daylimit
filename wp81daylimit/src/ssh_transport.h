#pragma once

/*
 * ssh_transport.h  -  SSH-2 binary packet protocol (RFC 4253 §6)
 *
 * Handles:
 *   - TCP banner exchange
 *   - Packet framing: send and receive, plaintext and encrypted
 *   - Buffer serialisation helpers (uint32, SSH string, mpint)
 *   - Utility: hexdump, disconnect
 *
 * Cipher   : AES-256-CTR
 * MAC      : HMAC-SHA-256 (encrypt-then-mac, seq prepended)
 * Block sz : 16 bytes  →  minimum padding 4, aligned to 16
 */

#include "ssh_client.h"

/*
 * Exchange SSH version banners.
 * Sends SSH_ID_STRING\r\n, reads server banner.
 * Stores both (without CRLF) in s->client_version / s->server_version.
 * Returns 0 on success, -1 on error.
 */
int ssh_banner_exchange(SshSession *s);

/*
 * Send one SSH-2 binary packet.
 *
 * payload     : raw SSH message (starting with message-type byte)
 * payload_len : length of payload
 *
 * If s->keys_active == 0: sends plaintext packet.
 * If s->keys_active != 0: encrypts with AES-256-CTR and appends
 *                          HMAC-SHA-256 MAC.
 * Returns 0 on success, -1 on error.
 */
int ssh_send_packet(SshSession *s, const uint8_t *payload, size_t payload_len);

/*
 * Receive one SSH-2 binary packet.
 *
 * buf      : caller-supplied buffer (at least SSH_MAX_PACKET bytes)
 * buf_size : size of buf
 * out_len  : set to the payload length on success
 *
 * Decrypts (if keys active) and verifies MAC.
 * Skips SSH_MSG_IGNORE and SSH_MSG_DEBUG transparently.
 * Returns 0 on success, -1 on error.
 */
int ssh_recv_packet(SshSession *s, uint8_t *buf, size_t buf_size, size_t *out_len);

/*
 * Send SSH_MSG_DISCONNECT and close the socket.
 */
void ssh_disconnect(SshSession *s, const char *reason);

/* ---- Buffer helpers ------------------------------------------------------ */

/* Write big-endian uint32 into b[0..3] */
void     buf_put_u32(uint8_t *b, uint32_t v);

/* Read big-endian uint32 from b[0..3] */
uint32_t buf_get_u32(const uint8_t *b);

/*
 * Append an SSH "string" (uint32 length + data) to buffer b.
 * b_size : total capacity of b
 * off    : current write offset, advanced on success
 * Returns 0 on success, -1 if buffer too small.
 */
int buf_put_string(uint8_t *b, size_t b_size, size_t *off,
                   const uint8_t *data, size_t data_len);

/*
 * Read an SSH "string" from buffer b at *off.
 * Sets *out_ptr to point inside b, sets *out_len.
 * Advances *off past the string.
 * Returns 0 on success, -1 on malformed input.
 */
int buf_get_string(const uint8_t *b, size_t b_size, size_t *off,
                   const uint8_t **out_ptr, size_t *out_len);

/* Debug hex dump to stderr */
void hexdump(const char *label, const uint8_t *data, size_t len);

/* TCP connect helper (Winsock2) */
int ssh_tcp_connect(const char *host, uint16_t port);
