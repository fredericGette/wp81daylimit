#pragma once

/*
 * ssh_client.h  –  Minimal SSH-2 client
 *
 * Supported algorithms (exactly):
 *   KEX       : curve25519-sha256
 *   Host key  : ssh-ed25519
 *   Cipher    : aes256-ctr  (client→server and server→client)
 *   MAC       : hmac-sha2-256 (client→server and server→client)
 *   Compression: none
 */

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------ sizes */
#define SSH_MAX_PACKET      35000
#define SSH_BANNER_MAX      256
#define SSH_ID_STRING       "SSH-2.0-TinySSH_0.1"

/* ------------------------------------------------------------------ SSH message numbers (RFC 4253 / 4252 / 4254) */
#define SSH_MSG_DISCONNECT              1
#define SSH_MSG_IGNORE                  2
#define SSH_MSG_DEBUG                  4
#define SSH_MSG_SERVICE_REQUEST         5
#define SSH_MSG_SERVICE_ACCEPT          6
#define SSH_MSG_KEXINIT                 20
#define SSH_MSG_NEWKEYS                 21
#define SSH_MSG_KEX_ECDH_INIT           30
#define SSH_MSG_KEX_ECDH_REPLY          31
#define SSH_MSG_USERAUTH_REQUEST        50
#define SSH_MSG_USERAUTH_FAILURE        51
#define SSH_MSG_USERAUTH_SUCCESS        52
#define SSH_MSG_USERAUTH_BANNER         53
#define SSH_MSG_GLOBAL_REQUEST          80
#define SSH_MSG_REQUEST_SUCCESS         81
#define SSH_MSG_REQUEST_FAILURE         82
#define SSH_MSG_CHANNEL_OPEN            90
#define SSH_MSG_CHANNEL_OPEN_CONFIRM    91
#define SSH_MSG_CHANNEL_OPEN_FAILURE    92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST   93
#define SSH_MSG_CHANNEL_DATA            94
#define SSH_MSG_CHANNEL_EXTENDED_DATA   95
#define SSH_MSG_CHANNEL_EOF             96
#define SSH_MSG_CHANNEL_CLOSE           97
#define SSH_MSG_CHANNEL_REQUEST         98
#define SSH_MSG_CHANNEL_SUCCESS         99
#define SSH_MSG_CHANNEL_FAILURE         100

/* ------------------------------------------------------------------ key sizes */
#define CURVE25519_KEY_LEN  32
#define ED25519_KEY_LEN     32
#define ED25519_SIG_LEN     64
#define AES256_KEY_LEN      32
#define AES256_IV_LEN       16
#define SHA256_LEN          32
#define HMAC_SHA256_LEN     32

/* ------------------------------------------------------------------ crypto state */
typedef struct {
    uint8_t  key[AES256_KEY_LEN];
    uint8_t  iv[AES256_IV_LEN];   /* running CTR */
    uint8_t  mac_key[SHA256_LEN];
    uint64_t seq;                  /* packet sequence number */
} CryptoDir;

/* ------------------------------------------------------------------ session state */
typedef struct {
    int      fd;                   /* TCP socket */

    /* version strings (no CRLF) */
    char     client_version[SSH_BANNER_MAX];
    char     server_version[SSH_BANNER_MAX];

    /* raw KEXINIT payloads saved for hashing */
    uint8_t *client_kexinit;
    size_t   client_kexinit_len;
    uint8_t *server_kexinit;
    size_t   server_kexinit_len;

    /* Curve25519 ephemeral keys */
    uint8_t  ecdh_client_priv[CURVE25519_KEY_LEN];
    uint8_t  ecdh_client_pub [CURVE25519_KEY_LEN];

    /* session / exchange identifiers */
    uint8_t  session_id[SHA256_LEN];    /* H from first KEX */
    uint8_t  exchange_hash[SHA256_LEN];

    /* server's Ed25519 host public key (raw 32 bytes) */
    uint8_t  server_host_key[ED25519_KEY_LEN];

    /* crypto contexts */
    CryptoDir enc;   /* client → server */
    CryptoDir dec;   /* server → client */
    int       keys_active;

    /* channel */
    uint32_t local_channel;
    uint32_t remote_channel;
    uint32_t remote_window;
    int      channel_open;
} SshSession;

/* ------------------------------------------------------------------ public API */

/* Transport */
int  ssh_tcp_connect(const char *host, uint16_t port);
int  ssh_banner_exchange(SshSession *s);

/* Packet I/O (plaintext or encrypted depending on s->keys_active) */
int  ssh_send_packet(SshSession *s, const uint8_t *payload, size_t len);
int  ssh_recv_packet(SshSession *s, uint8_t *buf, size_t buf_size, size_t *out_len);

/* Key exchange */
int  ssh_kex(SshSession *s);

/* Authentication */
int  ssh_userauth_password(SshSession *s, const char *user, const char *pass);

/* Channel / shell */
int  ssh_open_channel(SshSession *s);
int  ssh_request_shell(SshSession *s);
int  ssh_interactive_loop(SshSession *s);

/* Utilities */
void ssh_disconnect(SshSession *s, const char *reason);
void buf_put_u32(uint8_t *b, uint32_t v);
uint32_t buf_get_u32(const uint8_t *b);
int  buf_put_string(uint8_t *b, size_t b_size, size_t *off,
                    const uint8_t *data, size_t data_len);
int  buf_get_string(const uint8_t *b, size_t b_size, size_t *off,
                    const uint8_t **out_ptr, size_t *out_len);
void hexdump(const char *label, const uint8_t *data, size_t len);
