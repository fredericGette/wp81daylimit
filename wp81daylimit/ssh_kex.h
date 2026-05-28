#pragma once

/*
 * ssh_kex.h  -  SSH-2 key exchange (RFC 4253 §7 + RFC 5656 ECDH)
 *
 * Implements exactly:
 *   KEX        : curve25519-sha256  (draft-ietf-curdle-ssh-curves)
 *   Host key   : ssh-ed25519        (RFC 8709)
 *   Key derive : SHA-256 based KDF  (RFC 4253 §7.2)
 *
 * After ssh_kex() returns 0:
 *   s->enc  is ready for client→server encryption + MAC
 *   s->dec  is ready for server→client decryption + MAC
 *   s->session_id  holds the session identifier (H from first KEX)
 *   s->keys_active == 1
 */

#include "ssh_client.h"

/*
 * Perform the full key exchange:
 *   1. Send SSH_MSG_KEXINIT (client)
 *   2. Receive SSH_MSG_KEXINIT (server) and verify algorithm match
 *   3. Generate ephemeral Curve25519 key pair
 *   4. Send SSH_MSG_KEX_ECDH_INIT
 *   5. Receive SSH_MSG_KEX_ECDH_REPLY
 *   6. Verify server host key (Ed25519 signature over exchange hash H)
 *   7. Derive six key material blocks (IV×2, key×2, integrity×2)
 *   8. Send SSH_MSG_NEWKEYS, receive SSH_MSG_NEWKEYS
 *   9. Activate s->enc / s->dec
 *
 * Returns 0 on success, -1 on any failure.
 */
int ssh_kex(SshSession *s);
