/*
* ssh_kex.c  -  SSH-2 key exchange  (diagnostic build)
*
* curve25519-sha256 + ssh-ed25519 + SHA-256 KDF
* RFC 4253 §7, draft-ietf-curdle-ssh-curves, RFC 8709
*
* This version emits detailed hexdumps at every step so the exchange-hash
* construction can be verified against Wireshark / OpenSSH -vvv output.
*
* RNG: CryptGenRandom (wincrypt.h / advapi32.lib).
* C89 compliant: all declarations at top of block.
*/

#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0603
#endif
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
//#include <wincrypt.h>   /* CryptAcquireContext, CryptGenRandom */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ssh_client.h"
#include "ssh_kex.h"
#include "ssh_transport.h"
#include "crypto/sha256.h"
#include "crypto/curve25519.h"
#include "crypto/ed25519.h"
#include "crypto/aes256.h"
#include "Win32Api.h"

static Win32Api api_ssh_kex;

/* ---- constants ----------------------------------------------------------- */

#define COOKIE_LEN       16
#define KEX_PAYLOAD_MAX  2048

static const char ALGO_KEX[] = "curve25519-sha256";
static const char ALGO_HOSTKEY[] = "ssh-ed25519";
static const char ALGO_CIPHER[] = "aes256-ctr";
static const char ALGO_MAC[] = "hmac-sha2-256";
static const char ALGO_COMPRESS[] = "none";
static const char ALGO_LANG[] = "";

/* ---- helpers ------------------------------------------------------------- */

static int put_namelist(uint8_t *b, size_t bsz, size_t *off, const char *name)
{
	return buf_put_string(b, bsz, off, (const uint8_t *)name, strlen(name));
}

static int csprng_fill(uint8_t *buf, size_t len)
{
	HCRYPTPROV hProv = 0;
	BOOL       ok;
	if (!api_ssh_kex.CryptAcquireContextA(&hProv, NULL, NULL,
		PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		fprintf(stderr, "[kex] CryptAcquireContext failed: %lu\n", GetLastError());
		return -1;
	}
	ok = api_ssh_kex.CryptGenRandom(hProv, (DWORD)len, buf);
	api_ssh_kex.CryptReleaseContext(hProv, 0);
	if (!ok) {
		fprintf(stderr, "[kex] CryptGenRandom failed: %lu\n", GetLastError());
		return -1;
	}
	return 0;
}

/*
* Encode a 32-byte X25519 output as an SSH mpint (RFC 4251 §5).
*
* X25519 output is little-endian.  SSH mpint is big-endian two's-complement,
* preceded by a 4-byte length.  Always positive; prepend 0x00 if the high bit
* of the big-endian value is set.
*
* Returns total bytes written into mpint_buf (4 + 0or1 + up to 32 = max 37).
*/
static size_t encode_mpint(const uint8_t le32[32], uint8_t mpint_buf[37])
{
	int     start;
	int     needs_pad;
	size_t  data_len;
	size_t  off;

	start = 0;
	while (start < 32 && le32[start] == 0) start++;

	if (start == 32) {
		buf_put_u32(mpint_buf, 0);
		return 4;
	}

	needs_pad = (le32[start] & 0x80) ? 1 : 0;
	data_len = (size_t)(32 - start) + (size_t)needs_pad;
	buf_put_u32(mpint_buf, (uint32_t)data_len);
	off = 4;
	if (needs_pad) mpint_buf[off++] = 0x00;
	memcpy(mpint_buf + off, le32 + start, (size_t)(32 - start));
	off += (size_t)(32 - start);
	return off;
}

/*
* Derive one block of key material (RFC 4253 §7.2).
*/
static void derive_key(const uint8_t *k_mpint, size_t k_mpint_len,
	const uint8_t  H[32],
	char           X,
	const uint8_t  session_id[32],
	uint8_t       *out, size_t need)
{
	Sha256Ctx ctx;
	uint8_t   block[32];
	size_t    have;
	size_t    copy;

	sha256_init(&ctx);
	sha256_update(&ctx, k_mpint, k_mpint_len);
	sha256_update(&ctx, H, 32);
	sha256_update(&ctx, (const uint8_t *)&X, 1);
	sha256_update(&ctx, session_id, 32);
	sha256_final(&ctx, block);

	have = 32;
	memcpy(out, block, have < need ? have : need);
	if (have >= need) return;

	while (have < need) {
		sha256_init(&ctx);
		sha256_update(&ctx, k_mpint, k_mpint_len);
		sha256_update(&ctx, H, 32);
		sha256_update(&ctx, out, have);
		sha256_final(&ctx, block);
		copy = (need - have < 32) ? (need - have) : 32;
		memcpy(out + have, block, copy);
		have += copy;
	}
}

/* ---- Step 1: send SSH_MSG_KEXINIT ---------------------------------------- */

static int send_kexinit(SshSession *s)
{
	uint8_t pkt[KEX_PAYLOAD_MAX];
	uint8_t cookie[COOKIE_LEN];
	size_t  off = 0;

	pkt[off++] = SSH_MSG_KEXINIT;

	if (csprng_fill(cookie, COOKIE_LEN) != 0) return -1;
	memcpy(pkt + off, cookie, COOKIE_LEN);
	off += COOKIE_LEN;

	if (put_namelist(pkt, sizeof(pkt), &off, ALGO_KEX)      < 0) return -1;
	if (put_namelist(pkt, sizeof(pkt), &off, ALGO_HOSTKEY)  < 0) return -1;
	if (put_namelist(pkt, sizeof(pkt), &off, ALGO_CIPHER)   < 0) return -1;
	if (put_namelist(pkt, sizeof(pkt), &off, ALGO_CIPHER)   < 0) return -1;
	if (put_namelist(pkt, sizeof(pkt), &off, ALGO_MAC)      < 0) return -1;
	if (put_namelist(pkt, sizeof(pkt), &off, ALGO_MAC)      < 0) return -1;
	if (put_namelist(pkt, sizeof(pkt), &off, ALGO_COMPRESS) < 0) return -1;
	if (put_namelist(pkt, sizeof(pkt), &off, ALGO_COMPRESS) < 0) return -1;
	if (put_namelist(pkt, sizeof(pkt), &off, ALGO_LANG)     < 0) return -1;
	if (put_namelist(pkt, sizeof(pkt), &off, ALGO_LANG)     < 0) return -1;

	pkt[off++] = 0;
	buf_put_u32(pkt + off, 0);
	off += 4;

	s->client_kexinit = (uint8_t *)malloc(off);
	if (!s->client_kexinit) return -1;
	memcpy(s->client_kexinit, pkt, off);
	s->client_kexinit_len = off;

	return ssh_send_packet(s, pkt, off);
}

/* ---- Step 2: receive + validate SSH_MSG_KEXINIT from server -------------- */

static int recv_kexinit(SshSession *s, uint8_t *buf, size_t buf_size)
{
	const char *required[8];
	size_t      off;
	size_t      len = 0;
	int         i;

	if (ssh_recv_packet(s, buf, buf_size, &len) != 0) return -1;
	if (len < 1 || buf[0] != SSH_MSG_KEXINIT) {
		fprintf(stderr, "[kex] expected KEXINIT, got %u\n", buf[0]);
		return -1;
	}

	s->server_kexinit = (uint8_t *)malloc(len);
	if (!s->server_kexinit) return -1;
	memcpy(s->server_kexinit, buf, len);
	s->server_kexinit_len = len;

	required[0] = ALGO_KEX;      required[1] = ALGO_HOSTKEY;
	required[2] = ALGO_CIPHER;   required[3] = ALGO_CIPHER;
	required[4] = ALGO_MAC;      required[5] = ALGO_MAC;
	required[6] = ALGO_COMPRESS; required[7] = ALGO_COMPRESS;

	off = 1 + COOKIE_LEN;

	for (i = 0; i < 10; i++) {
		const uint8_t *ptr;
		size_t         slen;
		if (buf_get_string(buf, len, &off, &ptr, &slen) != 0) return -1;
		if (i < 8) {
			const char    *req = required[i];
			size_t         rlen = strlen(req);
			const uint8_t *p = ptr;
			size_t         rem = slen;
			int            found = 0;
			while (rem > 0) {
				const uint8_t *comma = (const uint8_t *)memchr(p, ',', rem);
				size_t         tok_len = comma ? (size_t)(comma - p) : rem;
				if (tok_len == rlen && memcmp(p, req, rlen) == 0) {
					found = 1; break;
				}
				if (!comma) break;
				p = comma + 1;
				rem = rem - tok_len - 1;
			}
			if (!found) {
				fprintf(stderr, "[kex] server missing '%s' (field %d)\n", req, i);
				return -1;
			}
		}
	}
	return 0;
}

/* ---- Step 3+4: generate ECDH keypair, send SSH_MSG_KEX_ECDH_INIT --------- */

static int send_ecdh_init(SshSession *s)
{
	uint8_t rand32[32];
	uint8_t pkt[64];
	size_t  off = 0;

	if (csprng_fill(rand32, 32) != 0) return -1;
	curve25519_keygen(rand32, s->ecdh_client_priv, s->ecdh_client_pub);

	pkt[off++] = SSH_MSG_KEX_ECDH_INIT;
	if (buf_put_string(pkt, sizeof(pkt), &off,
		s->ecdh_client_pub, CURVE25519_KEY_LEN) != 0) return -1;

	return ssh_send_packet(s, pkt, off);
}

/* ---- Step 5+6: receive ECDH_REPLY, verify signature ---------------------- */

static int recv_ecdh_reply(SshSession *s,
	uint8_t *buf, size_t buf_size,
	uint8_t shared_out[32],
	uint8_t hash_out[32])
{
	size_t         len = 0;
	size_t         off;
	const uint8_t *hostkey_blob;
	size_t         hostkey_blob_len;
	const uint8_t *server_pub;
	size_t         server_pub_len;
	const uint8_t *sig_blob;
	size_t         sig_blob_len;
	const uint8_t *raw_sig;
	size_t         raw_sig_len;
	uint8_t        k_mpint[37];
	size_t         k_mpint_len;

	if (ssh_recv_packet(s, buf, buf_size, &len) != 0) return -1;
	if (len < 1 || buf[0] != SSH_MSG_KEX_ECDH_REPLY) {
		fprintf(stderr, "[kex] expected ECDH_REPLY, got %u\n", buf[0]);
		return -1;
	}

	off = 1;

	/* ---- Parse host key blob ---- */
	if (buf_get_string(buf, len, &off, &hostkey_blob, &hostkey_blob_len) != 0) return -1;
	{
		size_t         hoff = 0;
		const uint8_t *algo;
		size_t         algo_len;
		const uint8_t *raw_pub;
		size_t         raw_pub_len;

		if (buf_get_string(hostkey_blob, hostkey_blob_len, &hoff, &algo, &algo_len) != 0) return -1;

		if (algo_len != strlen(ALGO_HOSTKEY) || memcmp(algo, ALGO_HOSTKEY, algo_len) != 0) {
			fprintf(stderr, "[kex] host key algorithm mismatch\n");
			return -1;
		}
		if (buf_get_string(hostkey_blob, hostkey_blob_len, &hoff, &raw_pub, &raw_pub_len) != 0) return -1;
		if (raw_pub_len != ED25519_PUBLIC_KEY_LEN) {
			fprintf(stderr, "[kex] bad Ed25519 pubkey length %u\n", (unsigned)raw_pub_len);
			return -1;
		}
		memcpy(s->server_host_key, raw_pub, ED25519_PUBLIC_KEY_LEN);
	}

	/* ---- Server ephemeral public key (Q_S) ---- */
	if (buf_get_string(buf, len, &off, &server_pub, &server_pub_len) != 0) return -1;
	if (server_pub_len != CURVE25519_KEY_LEN) {
		fprintf(stderr, "[kex] bad server ECDH pubkey length %u\n", (unsigned)server_pub_len);
		return -1;
	}

	/* ---- Signature blob ---- */
	if (buf_get_string(buf, len, &off, &sig_blob, &sig_blob_len) != 0) return -1;
	{
		size_t         soff = 0;
		const uint8_t *sig_algo;
		size_t         sig_algo_len;

		if (buf_get_string(sig_blob, sig_blob_len, &soff, &sig_algo, &sig_algo_len) != 0) return -1;

		if (sig_algo_len != strlen(ALGO_HOSTKEY) || memcmp(sig_algo, ALGO_HOSTKEY, sig_algo_len) != 0) {
			fprintf(stderr, "[kex] signature algorithm mismatch\n");
			return -1;
		}
		if (buf_get_string(sig_blob, sig_blob_len, &soff, &raw_sig, &raw_sig_len) != 0) return -1;
		if (raw_sig_len != ED25519_SIGNATURE_LEN) {
			fprintf(stderr, "[kex] bad Ed25519 sig length %u\n", (unsigned)raw_sig_len);
			return -1;
		}
	}

	/* ---- X25519 shared secret ---- */
	if (curve25519_scalarmult(shared_out, s->ecdh_client_priv, server_pub) != 0) {
		fprintf(stderr, "[kex] X25519 returned low-order point\n");
		return -1;
	}

	k_mpint_len = encode_mpint(shared_out, k_mpint);

	/* ---- Exchange hash H ---- */
	/*
	* H = SHA-256(
	*   string(V_C)  client version string (no CRLF)
	*   string(V_S)  server version string (no CRLF)
	*   string(I_C)  client KEXINIT payload (type byte + cookie + lists + ...)
	*   string(I_S)  server KEXINIT payload
	*   string(K_S)  server host key blob (as received on wire)
	*   string(Q_C)  client ephemeral pubkey (32 bytes)
	*   string(Q_S)  server ephemeral pubkey (32 bytes)
	*   mpint(K)     shared secret
	* )
	*/
	{
		Sha256Ctx ctx;
		uint8_t   tmp4[4];
		size_t    vc_len = strlen(s->client_version);
		size_t    vs_len = strlen(s->server_version);

		sha256_init(&ctx);

		/* string(V_C) */
		buf_put_u32(tmp4, (uint32_t)vc_len);
		sha256_update(&ctx, tmp4, 4);
		sha256_update(&ctx, (const uint8_t *)s->client_version, vc_len);

		/* string(V_S) */
		buf_put_u32(tmp4, (uint32_t)vs_len);
		sha256_update(&ctx, tmp4, 4);
		sha256_update(&ctx, (const uint8_t *)s->server_version, vs_len);

		/* string(I_C) */
		buf_put_u32(tmp4, (uint32_t)s->client_kexinit_len);
		sha256_update(&ctx, tmp4, 4);
		sha256_update(&ctx, s->client_kexinit, s->client_kexinit_len);

		/* string(I_S) */
		buf_put_u32(tmp4, (uint32_t)s->server_kexinit_len);
		sha256_update(&ctx, tmp4, 4);
		sha256_update(&ctx, s->server_kexinit, s->server_kexinit_len);

		/* string(K_S) */
		buf_put_u32(tmp4, (uint32_t)hostkey_blob_len);
		sha256_update(&ctx, tmp4, 4);
		sha256_update(&ctx, hostkey_blob, hostkey_blob_len);

		/* string(Q_C) */
		buf_put_u32(tmp4, CURVE25519_KEY_LEN);
		sha256_update(&ctx, tmp4, 4);
		sha256_update(&ctx, s->ecdh_client_pub, CURVE25519_KEY_LEN);

		/* string(Q_S) */
		buf_put_u32(tmp4, (uint32_t)server_pub_len);
		sha256_update(&ctx, tmp4, 4);
		sha256_update(&ctx, server_pub, server_pub_len);

		/* mpint(K) — already encoded with length prefix */
		sha256_update(&ctx, k_mpint, k_mpint_len);

		sha256_final(&ctx, hash_out);
	}

	/* ---- Ed25519 verify: sig covers H ---- */
	if (ed25519_verify(raw_sig, hash_out, SHA256_LEN, s->server_host_key) != 0) {
		fprintf(stderr, "[kex] Ed25519 host key signature INVALID\n");
		return -1;
	}

	return 0;
}

/* ---- Step 7: derive session keys ----------------------------------------- */

static void derive_session_keys(SshSession *s,
	const uint8_t *k_mpint, size_t k_mpint_len,
	const uint8_t  H[32])
{
	derive_key(k_mpint, k_mpint_len, H, 'A', s->session_id, s->enc.iv, AES256_IV_LEN);
	derive_key(k_mpint, k_mpint_len, H, 'B', s->session_id, s->dec.iv, AES256_IV_LEN);
	derive_key(k_mpint, k_mpint_len, H, 'C', s->session_id, s->enc.key, AES256_KEY_LEN);
	derive_key(k_mpint, k_mpint_len, H, 'D', s->session_id, s->dec.key, AES256_KEY_LEN);
	derive_key(k_mpint, k_mpint_len, H, 'E', s->session_id, s->enc.mac_key, SHA256_LEN);
	derive_key(k_mpint, k_mpint_len, H, 'F', s->session_id, s->dec.mac_key, SHA256_LEN);
}

/* ---- Steps 8+9: NEWKEYS -------------------------------------------------- */

static int send_newkeys(SshSession *s)
{
	uint8_t pkt = SSH_MSG_NEWKEYS;
	return ssh_send_packet(s, &pkt, 1);
}

static int recv_newkeys(SshSession *s, uint8_t *buf, size_t buf_size)
{
	size_t len = 0;
	if (ssh_recv_packet(s, buf, buf_size, &len) != 0) return -1;
	if (len < 1 || buf[0] != SSH_MSG_NEWKEYS) {
		fprintf(stderr, "[kex] expected NEWKEYS, got %u\n", buf[0]);
		return -1;
	}

	return 0;
}

/* ---- Public entry point -------------------------------------------------- */

int ssh_kex(SshSession *s)
{
	uint8_t buf[SSH_MAX_PACKET];
	uint8_t shared_secret[32];
	uint8_t exchange_hash[32];
	uint8_t k_mpint[37];
	size_t  k_mpint_len;

	if (send_kexinit(s) != 0) {
		fprintf(stderr, "[kex] send_kexinit failed\n");
		return -1;
	}
	if (recv_kexinit(s, buf, sizeof(buf)) != 0) {
		fprintf(stderr, "[kex] recv_kexinit failed\n");
		return -1;
	}
	if (send_ecdh_init(s) != 0) {
		fprintf(stderr, "[kex] send_ecdh_init failed\n");
		return -1;
	}
	if (recv_ecdh_reply(s, buf, sizeof(buf), shared_secret, exchange_hash) != 0) {
		fprintf(stderr, "[kex] recv_ecdh_reply failed\n");
		return -1;
	}

	memcpy(s->exchange_hash, exchange_hash, 32);
	if (!s->keys_active)
		memcpy(s->session_id, exchange_hash, 32);

	k_mpint_len = encode_mpint(shared_secret, k_mpint);
	derive_session_keys(s, k_mpint, k_mpint_len, exchange_hash);

	if (send_newkeys(s) != 0) {
		fprintf(stderr, "[kex] send NEWKEYS failed\n");
		return -1;
	}
	if (recv_newkeys(s, buf, sizeof(buf)) != 0) {
		fprintf(stderr, "[kex] recv NEWKEYS failed\n");
		return -1;
	}

	s->keys_active = 1;

	free(s->client_kexinit); s->client_kexinit = NULL; s->client_kexinit_len = 0;
	free(s->server_kexinit); s->server_kexinit = NULL; s->server_kexinit_len = 0;
	return 0;
}