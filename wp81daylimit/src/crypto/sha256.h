#pragma once

/*
* sha256.h  -  SHA-256 and HMAC-SHA-256
* FIPS 180-4 / RFC 2104
* No external dependencies.
*/

#include <stdint.h>
#include <stddef.h>

/* ---- SHA-256 ------------------------------------------------------------ */

#define SHA256_BLOCK_SIZE   64
#define SHA256_DIGEST_SIZE  32

typedef struct {
	uint32_t state[8];
	uint64_t count;          /* total bits processed */
	uint8_t  buf[SHA256_BLOCK_SIZE];
	uint32_t buf_len;
} Sha256Ctx;

void sha256_init(Sha256Ctx *ctx);
void sha256_update(Sha256Ctx *ctx, const uint8_t *data, size_t len);
void sha256_final(Sha256Ctx *ctx, uint8_t digest[SHA256_DIGEST_SIZE]);

/* Single-call helper */
void sha256(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_SIZE]);

/* ---- HMAC-SHA-256 ------------------------------------------------------- */

typedef struct {
	Sha256Ctx inner;
	Sha256Ctx outer;
} HmacSha256Ctx;

void hmac_sha256_init(HmacSha256Ctx *ctx,
	const uint8_t *key, size_t key_len);
void hmac_sha256_update(HmacSha256Ctx *ctx,
	const uint8_t *data, size_t len);
void hmac_sha256_final(HmacSha256Ctx *ctx,
	uint8_t mac[SHA256_DIGEST_SIZE]);

/* Single-call helper */
void hmac_sha256(const uint8_t *key, size_t key_len,
	const uint8_t *data, size_t data_len,
	uint8_t mac[SHA256_DIGEST_SIZE]);