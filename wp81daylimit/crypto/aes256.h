#pragma once

/*
* aes256.h  -  AES-256 key schedule + CTR mode
* FIPS 197
* No external dependencies.
*/

#include <stdint.h>
#include <stddef.h>

#define AES_BLOCK_SIZE   16
#define AES256_KEY_SIZE  32
#define AES256_ROUNDS    14

typedef struct {
	uint32_t rk[4 * (AES256_ROUNDS + 1)];  /* round keys (expanded) */
} Aes256Ctx;

/*
* Expand a 32-byte key into the round key schedule.
* Must be called before aes256_ctr_crypt.
*/
void aes256_key_expand(Aes256Ctx *ctx, const uint8_t key[AES256_KEY_SIZE]);

/*
* AES-256-CTR encrypt/decrypt (same operation).
*
* iv_ctr : 16-byte counter block (modified in-place, caller keeps it
*           across calls to maintain the stream).
* in     : input buffer
* out    : output buffer (may alias in)
* len    : number of bytes to process
*/
void aes256_ctr_crypt(Aes256Ctx *ctx,
	uint8_t    iv_ctr[AES_BLOCK_SIZE],
	const uint8_t *in,
	uint8_t       *out,
	size_t         len);