/*
* sha256.c  -  SHA-256 and HMAC-SHA-256  (FIPS 180-4 / RFC 2104)
* C89 compliant.
*/

#include "sha256.h"
#include <string.h>

static const uint32_t K[64] = {
	0x428a2f98UL,0x71374491UL,0xb5c0fbcfUL,0xe9b5dba5UL,
	0x3956c25bUL,0x59f111f1UL,0x923f82a4UL,0xab1c5ed5UL,
	0xd807aa98UL,0x12835b01UL,0x243185beUL,0x550c7dc3UL,
	0x72be5d74UL,0x80deb1feUL,0x9bdc06a7UL,0xc19bf174UL,
	0xe49b69c1UL,0xefbe4786UL,0x0fc19dc6UL,0x240ca1ccUL,
	0x2de92c6fUL,0x4a7484aaUL,0x5cb0a9dcUL,0x76f988daUL,
	0x983e5152UL,0xa831c66dUL,0xb00327c8UL,0xbf597fc7UL,
	0xc6e00bf3UL,0xd5a79147UL,0x06ca6351UL,0x14292967UL,
	0x27b70a85UL,0x2e1b2138UL,0x4d2c6dfcUL,0x53380d13UL,
	0x650a7354UL,0x766a0abbUL,0x81c2c92eUL,0x92722c85UL,
	0xa2bfe8a1UL,0xa81a664bUL,0xc24b8b70UL,0xc76c51a3UL,
	0xd192e819UL,0xd6990624UL,0xf40e3585UL,0x106aa070UL,
	0x19a4c116UL,0x1e376c08UL,0x2748774cUL,0x34b0bcb5UL,
	0x391c0cb3UL,0x4ed8aa4aUL,0x5b9cca4fUL,0x682e6ff3UL,
	0x748f82eeUL,0x78a5636fUL,0x84c87814UL,0x8cc70208UL,
	0x90befffaUL,0xa4506cebUL,0xbef9a3f7UL,0xc67178f2UL
};

#define ROTR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z)  (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x)     (ROTR32(x,2) ^ROTR32(x,13)^ROTR32(x,22))
#define EP1(x)     (ROTR32(x,6) ^ROTR32(x,11)^ROTR32(x,25))
#define SIG0(x)    (ROTR32(x,7) ^ROTR32(x,18)^((x)>>3))
#define SIG1(x)    (ROTR32(x,17)^ROTR32(x,19)^((x)>>10))

static void sha256_compress(Sha256Ctx *ctx, const uint8_t block[SHA256_BLOCK_SIZE])
{
	uint32_t w[64];
	uint32_t a, b, c, d, e, f, g, h, t1, t2;
	int i;

	for (i = 0; i < 16; i++) {
		w[i] = ((uint32_t)block[i * 4 + 0] << 24) | ((uint32_t)block[i * 4 + 1] << 16)
			| ((uint32_t)block[i * 4 + 2] << 8) | ((uint32_t)block[i * 4 + 3]);
	}
	for (i = 16; i < 64; i++)
		w[i] = SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16];

	a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
	e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

	for (i = 0; i < 64; i++) {
		t1 = h + EP1(e) + CH(e, f, g) + K[i] + w[i];
		t2 = EP0(a) + MAJ(a, b, c);
		h = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}
	ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
	ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

void sha256_init(Sha256Ctx *ctx)
{
	ctx->state[0] = 0x6a09e667UL; ctx->state[1] = 0xbb67ae85UL;
	ctx->state[2] = 0x3c6ef372UL; ctx->state[3] = 0xa54ff53aUL;
	ctx->state[4] = 0x510e527fUL; ctx->state[5] = 0x9b05688cUL;
	ctx->state[6] = 0x1f83d9abUL; ctx->state[7] = 0x5be0cd19UL;
	ctx->count = 0;
	ctx->buf_len = 0;
}

void sha256_update(Sha256Ctx *ctx, const uint8_t *data, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++) {
		ctx->buf[ctx->buf_len++] = data[i];
		if (ctx->buf_len == SHA256_BLOCK_SIZE) {
			sha256_compress(ctx, ctx->buf);
			ctx->count += SHA256_BLOCK_SIZE * 8;
			ctx->buf_len = 0;
		}
	}
}

void sha256_final(Sha256Ctx *ctx, uint8_t digest[SHA256_DIGEST_SIZE])
{
	uint64_t total_bits;
	uint32_t i;

	total_bits = ctx->count + (uint64_t)ctx->buf_len * 8;
	ctx->buf[ctx->buf_len++] = 0x80;

	if (ctx->buf_len > 56) {
		while (ctx->buf_len < SHA256_BLOCK_SIZE) ctx->buf[ctx->buf_len++] = 0;
		sha256_compress(ctx, ctx->buf);
		ctx->buf_len = 0;
	}
	while (ctx->buf_len < 56) ctx->buf[ctx->buf_len++] = 0;

	ctx->buf[56] = (uint8_t)(total_bits >> 56); ctx->buf[57] = (uint8_t)(total_bits >> 48);
	ctx->buf[58] = (uint8_t)(total_bits >> 40); ctx->buf[59] = (uint8_t)(total_bits >> 32);
	ctx->buf[60] = (uint8_t)(total_bits >> 24); ctx->buf[61] = (uint8_t)(total_bits >> 16);
	ctx->buf[62] = (uint8_t)(total_bits >> 8); ctx->buf[63] = (uint8_t)(total_bits);
	sha256_compress(ctx, ctx->buf);

	for (i = 0; i < 8; i++) {
		digest[i * 4 + 0] = (uint8_t)(ctx->state[i] >> 24);
		digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
		digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
		digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
	}
}

void sha256(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_SIZE])
{
	Sha256Ctx ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, data, len);
	sha256_final(&ctx, digest);
}

void hmac_sha256_init(HmacSha256Ctx *ctx, const uint8_t *key, size_t key_len)
{
	uint8_t k_pad[SHA256_BLOCK_SIZE];
	uint8_t k_hash[SHA256_DIGEST_SIZE];
	size_t  i;

	memset(k_pad, 0, sizeof(k_pad));
	if (key_len > SHA256_BLOCK_SIZE) {
		sha256(key, key_len, k_hash);
		memcpy(k_pad, k_hash, SHA256_DIGEST_SIZE);
	}
	else {
		memcpy(k_pad, key, key_len);
	}

	sha256_init(&ctx->inner);
	for (i = 0; i < SHA256_BLOCK_SIZE; i++) k_pad[i] ^= 0x36;
	sha256_update(&ctx->inner, k_pad, SHA256_BLOCK_SIZE);
	for (i = 0; i < SHA256_BLOCK_SIZE; i++) k_pad[i] ^= 0x36;

	sha256_init(&ctx->outer);
	for (i = 0; i < SHA256_BLOCK_SIZE; i++) k_pad[i] ^= 0x5c;
	sha256_update(&ctx->outer, k_pad, SHA256_BLOCK_SIZE);
}

void hmac_sha256_update(HmacSha256Ctx *ctx, const uint8_t *data, size_t len)
{
	sha256_update(&ctx->inner, data, len);
}

void hmac_sha256_final(HmacSha256Ctx *ctx, uint8_t mac[SHA256_DIGEST_SIZE])
{
	uint8_t inner_hash[SHA256_DIGEST_SIZE];
	sha256_final(&ctx->inner, inner_hash);
	sha256_update(&ctx->outer, inner_hash, SHA256_DIGEST_SIZE);
	sha256_final(&ctx->outer, mac);
}

void hmac_sha256(const uint8_t *key, size_t key_len,
	const uint8_t *data, size_t data_len,
	uint8_t mac[SHA256_DIGEST_SIZE])
{
	HmacSha256Ctx ctx;
	hmac_sha256_init(&ctx, key, key_len);
	hmac_sha256_update(&ctx, data, data_len);
	hmac_sha256_final(&ctx, mac);
}