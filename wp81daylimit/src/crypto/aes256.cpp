/*
* aes256.c  -  AES-256 (FIPS 197) + CTR mode.  C89 compliant.
*/

#include "aes256.h"
#include <string.h>

static const uint8_t SBOX[256] = {
	0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
	0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
	0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
	0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
	0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
	0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
	0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
	0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
	0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
	0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
	0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
	0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
	0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
	0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
	0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
	0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t RCON[11] = {
	0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

/* GF(2^8) multiply */
static uint8_t gmul(uint8_t a, uint8_t b)
{
	uint8_t p = 0;
	int     i;
	for (i = 0; i < 8; i++) {
		if (b & 1) p ^= a;
		a = (uint8_t)((a << 1) ^ ((a >> 7) ? 0x1b : 0x00));
		b >>= 1;
	}
	return p;
}

/* MixColumns lookup tables — built once at first call */
static uint32_t Te0[256], Te1[256], Te2[256], Te3[256];
static int      tables_ready = 0;

static void build_tables(void)
{
	int i;
	if (tables_ready) return;
	for (i = 0; i < 256; i++) {
		uint8_t s = SBOX[i];
		uint8_t s2 = gmul(s, 2);
		uint8_t s3 = gmul(s, 3);
		Te0[i] = ((uint32_t)s2 << 24) | ((uint32_t)s << 16) | ((uint32_t)s << 8) | s3;
		Te1[i] = ((uint32_t)s3 << 24) | ((uint32_t)s2 << 16) | ((uint32_t)s << 8) | s;
		Te2[i] = ((uint32_t)s << 24) | ((uint32_t)s3 << 16) | ((uint32_t)s2 << 8) | s;
		Te3[i] = ((uint32_t)s << 24) | ((uint32_t)s << 16) | ((uint32_t)s3 << 8) | s2;
	}
	tables_ready = 1;
}

static uint32_t subword(uint32_t w)
{
	return ((uint32_t)SBOX[(w >> 24) & 0xff] << 24) | ((uint32_t)SBOX[(w >> 16) & 0xff] << 16)
		| ((uint32_t)SBOX[(w >> 8) & 0xff] << 8) | ((uint32_t)SBOX[(w) & 0xff]);
}

static uint32_t rotword(uint32_t w) { return (w << 8) | (w >> 24); }

void aes256_key_expand(Aes256Ctx *ctx, const uint8_t key[AES256_KEY_SIZE])
{
	uint32_t *rk = ctx->rk;
	uint32_t  temp;
	int       i;

	build_tables();

	for (i = 0; i < 8; i++) {
		rk[i] = ((uint32_t)key[4 * i + 0] << 24) | ((uint32_t)key[4 * i + 1] << 16)
			| ((uint32_t)key[4 * i + 2] << 8) | ((uint32_t)key[4 * i + 3]);
	}
	for (i = 8; i < 60; i++) {
		temp = rk[i - 1];
		if (i % 8 == 0) temp = subword(rotword(temp)) ^ ((uint32_t)RCON[i / 8] << 24);
		else if (i % 8 == 4) temp = subword(temp);
		rk[i] = rk[i - 8] ^ temp;
	}
}

static void aes256_encrypt_block(const Aes256Ctx *ctx,
	const uint8_t in[AES_BLOCK_SIZE],
	uint8_t       out[AES_BLOCK_SIZE])
{
	const uint32_t *rk = ctx->rk;
	uint32_t s0, s1, s2, s3, t0, t1, t2, t3;
	int      r;

	s0 = ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) | ((uint32_t)in[2] << 8) | in[3];
	s1 = ((uint32_t)in[4] << 24) | ((uint32_t)in[5] << 16) | ((uint32_t)in[6] << 8) | in[7];
	s2 = ((uint32_t)in[8] << 24) | ((uint32_t)in[9] << 16) | ((uint32_t)in[10] << 8) | in[11];
	s3 = ((uint32_t)in[12] << 24) | ((uint32_t)in[13] << 16) | ((uint32_t)in[14] << 8) | in[15];

	s0 ^= rk[0]; s1 ^= rk[1]; s2 ^= rk[2]; s3 ^= rk[3];

	for (r = 1; r < AES256_ROUNDS; r++) {
		t0 = Te0[(s0 >> 24) & 0xff] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[r * 4 + 0];
		t1 = Te0[(s1 >> 24) & 0xff] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[r * 4 + 1];
		t2 = Te0[(s2 >> 24) & 0xff] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[r * 4 + 2];
		t3 = Te0[(s3 >> 24) & 0xff] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[r * 4 + 3];
		s0 = t0; s1 = t1; s2 = t2; s3 = t3;
	}

	/* Final round — SubBytes + ShiftRows only, no MixColumns */
	t0 = ((uint32_t)SBOX[(s0 >> 24) & 0xff] << 24) | ((uint32_t)SBOX[(s1 >> 16) & 0xff] << 16)
		| ((uint32_t)SBOX[(s2 >> 8) & 0xff] << 8) | ((uint32_t)SBOX[(s3) & 0xff]);
	t1 = ((uint32_t)SBOX[(s1 >> 24) & 0xff] << 24) | ((uint32_t)SBOX[(s2 >> 16) & 0xff] << 16)
		| ((uint32_t)SBOX[(s3 >> 8) & 0xff] << 8) | ((uint32_t)SBOX[(s0) & 0xff]);
	t2 = ((uint32_t)SBOX[(s2 >> 24) & 0xff] << 24) | ((uint32_t)SBOX[(s3 >> 16) & 0xff] << 16)
		| ((uint32_t)SBOX[(s0 >> 8) & 0xff] << 8) | ((uint32_t)SBOX[(s1) & 0xff]);
	t3 = ((uint32_t)SBOX[(s3 >> 24) & 0xff] << 24) | ((uint32_t)SBOX[(s0 >> 16) & 0xff] << 16)
		| ((uint32_t)SBOX[(s1 >> 8) & 0xff] << 8) | ((uint32_t)SBOX[(s2) & 0xff]);

	t0 ^= rk[AES256_ROUNDS * 4 + 0]; t1 ^= rk[AES256_ROUNDS * 4 + 1];
	t2 ^= rk[AES256_ROUNDS * 4 + 2]; t3 ^= rk[AES256_ROUNDS * 4 + 3];

	out[0] = (uint8_t)(t0 >> 24); out[1] = (uint8_t)(t0 >> 16);
	out[2] = (uint8_t)(t0 >> 8); out[3] = (uint8_t)(t0);
	out[4] = (uint8_t)(t1 >> 24); out[5] = (uint8_t)(t1 >> 16);
	out[6] = (uint8_t)(t1 >> 8); out[7] = (uint8_t)(t1);
	out[8] = (uint8_t)(t2 >> 24); out[9] = (uint8_t)(t2 >> 16);
	out[10] = (uint8_t)(t2 >> 8); out[11] = (uint8_t)(t2);
	out[12] = (uint8_t)(t3 >> 24); out[13] = (uint8_t)(t3 >> 16);
	out[14] = (uint8_t)(t3 >> 8); out[15] = (uint8_t)(t3);
}

static void ctr_inc(uint8_t ctr[AES_BLOCK_SIZE])
{
	int i;
	for (i = AES_BLOCK_SIZE - 1; i >= 0; i--)
		if (++ctr[i]) break;
}

void aes256_ctr_crypt(Aes256Ctx *ctx,
	uint8_t    iv_ctr[AES_BLOCK_SIZE],
	const uint8_t *in, uint8_t *out, size_t len)
{
	uint8_t ks[AES_BLOCK_SIZE];
	size_t  i;
	size_t  off = 0;

	while (len > 0) {
		size_t chunk = (len < AES_BLOCK_SIZE) ? len : AES_BLOCK_SIZE;
		aes256_encrypt_block(ctx, iv_ctr, ks);
		ctr_inc(iv_ctr);
		for (i = 0; i < chunk; i++) out[off + i] = in[off + i] ^ ks[i];
		off += chunk;
		len -= chunk;
	}
}