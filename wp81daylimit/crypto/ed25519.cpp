/*
* ed25519.c  -  Ed25519 signature verification (RFC 8032)
*
* Verify-only.  ref10 field representation: 10 signed 32-bit limbs,
* alternating 26-bit and 25-bit widths.
*
* Bugs fixed vs previous version:
*   1. fe_frombytes: all 10 limb loads had wrong byte offsets and shifts.
*      Correct offsets derived from bit positions 0,26,51,77,102,128,153,179,204,230.
*   2. ed25519_verify: h32 was 32 bytes but sc_reduce needs 64 bytes in-place.
*   3. sc_reduce: works correctly on 64-byte input (ref10 algorithm).
*
* SHA-512 is implemented locally (Ed25519 uses SHA-512 internally).
* C89 compliant.
*/

#include "ed25519.h"
#include <string.h>

/* =========================================================================
* SHA-512
* ========================================================================= */

#define SHA512_BLOCK  128
#define SHA512_DIGEST  64

typedef struct {
	uint64_t state[8];
	uint64_t count[2];
	uint8_t  buf[SHA512_BLOCK];
	uint32_t buf_len;
} Sha512Ctx;

#define R64(x,n) (((x)>>(n))|((x)<<(64-(n))))

static const uint64_t K512[80] = {
	0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
	0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
	0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
	0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
	0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
	0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
	0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
	0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
	0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
	0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
	0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
	0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
	0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
	0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
	0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
	0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

static void sha512_compress(Sha512Ctx *ctx, const uint8_t *blk)
{
	uint64_t w[80];
	uint64_t a, b, c, d, e, f, g, h, t1, t2;
	int i;
	for (i = 0; i < 16; i++)
		w[i] = ((uint64_t)blk[i * 8 + 0] << 56) | ((uint64_t)blk[i * 8 + 1] << 48)
		| ((uint64_t)blk[i * 8 + 2] << 40) | ((uint64_t)blk[i * 8 + 3] << 32)
		| ((uint64_t)blk[i * 8 + 4] << 24) | ((uint64_t)blk[i * 8 + 5] << 16)
		| ((uint64_t)blk[i * 8 + 6] << 8) | ((uint64_t)blk[i * 8 + 7]);
	for (i = 16; i < 80; i++) {
		uint64_t s0 = R64(w[i - 15], 1) ^ R64(w[i - 15], 8) ^ (w[i - 15] >> 7);
		uint64_t s1 = R64(w[i - 2], 19) ^ R64(w[i - 2], 61) ^ (w[i - 2] >> 6);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
	e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
	for (i = 0; i < 80; i++) {
		t1 = h + (R64(e, 14) ^ R64(e, 18) ^ R64(e, 41)) + ((e&f) ^ (~e&g)) + K512[i] + w[i];
		t2 = (R64(a, 28) ^ R64(a, 34) ^ R64(a, 39)) + ((a&b) ^ (a&c) ^ (b&c));
		h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	}
	ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
	ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha512_init(Sha512Ctx *ctx)
{
	ctx->state[0] = 0x6a09e667f3bcc908ULL; ctx->state[1] = 0xbb67ae8584caa73bULL;
	ctx->state[2] = 0x3c6ef372fe94f82bULL; ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
	ctx->state[4] = 0x510e527fade682d1ULL; ctx->state[5] = 0x9b05688c2b3e6c1fULL;
	ctx->state[6] = 0x1f83d9abfb41bd6bULL; ctx->state[7] = 0x5be0cd19137e2179ULL;
	ctx->count[0] = ctx->count[1] = 0;
	ctx->buf_len = 0;
}

static void sha512_update(Sha512Ctx *ctx, const uint8_t *data, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++) {
		ctx->buf[ctx->buf_len++] = data[i];
		if (ctx->buf_len == SHA512_BLOCK) {
			sha512_compress(ctx, ctx->buf);
			ctx->count[0] += SHA512_BLOCK * 8;
			if (ctx->count[0] == 0) ctx->count[1]++;
			ctx->buf_len = 0;
		}
	}
}

static void sha512_final(Sha512Ctx *ctx, uint8_t digest[SHA512_DIGEST])
{
	uint64_t lo = ctx->count[0] + (uint64_t)ctx->buf_len * 8;
	uint64_t hi = ctx->count[1] + (lo < ctx->count[0] ? 1 : 0);
	int i;
	ctx->buf[ctx->buf_len++] = 0x80;
	if (ctx->buf_len > 112) {
		while (ctx->buf_len < SHA512_BLOCK) ctx->buf[ctx->buf_len++] = 0;
		sha512_compress(ctx, ctx->buf);
		ctx->buf_len = 0;
	}
	while (ctx->buf_len < 112) ctx->buf[ctx->buf_len++] = 0;
	for (i = 0; i < 8; i++) ctx->buf[112 + i] = (uint8_t)(hi >> (56 - 8 * i));
	for (i = 0; i < 8; i++) ctx->buf[120 + i] = (uint8_t)(lo >> (56 - 8 * i));
	sha512_compress(ctx, ctx->buf);
	for (i = 0; i < 8; i++) {
		digest[i * 8 + 0] = (uint8_t)(ctx->state[i] >> 56); digest[i * 8 + 1] = (uint8_t)(ctx->state[i] >> 48);
		digest[i * 8 + 2] = (uint8_t)(ctx->state[i] >> 40); digest[i * 8 + 3] = (uint8_t)(ctx->state[i] >> 32);
		digest[i * 8 + 4] = (uint8_t)(ctx->state[i] >> 24); digest[i * 8 + 5] = (uint8_t)(ctx->state[i] >> 16);
		digest[i * 8 + 6] = (uint8_t)(ctx->state[i] >> 8); digest[i * 8 + 7] = (uint8_t)(ctx->state[i]);
	}
}

/* =========================================================================
* GF(2^255-19) — ref10 representation
*
* 10 signed 32-bit limbs with alternating widths:
*   limbs 0,2,4,6,8 hold 26 bits
*   limbs 1,3,5,7,9 hold 25 bits
*
* Bit layout in the 256-bit little-endian byte string:
*   limb 0: bits   0.. 25  -> load4(s, 0) >> 0
*   limb 1: bits  26.. 50  -> load4(s, 3) >> 2
*   limb 2: bits  51.. 76  -> load4(s, 6) >> 3
*   limb 3: bits  77..101  -> load4(s, 9) >> 5
*   limb 4: bits 102..127  -> load4(s,12) >> 6
*   limb 5: bits 128..152  -> load4(s,16) >> 0
*   limb 6: bits 153..178  -> load4(s,19) >> 1
*   limb 7: bits 179..203  -> load4(s,22) >> 3
*   limb 8: bits 204..229  -> load4(s,25) >> 4
*   limb 9: bits 230..254  -> load4(s,28) >> 6
* ========================================================================= */

typedef int32_t fe[10];

/* Helper: load 4 bytes little-endian as uint32 */
static uint32_t load4(const uint8_t *s, int i)
{
	return (uint32_t)s[i]
		| ((uint32_t)s[i + 1] << 8)
		| ((uint32_t)s[i + 2] << 16)
		| ((uint32_t)s[i + 3] << 24);
}

static void fe_0(fe h) { int i; for (i = 0; i<10; i++) h[i] = 0; }
static void fe_1(fe h) { fe_0(h); h[0] = 1; }
static void fe_cpy(fe d, const fe s) { int i; for (i = 0; i<10; i++) d[i] = s[i]; }
static void fe_add(fe h, const fe f, const fe g) { int i; for (i = 0; i<10; i++) h[i] = f[i] + g[i]; }
static void fe_sub(fe h, const fe f, const fe g) { int i; for (i = 0; i<10; i++) h[i] = f[i] - g[i]; }
static void fe_neg(fe h, const fe f) { int i; for (i = 0; i<10; i++) h[i] = -f[i]; }

static void fe_cmov(fe f, const fe g, uint32_t b)
{
	int32_t mask = -(int32_t)b;
	int     i;
	for (i = 0; i < 10; i++) f[i] ^= mask & (f[i] ^ g[i]);
}

/* Load a 32-byte little-endian field element.
* The top bit of byte 31 is ignored (Curve25519/Ed25519 convention). */
static void fe_frombytes(fe h, const uint8_t *s)
{
	int64_t h0, h1, h2, h3, h4, h5, h6, h7, h8, h9;

	/*
	* Each load4 straddles the correct byte boundary for the limb.
	* Shift and mask extract exactly the required bits.
	*/
	/*
	* The masks guarantee each limb is in [0, 2^width), which is the valid
	* unsigned range for fe_tobytes. No carry normalisation needed here —
	* the carry pass used in fe_mul/fe_sq introduces signed limbs that are
	* NOT compatible with fe_tobytes unless a full conditional reduction is
	* done. For fe_frombytes the masks are sufficient and produce non-negative
	* limbs that fe_tobytes handles correctly.
	*/
	h0 = (int64_t)((load4(s, 0) >> 0) & 0x3ffffffU);
	h1 = (int64_t)((load4(s, 3) >> 2) & 0x1ffffffU);
	h2 = (int64_t)((load4(s, 6) >> 3) & 0x3ffffffU);
	h3 = (int64_t)((load4(s, 9) >> 5) & 0x1ffffffU);
	h4 = (int64_t)((load4(s, 12) >> 6) & 0x3ffffffU);
	h5 = (int64_t)((load4(s, 16) >> 0) & 0x1ffffffU);
	h6 = (int64_t)((load4(s, 19) >> 1) & 0x3ffffffU);
	h7 = (int64_t)((load4(s, 22) >> 3) & 0x1ffffffU);
	h8 = (int64_t)((load4(s, 25) >> 4) & 0x3ffffffU);
	h9 = (int64_t)((load4(s, 28) >> 6) & 0x1ffffffU);

	h[0] = (int32_t)h0; h[1] = (int32_t)h1; h[2] = (int32_t)h2; h[3] = (int32_t)h3; h[4] = (int32_t)h4;
	h[5] = (int32_t)h5; h[6] = (int32_t)h6; h[7] = (int32_t)h7; h[8] = (int32_t)h8; h[9] = (int32_t)h9;
}

/*
* fe_tobytes: pack field element limbs into 32 little-endian bytes.
*
* After fe_mul's unsigned carry chain, limbs are in [0, 2^width) and the
* represented value is in [0, 2p).  We must reduce mod p before packing.
*
* Reduction: if value >= p, subtract p.  Since p = 2^255-19, subtracting p
* is equivalent to adding 19 (mod 2^255).  We compute q ∈ {0,1}:
*   q = 1 iff all odd limbs are 0x1ffffff AND all even limbs are 0x3ffffff
*          AND h0 >= 0x3ffffed (= p mod 2^26).
* Then h0 += 19*q and carry-propagate to produce canonical limbs in [0,2^width).
*/
static void fe_tobytes(uint8_t *s, const fe h)
{
	int32_t h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4];
	int32_t h5 = h[5], h6 = h[6], h7 = h[7], h8 = h[8], h9 = h[9];
	int32_t q, c;

	/* Determine q: does the represented value exceed p? */
	q = (h9 == 0x1ffffff) & (h8 == 0x3ffffff) & (h7 == 0x1ffffff)
		& (h6 == 0x3ffffff) & (h5 == 0x1ffffff) & (h4 == 0x3ffffff)
		& (h3 == 0x1ffffff) & (h2 == 0x3ffffff) & (h1 == 0x1ffffff)
		& (h0 >= 0x3ffffed);

	/* Conditionally subtract p by adding 19*q to h0, then propagate */
	h0 += 19 * q;
	c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
	c = h1 >> 25; h1 &= 0x1ffffff; h2 += c;
	c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
	c = h3 >> 25; h3 &= 0x1ffffff; h4 += c;
	c = h4 >> 26; h4 &= 0x3ffffff; h5 += c;
	c = h5 >> 25; h5 &= 0x1ffffff; h6 += c;
	c = h6 >> 26; h6 &= 0x3ffffff; h7 += c;
	c = h7 >> 25; h7 &= 0x1ffffff; h8 += c;
	c = h8 >> 26; h8 &= 0x3ffffff; h9 += c;
	/* h9 is now ≤ 0x1ffffff; no further carry needed */

	s[0] = (uint8_t)(h0); s[1] = (uint8_t)(h0 >> 8); s[2] = (uint8_t)(h0 >> 16);
	s[3] = (uint8_t)((h0 >> 24) | (h1 << 2));
	s[4] = (uint8_t)(h1 >> 6); s[5] = (uint8_t)(h1 >> 14);
	s[6] = (uint8_t)((h1 >> 22) | (h2 << 3));
	s[7] = (uint8_t)(h2 >> 5); s[8] = (uint8_t)(h2 >> 13);
	s[9] = (uint8_t)((h2 >> 21) | (h3 << 5));
	s[10] = (uint8_t)(h3 >> 3); s[11] = (uint8_t)(h3 >> 11);
	s[12] = (uint8_t)((h3 >> 19) | (h4 << 6));
	s[13] = (uint8_t)(h4 >> 2); s[14] = (uint8_t)(h4 >> 10); s[15] = (uint8_t)(h4 >> 18);
	s[16] = (uint8_t)(h5); s[17] = (uint8_t)(h5 >> 8); s[18] = (uint8_t)(h5 >> 16);
	s[19] = (uint8_t)((h5 >> 24) | (h6 << 1));
	s[20] = (uint8_t)(h6 >> 7); s[21] = (uint8_t)(h6 >> 15);
	s[22] = (uint8_t)((h6 >> 23) | (h7 << 3));
	s[23] = (uint8_t)(h7 >> 5); s[24] = (uint8_t)(h7 >> 13);
	s[25] = (uint8_t)((h7 >> 21) | (h8 << 4));
	s[26] = (uint8_t)(h8 >> 4); s[27] = (uint8_t)(h8 >> 12);
	s[28] = (uint8_t)((h8 >> 20) | (h9 << 6));
	s[29] = (uint8_t)(h9 >> 2); s[30] = (uint8_t)(h9 >> 10); s[31] = (uint8_t)(h9 >> 18);
}

static void fe_mul(fe h, const fe f, const fe g)
{
	int32_t f0 = f[0], f1 = f[1], f2 = f[2], f3 = f[3], f4 = f[4];
	int32_t f5 = f[5], f6 = f[6], f7 = f[7], f8 = f[8], f9 = f[9];
	int32_t g0 = g[0], g1 = g[1], g2 = g[2], g3 = g[3], g4 = g[4];
	int32_t g5 = g[5], g6 = g[6], g7 = g[7], g8 = g[8], g9 = g[9];
	/* Precompute as int64_t to avoid int32 overflow when limbs are large
	* negative values (e.g. from fe_neg on max-magnitude elements). */
	int64_t g1_19 = (int64_t)19 * g1, g2_19 = (int64_t)19 * g2;
	int64_t g3_19 = (int64_t)19 * g3, g4_19 = (int64_t)19 * g4;
	int64_t g5_19 = (int64_t)19 * g5, g6_19 = (int64_t)19 * g6;
	int64_t g7_19 = (int64_t)19 * g7, g8_19 = (int64_t)19 * g8, g9_19 = (int64_t)19 * g9;
	int64_t f1_2 = (int64_t)2 * f1, f3_2 = (int64_t)2 * f3, f5_2 = (int64_t)2 * f5;
	int64_t f7_2 = (int64_t)2 * f7, f9_2 = (int64_t)2 * f9;
	int64_t h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, c;

	h0 = (int64_t)f0*g0 + (int64_t)f1_2*g9_19 + (int64_t)f2*g8_19 + (int64_t)f3_2*g7_19 + (int64_t)f4*g6_19
		+ (int64_t)f5_2*g5_19 + (int64_t)f6*g4_19 + (int64_t)f7_2*g3_19 + (int64_t)f8*g2_19 + (int64_t)f9_2*g1_19;
	h1 = (int64_t)f0*g1 + (int64_t)f1*g0 + (int64_t)f2*g9_19 + (int64_t)f3*g8_19 + (int64_t)f4*g7_19
		+ (int64_t)f5*g6_19 + (int64_t)f6*g5_19 + (int64_t)f7*g4_19 + (int64_t)f8*g3_19 + (int64_t)f9*g2_19;
	h2 = (int64_t)f0*g2 + (int64_t)f1_2*g1 + (int64_t)f2*g0 + (int64_t)f3_2*g9_19 + (int64_t)f4*g8_19
		+ (int64_t)f5_2*g7_19 + (int64_t)f6*g6_19 + (int64_t)f7_2*g5_19 + (int64_t)f8*g4_19 + (int64_t)f9_2*g3_19;
	h3 = (int64_t)f0*g3 + (int64_t)f1*g2 + (int64_t)f2*g1 + (int64_t)f3*g0 + (int64_t)f4*g9_19
		+ (int64_t)f5*g8_19 + (int64_t)f6*g7_19 + (int64_t)f7*g6_19 + (int64_t)f8*g5_19 + (int64_t)f9*g4_19;
	h4 = (int64_t)f0*g4 + (int64_t)f1_2*g3 + (int64_t)f2*g2 + (int64_t)f3_2*g1 + (int64_t)f4*g0
		+ (int64_t)f5_2*g9_19 + (int64_t)f6*g8_19 + (int64_t)f7_2*g7_19 + (int64_t)f8*g6_19 + (int64_t)f9_2*g5_19;
	h5 = (int64_t)f0*g5 + (int64_t)f1*g4 + (int64_t)f2*g3 + (int64_t)f3*g2 + (int64_t)f4*g1
		+ (int64_t)f5*g0 + (int64_t)f6*g9_19 + (int64_t)f7*g8_19 + (int64_t)f8*g7_19 + (int64_t)f9*g6_19;
	h6 = (int64_t)f0*g6 + (int64_t)f1_2*g5 + (int64_t)f2*g4 + (int64_t)f3_2*g3 + (int64_t)f4*g2
		+ (int64_t)f5_2*g1 + (int64_t)f6*g0 + (int64_t)f7_2*g9_19 + (int64_t)f8*g8_19 + (int64_t)f9_2*g7_19;
	h7 = (int64_t)f0*g7 + (int64_t)f1*g6 + (int64_t)f2*g5 + (int64_t)f3*g4 + (int64_t)f4*g3
		+ (int64_t)f5*g2 + (int64_t)f6*g1 + (int64_t)f7*g0 + (int64_t)f8*g9_19 + (int64_t)f9*g8_19;
	h8 = (int64_t)f0*g8 + (int64_t)f1_2*g7 + (int64_t)f2*g6 + (int64_t)f3_2*g5 + (int64_t)f4*g4
		+ (int64_t)f5_2*g3 + (int64_t)f6*g2 + (int64_t)f7_2*g1 + (int64_t)f8*g0 + (int64_t)f9_2*g9_19;
	h9 = (int64_t)f0*g9 + (int64_t)f1*g8 + (int64_t)f2*g7 + (int64_t)f3*g6 + (int64_t)f4*g5
		+ (int64_t)f5*g4 + (int64_t)f6*g3 + (int64_t)f7*g2 + (int64_t)f8*g1 + (int64_t)f9*g0;

	/*
	* Unsigned carry chain: c = limb >> width; limb &= mask; next += c.
	* This keeps all output limbs in [0, 2^width), which is required by
	* fe_tobytes (direct bit-packing without further normalisation).
	*/
#define C26(a,b) { int64_t _c=(a)>>26; (a)&=0x3ffffffLL; (b)+=_c; }
#define C25(a,b) { int64_t _c=(a)>>25; (a)&=0x1ffffffLL; (b)+=_c; }
	C26(h0, h1); C25(h1, h2); C26(h2, h3); C25(h3, h4);
	C26(h4, h5); C25(h5, h6); C26(h6, h7); C25(h7, h8);
	C26(h8, h9); c = h9 >> 25; h9 &= 0x1ffffffLL; h0 += c * 19;
	C26(h0, h1);
#undef C26
#undef C25

	h[0] = (int32_t)h0; h[1] = (int32_t)h1; h[2] = (int32_t)h2; h[3] = (int32_t)h3; h[4] = (int32_t)h4;
	h[5] = (int32_t)h5; h[6] = (int32_t)h6; h[7] = (int32_t)h7; h[8] = (int32_t)h8; h[9] = (int32_t)h9;
}

static void fe_sq(fe h, const fe f) { fe_mul(h, f, f); }

static void fe_invert(fe out, const fe z)
{
	fe t0, t1, t2, t3;
	int i;
	fe_sq(t0, z);                                    /* t0 = z^2            */
	fe_sq(t1, t0); fe_sq(t1, t1); fe_mul(t1, z, t1);/* t1 = z^9            */
	fe_mul(t3, t0, t1);                              /* t3 = z^11  (SAVED)  */
	fe_sq(t0, t3);                                   /* t0 = z^22           */
	fe_mul(t0, t1, t0);                              /* t0 = z^31           */
	fe_sq(t1, t0);
	for (i = 1; i<5; i++) fe_sq(t1, t1);               /* t1 = z^(2^10-2^5)  */
	fe_mul(t0, t1, t0);                              /* t0 = z^(2^10-1)     */
	fe_sq(t1, t0);
	for (i = 1; i<10; i++) fe_sq(t1, t1);               /* t1 = z^(2^20-2^10) */
	fe_mul(t1, t1, t0);                              /* t1 = z^(2^20-1)     */
	fe_sq(t2, t1);
	for (i = 1; i<20; i++) fe_sq(t2, t2);               /* t2 = z^(2^40-2^20) */
	fe_mul(t1, t2, t1);                              /* t1 = z^(2^40-1)     */
	fe_sq(t1, t1);
	for (i = 1; i<10; i++) fe_sq(t1, t1);               /* t1 = z^(2^50-2^10) */
	fe_mul(t0, t1, t0);                              /* t0 = z^(2^50-1)     */
	fe_sq(t1, t0);
	for (i = 1; i<50; i++) fe_sq(t1, t1);               /* t1 = z^(2^100-2^50)*/
	fe_mul(t1, t1, t0);                              /* t1 = z^(2^100-1)    */
	fe_sq(t2, t1);
	for (i = 1; i<100; i++) fe_sq(t2, t2);              /* t2 = z^(2^200-2^100)*/
	fe_mul(t1, t2, t1);                              /* t1 = z^(2^200-1)    */
	fe_sq(t1, t1);
	for (i = 1; i<50; i++) fe_sq(t1, t1);               /* t1 = z^(2^250-2^50)*/
	fe_mul(t0, t1, t0);                              /* t0 = z^(2^250-1)    */
	fe_sq(t1, t0);
	for (i = 1; i<5; i++) fe_sq(t1, t1);               /* t1 = z^(2^255-32)  */
	fe_mul(out, t1, t3);                             /* out= z^(2^255-32+11)*/
													 /*    = z^(2^255-21)   */
													 /*    = z^(p-2)        */
}

/* z^((p-5)/8) used in square root */
static void fe_pow22523(fe out, const fe z)
{
	fe t0, t1, t2;
	int i;
	fe_sq(t0, z);
	fe_sq(t1, t0); fe_sq(t1, t1); fe_mul(t1, z, t1); /* t1 = z^9            */
	fe_mul(t0, t0, t1);                               /* t0 = z^11           */
	fe_sq(t0, t0);
	fe_mul(t0, t1, t0);                               /* t0 = z^31           */
	fe_sq(t1, t0);
	for (i = 1; i<5; i++) fe_sq(t1, t1);
	fe_mul(t0, t1, t0);                               /* t0 = z^(2^10-1)     */
	fe_sq(t1, t0);
	for (i = 1; i<10; i++) fe_sq(t1, t1);
	fe_mul(t1, t1, t0);                               /* t1 = z^(2^20-1)     */
	fe_sq(t2, t1);
	for (i = 1; i<20; i++) fe_sq(t2, t2);
	fe_mul(t1, t2, t1);                               /* t1 = z^(2^40-1)     */
	fe_sq(t1, t1);
	for (i = 1; i<10; i++) fe_sq(t1, t1);
	fe_mul(t0, t1, t0);                               /* t0 = z^(2^50-1)     */
	fe_sq(t1, t0);
	for (i = 1; i<50; i++) fe_sq(t1, t1);
	fe_mul(t1, t1, t0);                               /* t1 = z^(2^100-1)    */
	fe_sq(t2, t1);
	for (i = 1; i<100; i++) fe_sq(t2, t2);
	fe_mul(t1, t2, t1);                               /* t1 = z^(2^200-1)    */
	fe_sq(t1, t1);
	for (i = 1; i<50; i++) fe_sq(t1, t1);
	fe_mul(t0, t1, t0);                               /* t0 = z^(2^250-1)    */
	fe_sq(t0, t0);
	fe_sq(t0, t0);                                    /* t0 = z^(2^252-4)    */
	fe_mul(out, t0, z);                               /* out= z^(2^252-3)    */
													  /*    = z^((p-5)/8)    */
}

/* =========================================================================
* Twisted Edwards point arithmetic
* Extended coordinates (X:Y:Z:T), x=X/Z, y=Y/Z, xy=T/Z
* ========================================================================= */

typedef struct { fe X, Y, Z, T; } GeP3;

/* 2*d constant */
static const fe D2 = {
	-21827239,-5839606,-30745221,13898782,229458,15978800,-12551817,-6495438,29715968,9444199
};

/* sqrt(-1) mod p */
static const fe SQRTM1 = {
	-32595792,-7943725,9377950,3500415,12389472,-272473,-25146209,-2005654,326686,11406482
};

/* d constant (used in point decode check) */
static const fe D1 = {
	-10913610,13857413,-15372611,6949391,114729,-8787816,-6275908,-3247719,-18696448,-12055116
};

static void ge_p3_0(GeP3 *p)
{
	fe_0(p->X); fe_1(p->Y); fe_1(p->Z); fe_0(p->T);
}

/* Decode compressed point; negate X for verification equation.
* Returns 0 on success, -1 on invalid encoding. */
static int ge_frombytes_negate_vartime(GeP3 *h, const uint8_t *s)
{
	fe u, v, vxx, check;
	uint8_t s2[32];
	int     sign, nonzero, i;
	uint8_t chk[32];

	memcpy(s2, s, 32);
	sign = s2[31] >> 7;
	s2[31] &= 0x7f;

	fe_frombytes(h->Y, s2);
	fe_1(h->Z);

	/* u = y^2 - 1,  v = d*y^2 + 1 */
	fe_sq(u, h->Y);
	fe_mul(v, u, D1);
	fe_sub(u, u, h->Z);
	fe_add(v, v, h->Z);

	/* Compute x = sqrt(u/v) via u*v^3*(u*v^7)^((p-5)/8) */
	{
		fe v3, uv7, rcp;
		fe_sq(v3, v);
		fe_mul(v3, v3, v);             /* v^3 */
		fe_sq(uv7, v3);
		fe_mul(uv7, uv7, v);           /* v^7 */
		fe_mul(uv7, uv7, u);           /* u*v^7 */
		fe_pow22523(rcp, uv7);         /* (u*v^7)^((p-5)/8) */
		fe_mul(h->X, u, v3);
		fe_mul(h->X, h->X, rcp);
	}

	/* Check: v*x^2 == u? */
	fe_sq(vxx, h->X);
	fe_mul(vxx, vxx, v);
	fe_sub(check, vxx, u);
	fe_tobytes(chk, check);
	nonzero = 0;
	for (i = 0; i < 32; i++) nonzero |= chk[i];

	if (nonzero) {
		/* Try x * sqrt(-1) */
		fe_mul(h->X, h->X, SQRTM1);
		fe_sq(vxx, h->X);
		fe_mul(vxx, vxx, v);
		fe_sub(check, vxx, u);
		fe_tobytes(chk, check);
		nonzero = 0;
		for (i = 0; i < 32; i++) nonzero |= chk[i];
		if (nonzero) return -1;
	}

	/* Fix sign then negate (for verification: [S]B + [h](-A) == R) */
	{
		uint8_t xb[32];
		fe_tobytes(xb, h->X);
		if ((xb[0] & 1) == (uint8_t)sign) fe_neg(h->X, h->X);
	}
	fe_mul(h->T, h->X, h->Y);
	return 0;
}

static void ge_p3_tobytes(uint8_t *s, const GeP3 *h)
{
	fe recip, x, y;
	uint8_t xb[32];
	fe_invert(recip, h->Z);
	fe_mul(x, h->X, recip);
	fe_mul(y, h->Y, recip);
	fe_tobytes(s, y);
	fe_tobytes(xb, x);
	s[31] ^= (xb[0] & 1) << 7;
}

/* p3 + p3 -> p3 (complete unified addition) */
static void ge_add(GeP3 *r, const GeP3 *p, const GeP3 *q)
{
	fe A, B, C, Dv, E, F, G, H;
	fe_sub(A, p->Y, p->X);
	{ fe t; fe_sub(t, q->Y, q->X); fe_mul(A, A, t); }
	fe_add(B, p->Y, p->X);
	{ fe t; fe_add(t, q->Y, q->X); fe_mul(B, B, t); }
	fe_mul(C, p->T, q->T);
	fe_mul(C, C, D2);
	fe_mul(Dv, p->Z, q->Z);
	fe_add(Dv, Dv, Dv);
	fe_sub(E, B, A);
	fe_sub(F, Dv, C);
	fe_add(G, Dv, C);
	fe_add(H, B, A);
	fe_mul(r->X, E, F);
	fe_mul(r->Y, G, H);
	fe_mul(r->T, E, H);
	fe_mul(r->Z, F, G);
}

/* p3 doubling — twisted Edwards with a = -1, formula dbl-2008-hwcd */
static void ge_double(GeP3 *r, const GeP3 *p)
{
	fe XX, YY, ZZ2, XpY2, Hv, Ev, Gv, Fv;
	fe_sq(XX, p->X);
	fe_sq(YY, p->Y);
	fe_sq(ZZ2, p->Z); fe_add(ZZ2, ZZ2, ZZ2);
	{ fe t; fe_add(t, p->X, p->Y); fe_sq(XpY2, t); }
	fe_add(Hv, XX, YY);                    /* H_tmp = XX + YY        */
	fe_neg(Hv, Hv);                        /* H = -(XX+YY)  (a=-1)  */
	fe_sub(Ev, XpY2, XX); fe_sub(Ev, Ev, YY); /* E = XpY2-XX-YY     */
	fe_sub(Gv, YY, XX);                    /* G = YY - XX  (D+B)    */
	fe_sub(Fv, Gv, ZZ2);                   /* F = G - 2ZZ           */
	fe_mul(r->X, Ev, Fv);
	fe_mul(r->Y, Gv, Hv);
	fe_mul(r->T, Ev, Hv);
	fe_mul(r->Z, Fv, Gv);
}

/* Variable-time scalar multiplication: r = s * base (s = 32 bytes LE) */
static void ge_scalarmult(GeP3 *r, const uint8_t *s, const GeP3 *base)
{
	GeP3 acc, tmp;
	int  i;
	ge_p3_0(&acc);
	for (i = 255; i >= 0; i--) {
		ge_double(&acc, &acc);
		if ((s[i >> 3] >> (i & 7)) & 1) {
			ge_add(&tmp, &acc, base);
			fe_cpy(acc.X, tmp.X); fe_cpy(acc.Y, tmp.Y);
			fe_cpy(acc.Z, tmp.Z); fe_cpy(acc.T, tmp.T);
		}
	}
	fe_cpy(r->X, acc.X); fe_cpy(r->Y, acc.Y);
	fe_cpy(r->Z, acc.Z); fe_cpy(r->T, acc.T);
}

/* =========================================================================
* Ed25519 base point in extended coordinates
* ========================================================================= */

static const GeP3 ED25519_B = {
	/* X(B) — unsigned limbs from B.x = 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a */
	{ 52811034, 25909283, 16144682, 17082669, 27570973, 30858332, 40966398, 8378388, 20764389, 8758491 },
	/* Y(B) = 4/5 mod p — unsigned limbs */
	{ 40265304, 26843545, 13421772, 20132659, 26843545, 6710886, 53687091, 13421772, 40265318, 26843545 },
	/* Z(B) = 1 */
	{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
	/* T(B) = X*Y mod p — unsigned limbs */
	{ 28827043, 27438313, 39759291, 244362, 8635006, 11264893, 19351346, 13413597, 16611511, 27139452 }
};

/* =========================================================================
* Scalar reduction mod l (group order of Ed25519)
* l = 2^252 + 27742317777372353535851937790883648493
*
* Input: s[0..63] — a 64-byte value (output of SHA-512).
* Output: s[0..31] — s reduced mod l, s[32..63] zeroed.
*
* Uses the ref10 carry-chain algorithm with 21-bit limbs.
* ========================================================================= */
static void sc_reduce(uint8_t s[64])
{
	int64_t s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11;
	int64_t s12, s13, s14, s15, s16, s17, s18, s19, s20, s21, s22, s23;
	int64_t carry[24];

#define LOAD3(b,i) ((int64_t)((uint32_t)s[(i)] | ((uint32_t)s[(i)+1]<<8) | ((uint32_t)s[(i)+2]<<16)))
#define LOAD4(b,i) ((int64_t)((uint32_t)s[(i)] | ((uint32_t)s[(i)+1]<<8) | ((uint32_t)s[(i)+2]<<16) | ((uint32_t)s[(i)+3]<<24)))

	s0 = 2097151LL & LOAD3(s, 0);
	s1 = 2097151LL & (LOAD4(s, 2) >> 5);
	s2 = 2097151LL & (LOAD3(s, 5) >> 2);
	s3 = 2097151LL & (LOAD4(s, 7) >> 7);
	s4 = 2097151LL & (LOAD4(s, 10) >> 4);
	s5 = 2097151LL & (LOAD3(s, 13) >> 1);
	s6 = 2097151LL & (LOAD4(s, 15) >> 6);
	s7 = 2097151LL & (LOAD3(s, 18) >> 3);
	s8 = 2097151LL & LOAD3(s, 21);
	s9 = 2097151LL & (LOAD4(s, 23) >> 5);
	s10 = 2097151LL & (LOAD3(s, 26) >> 2);
	s11 = 2097151LL & (LOAD4(s, 28) >> 7);
	s12 = 2097151LL & (LOAD4(s, 31) >> 4);
	s13 = 2097151LL & (LOAD3(s, 34) >> 1);
	s14 = 2097151LL & (LOAD4(s, 36) >> 6);
	s15 = 2097151LL & (LOAD3(s, 39) >> 3);
	s16 = 2097151LL & LOAD3(s, 42);
	s17 = 2097151LL & (LOAD4(s, 44) >> 5);
	s18 = 2097151LL & (LOAD3(s, 47) >> 2);
	s19 = 2097151LL & (LOAD4(s, 49) >> 7);
	s20 = 2097151LL & (LOAD4(s, 52) >> 4);
	s21 = 2097151LL & (LOAD3(s, 55) >> 1);
	s22 = 2097151LL & (LOAD4(s, 57) >> 6);
	s23 = (LOAD4(s, 60) >> 3);
#undef LOAD3
#undef LOAD4

	/* Reduce high limbs using l's representation:
	* l = 2^252 + 27742317777372353535851937790883648493
	* mu coefficients from ref10: 666643, 470296, 654183, -997805, 136657, -683901 */
	s11 += s23 * 666643LL; s12 += s23 * 470296LL; s13 += s23 * 654183LL;
	s14 -= s23 * 997805LL; s15 += s23 * 136657LL; s16 -= s23 * 683901LL; s23 = 0;
	s10 += s22 * 666643LL; s11 += s22 * 470296LL; s12 += s22 * 654183LL;
	s13 -= s22 * 997805LL; s14 += s22 * 136657LL; s15 -= s22 * 683901LL; s22 = 0;
	s9 += s21 * 666643LL; s10 += s21 * 470296LL; s11 += s21 * 654183LL;
	s12 -= s21 * 997805LL; s13 += s21 * 136657LL; s14 -= s21 * 683901LL; s21 = 0;
	s8 += s20 * 666643LL; s9 += s20 * 470296LL; s10 += s20 * 654183LL;
	s11 -= s20 * 997805LL; s12 += s20 * 136657LL; s13 -= s20 * 683901LL; s20 = 0;
	s7 += s19 * 666643LL; s8 += s19 * 470296LL; s9 += s19 * 654183LL;
	s10 -= s19 * 997805LL; s11 += s19 * 136657LL; s12 -= s19 * 683901LL; s19 = 0;
	s6 += s18 * 666643LL; s7 += s18 * 470296LL; s8 += s18 * 654183LL;
	s9 -= s18 * 997805LL; s10 += s18 * 136657LL; s11 -= s18 * 683901LL; s18 = 0;

	carry[6] = s6 >> 21; s7 += carry[6];  s6 -= carry[6] << 21;
	carry[8] = s8 >> 21; s9 += carry[8];  s8 -= carry[8] << 21;
	carry[10] = s10 >> 21; s11 += carry[10]; s10 -= carry[10] << 21;
	carry[12] = s12 >> 21; s13 += carry[12]; s12 -= carry[12] << 21;
	carry[14] = s14 >> 21; s15 += carry[14]; s14 -= carry[14] << 21;
	carry[16] = s16 >> 21; s17 += carry[16]; s16 -= carry[16] << 21;
	carry[7] = s7 >> 21; s8 += carry[7];  s7 -= carry[7] << 21;
	carry[9] = s9 >> 21; s10 += carry[9];  s9 -= carry[9] << 21;
	carry[11] = s11 >> 21; s12 += carry[11]; s11 -= carry[11] << 21;
	carry[13] = s13 >> 21; s14 += carry[13]; s13 -= carry[13] << 21;
	carry[15] = s15 >> 21; s16 += carry[15]; s15 -= carry[15] << 21;

	s5 += s17 * 666643LL; s6 += s17 * 470296LL; s7 += s17 * 654183LL;
	s8 -= s17 * 997805LL; s9 += s17 * 136657LL; s10 -= s17 * 683901LL; s17 = 0;
	s4 += s16 * 666643LL; s5 += s16 * 470296LL; s6 += s16 * 654183LL;
	s7 -= s16 * 997805LL; s8 += s16 * 136657LL; s9 -= s16 * 683901LL; s16 = 0;
	s3 += s15 * 666643LL; s4 += s15 * 470296LL; s5 += s15 * 654183LL;
	s6 -= s15 * 997805LL; s7 += s15 * 136657LL; s8 -= s15 * 683901LL; s15 = 0;
	s2 += s14 * 666643LL; s3 += s14 * 470296LL; s4 += s14 * 654183LL;
	s5 -= s14 * 997805LL; s6 += s14 * 136657LL; s7 -= s14 * 683901LL; s14 = 0;
	s1 += s13 * 666643LL; s2 += s13 * 470296LL; s3 += s13 * 654183LL;
	s4 -= s13 * 997805LL; s5 += s13 * 136657LL; s6 -= s13 * 683901LL; s13 = 0;
	s0 += s12 * 666643LL; s1 += s12 * 470296LL; s2 += s12 * 654183LL;
	s3 -= s12 * 997805LL; s4 += s12 * 136657LL; s5 -= s12 * 683901LL; s12 = 0;

	carry[0] = s0 >> 21; s1 += carry[0];  s0 -= carry[0] << 21;
	carry[2] = s2 >> 21; s3 += carry[2];  s2 -= carry[2] << 21;
	carry[4] = s4 >> 21; s5 += carry[4];  s4 -= carry[4] << 21;
	carry[6] = s6 >> 21; s7 += carry[6];  s6 -= carry[6] << 21;
	carry[8] = s8 >> 21; s9 += carry[8];  s8 -= carry[8] << 21;
	carry[10] = s10 >> 21; s11 += carry[10]; s10 -= carry[10] << 21;
	carry[1] = s1 >> 21; s2 += carry[1];  s1 -= carry[1] << 21;
	carry[3] = s3 >> 21; s4 += carry[3];  s3 -= carry[3] << 21;
	carry[5] = s5 >> 21; s6 += carry[5];  s5 -= carry[5] << 21;
	carry[7] = s7 >> 21; s8 += carry[7];  s7 -= carry[7] << 21;
	carry[9] = s9 >> 21; s10 += carry[9];  s9 -= carry[9] << 21;
	carry[11] = s11 >> 21; s12 += carry[11]; s11 -= carry[11] << 21;

	s0 += s12 * 666643LL; s1 += s12 * 470296LL; s2 += s12 * 654183LL;
	s3 -= s12 * 997805LL; s4 += s12 * 136657LL; s5 -= s12 * 683901LL; s12 = 0;

	carry[0] = s0 >> 21; s1 += carry[0]; s0 -= carry[0] << 21;
	carry[1] = s1 >> 21; s2 += carry[1]; s1 -= carry[1] << 21;
	carry[2] = s2 >> 21; s3 += carry[2]; s2 -= carry[2] << 21;
	carry[3] = s3 >> 21; s4 += carry[3]; s3 -= carry[3] << 21;
	carry[4] = s4 >> 21; s5 += carry[4]; s4 -= carry[4] << 21;
	carry[5] = s5 >> 21; s6 += carry[5]; s5 -= carry[5] << 21;
	carry[6] = s6 >> 21; s7 += carry[6]; s6 -= carry[6] << 21;
	carry[7] = s7 >> 21; s8 += carry[7]; s7 -= carry[7] << 21;
	carry[8] = s8 >> 21; s9 += carry[8]; s8 -= carry[8] << 21;
	carry[9] = s9 >> 21; s10 += carry[9]; s9 -= carry[9] << 21;
	carry[10] = s10 >> 21; s11 += carry[10]; s10 -= carry[10] << 21;
	carry[11] = s11 >> 21; s12 += carry[11]; s11 -= carry[11] << 21;

	s0 += s12 * 666643LL; s1 += s12 * 470296LL; s2 += s12 * 654183LL;
	s3 -= s12 * 997805LL; s4 += s12 * 136657LL; s5 -= s12 * 683901LL; s12 = 0;

	/* Final carry pass uses floor division (>>21, no rounding) so the packed
	* limbs represent exactly h mod l without off-by-one from the rounding. */
	carry[0] = s0 >> 21; s1 += carry[0]; s0 -= carry[0] << 21;
	carry[1] = s1 >> 21; s2 += carry[1]; s1 -= carry[1] << 21;
	carry[2] = s2 >> 21; s3 += carry[2]; s2 -= carry[2] << 21;
	carry[3] = s3 >> 21; s4 += carry[3]; s3 -= carry[3] << 21;
	carry[4] = s4 >> 21; s5 += carry[4]; s4 -= carry[4] << 21;
	carry[5] = s5 >> 21; s6 += carry[5]; s5 -= carry[5] << 21;
	carry[6] = s6 >> 21; s7 += carry[6]; s6 -= carry[6] << 21;
	carry[7] = s7 >> 21; s8 += carry[7]; s7 -= carry[7] << 21;
	carry[8] = s8 >> 21; s9 += carry[8]; s8 -= carry[8] << 21;
	carry[9] = s9 >> 21; s10 += carry[9]; s9 -= carry[9] << 21;
	carry[10] = s10 >> 21; s11 += carry[10]; s10 -= carry[10] << 21;

	s[0] = (uint8_t)(s0); s[1] = (uint8_t)(s0 >> 8);
	s[2] = (uint8_t)((s0 >> 16) | (s1 << 5)); s[3] = (uint8_t)(s1 >> 3);
	s[4] = (uint8_t)(s1 >> 11); s[5] = (uint8_t)((s1 >> 19) | (s2 << 2));
	s[6] = (uint8_t)(s2 >> 6); s[7] = (uint8_t)((s2 >> 14) | (s3 << 7));
	s[8] = (uint8_t)(s3 >> 1); s[9] = (uint8_t)(s3 >> 9);
	s[10] = (uint8_t)((s3 >> 17) | (s4 << 4)); s[11] = (uint8_t)(s4 >> 4);
	s[12] = (uint8_t)(s4 >> 12); s[13] = (uint8_t)((s4 >> 20) | (s5 << 1));
	s[14] = (uint8_t)(s5 >> 7); s[15] = (uint8_t)((s5 >> 15) | (s6 << 6));
	s[16] = (uint8_t)(s6 >> 2); s[17] = (uint8_t)(s6 >> 10);
	s[18] = (uint8_t)((s6 >> 18) | (s7 << 3)); s[19] = (uint8_t)(s7 >> 5);
	s[20] = (uint8_t)(s7 >> 13); s[21] = (uint8_t)(s8);
	s[22] = (uint8_t)(s8 >> 8); s[23] = (uint8_t)((s8 >> 16) | (s9 << 5));
	s[24] = (uint8_t)(s9 >> 3); s[25] = (uint8_t)(s9 >> 11);
	s[26] = (uint8_t)((s9 >> 19) | (s10 << 2)); s[27] = (uint8_t)(s10 >> 6);
	s[28] = (uint8_t)((s10 >> 14) | (s11 << 7)); s[29] = (uint8_t)(s11 >> 1);
	s[30] = (uint8_t)(s11 >> 9); s[31] = (uint8_t)(s11 >> 17);
	/* zero out the upper 32 bytes */
	memset(s + 32, 0, 32);
	(void)s12;
}

/* =========================================================================
* ed25519_verify
* ========================================================================= */

int ed25519_verify(const uint8_t sig[ED25519_SIGNATURE_LEN],
	const uint8_t *msg, size_t msg_len,
	const uint8_t pub[ED25519_PUBLIC_KEY_LEN])
{
	Sha512Ctx ctx;
	uint8_t   h[64];         /* SHA-512(R || A || M) — full 64 bytes */
	uint8_t   rcheck[32];
	GeP3      A;             /* decoded (and negated) public key */
	GeP3      sB;            /* [S]B */
	GeP3      hA;            /* [h](-A) */
	GeP3      R;             /* [S]B + [h](-A) */
	uint8_t   S[32];         /* copy of sig[32..63] */
	uint8_t   diff;
	int       i;

	/* S must have top 3 bits clear (S < 2^253) */
	if (sig[63] & 0xe0) return -1;

	/* Decode and negate public key */
	if (ge_frombytes_negate_vartime(&A, pub) != 0) return -1;

	/* h = SHA-512(R || A || M) */
	sha512_init(&ctx);
	sha512_update(&ctx, sig, 32);
	sha512_update(&ctx, pub, 32);
	sha512_update(&ctx, msg, msg_len);
	sha512_final(&ctx, h);

	/* Reduce h mod l in-place (sc_reduce works on 64-byte buffer) */
	sc_reduce(h);   /* result in h[0..31], h[32..63] zeroed */

					/* Copy S from signature */
	memcpy(S, sig + 32, 32);

	/* [S]B */
	ge_scalarmult(&sB, S, &ED25519_B);

	/* [h](-A) */
	ge_scalarmult(&hA, h, &A);

	/* R = [S]B + [h](-A) */
	ge_add(&R, &sB, &hA);

	/* Compress and compare with sig[0..31] */
	ge_p3_tobytes(rcheck, &R);

	diff = 0;
	for (i = 0; i < 32; i++) diff |= rcheck[i] ^ sig[i];
	return (diff == 0) ? 0 : -1;
}