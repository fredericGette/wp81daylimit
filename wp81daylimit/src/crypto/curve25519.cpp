/*
* curve25519.c  -  X25519 Diffie-Hellman (RFC 7748)
*
* Implements scalar multiplication on Curve25519 using the Montgomery ladder
* over a 10-limb radix-2^25.5 representation of GF(2^255-19).
*
* Field representation
* --------------------
* A field element is stored as ten signed 32-bit limbs with alternating
* radix 2^26 / 2^25 (the "ref10" layout):
*
*   limb  BASE  WIDTH
*   h[0]    0     26    bits   0- 25
*   h[1]   26     25    bits  26- 50
*   h[2]   51     26    bits  51- 76
*   h[3]   77     25    bits  77-101
*   h[4]  102     26    bits 102-127
*   h[5]  128     25    bits 128-152
*   h[6]  153     26    bits 153-178
*   h[7]  179     25    bits 179-203
*   h[8]  204     26    bits 204-229
*   h[9]  230     25    bits 230-254
*
* Every cross-product in fe_mul is int32_t × int32_t → int64_t, which maps
* to a single SMULL/SMLAL instruction on ARM32.
*
* No heap allocation.  No external dependencies.
*/

#include "curve25519.h"
#include <string.h>

/* =========================================================================
* Internal types and constant-time helpers
* ====================================================================== */

typedef int32_t fe[10];

/*
* mask32 — constant-time bit mask
*   b == 1  →  0xFFFFFFFF
*   b == 0  →  0x00000000
* b must be 0 or 1.
*/
static uint32_t mask32(int b)
{
	return (uint32_t)(-(int32_t)b);
}

/*
* fe_cswap — constant-time conditional swap of two field elements.
* Swaps f and g when b == 1; leaves them unchanged when b == 0.
*/
static void fe_cswap(fe f, fe g, int b)
{
	uint32_t m = mask32(b);
	int i;
	for (i = 0; i < 10; i++) {
		uint32_t t = ((uint32_t)f[i] ^ (uint32_t)g[i]) & m;
		f[i] ^= (int32_t)t;
		g[i] ^= (int32_t)t;
	}
}

/* =========================================================================
* Field arithmetic in GF(2^255-19)
* ====================================================================== */

static void fe_0(fe h) { memset(h, 0, sizeof(fe)); }
static void fe_1(fe h) { fe_0(h); h[0] = 1; }
static void fe_copy(fe h, const fe f) { memcpy(h, f, sizeof(fe)); }

static void fe_add(fe h, const fe f, const fe g)
{
	int i;
	for (i = 0; i < 10; i++) h[i] = f[i] + g[i];
}

static void fe_sub(fe h, const fe f, const fe g)
{
	int i;
	for (i = 0; i < 10; i++) h[i] = f[i] - g[i];
}

/*
* fe_mul — h = f * g  mod  2^255-19
*
* Schoolbook 10×10 product.  High limbs are reduced via multiplication by 19
* (since 2^255 ≡ 19 mod p).  All intermediate values stay in int64_t.
* Two carry-propagation passes give fully-reduced limbs.
*
* On ARM32, GCC/Clang lower each (int64_t)a*b accumulation to SMULL/SMLAL.
*/
static void fe_mul(fe h, const fe f, const fe g)
{
	const int32_t f0 = f[0], f1 = f[1], f2 = f[2], f3 = f[3], f4 = f[4];
	const int32_t f5 = f[5], f6 = f[6], f7 = f[7], f8 = f[8], f9 = f[9];
	const int32_t g0 = g[0], g1 = g[1], g2 = g[2], g3 = g[3], g4 = g[4];
	const int32_t g5 = g[5], g6 = g[6], g7 = g[7], g8 = g[8], g9 = g[9];

	/* gi_19 = 19*gi  (applied when a limb index wraps mod 10) */
	const int32_t g1_19 = 19 * g1, g2_19 = 19 * g2, g3_19 = 19 * g3, g4_19 = 19 * g4;
	const int32_t g5_19 = 19 * g5, g6_19 = 19 * g6, g7_19 = 19 * g7, g8_19 = 19 * g8;
	const int32_t g9_19 = 19 * g9;

	/* fi_2: double odd-indexed f limbs to absorb the 2× symmetry factor */
	const int32_t f1_2 = 2 * f1, f3_2 = 2 * f3, f5_2 = 2 * f5, f7_2 = 2 * f7, f9_2 = 2 * f9;

	int64_t h0, h1, h2, h3, h4, h5, h6, h7, h8, h9;

	h0 = (int64_t)f0*g0 + (int64_t)f1_2*g9_19 + (int64_t)f2*g8_19
		+ (int64_t)f3_2*g7_19 + (int64_t)f4*g6_19 + (int64_t)f5_2*g5_19
		+ (int64_t)f6*g4_19 + (int64_t)f7_2*g3_19 + (int64_t)f8*g2_19
		+ (int64_t)f9_2*g1_19;

	h1 = (int64_t)f0*g1 + (int64_t)f1*g0 + (int64_t)f2*g9_19
		+ (int64_t)f3*g8_19 + (int64_t)f4*g7_19 + (int64_t)f5*g6_19
		+ (int64_t)f6*g5_19 + (int64_t)f7*g4_19 + (int64_t)f8*g3_19
		+ (int64_t)f9*g2_19;

	h2 = (int64_t)f0*g2 + (int64_t)f1_2*g1 + (int64_t)f2*g0
		+ (int64_t)f3_2*g9_19 + (int64_t)f4*g8_19 + (int64_t)f5_2*g7_19
		+ (int64_t)f6*g6_19 + (int64_t)f7_2*g5_19 + (int64_t)f8*g4_19
		+ (int64_t)f9_2*g3_19;

	h3 = (int64_t)f0*g3 + (int64_t)f1*g2 + (int64_t)f2*g1
		+ (int64_t)f3*g0 + (int64_t)f4*g9_19 + (int64_t)f5*g8_19
		+ (int64_t)f6*g7_19 + (int64_t)f7*g6_19 + (int64_t)f8*g5_19
		+ (int64_t)f9*g4_19;

	h4 = (int64_t)f0*g4 + (int64_t)f1_2*g3 + (int64_t)f2*g2
		+ (int64_t)f3_2*g1 + (int64_t)f4*g0 + (int64_t)f5_2*g9_19
		+ (int64_t)f6*g8_19 + (int64_t)f7_2*g7_19 + (int64_t)f8*g6_19
		+ (int64_t)f9_2*g5_19;

	h5 = (int64_t)f0*g5 + (int64_t)f1*g4 + (int64_t)f2*g3
		+ (int64_t)f3*g2 + (int64_t)f4*g1 + (int64_t)f5*g0
		+ (int64_t)f6*g9_19 + (int64_t)f7*g8_19 + (int64_t)f8*g7_19
		+ (int64_t)f9*g6_19;

	h6 = (int64_t)f0*g6 + (int64_t)f1_2*g5 + (int64_t)f2*g4
		+ (int64_t)f3_2*g3 + (int64_t)f4*g2 + (int64_t)f5_2*g1
		+ (int64_t)f6*g0 + (int64_t)f7_2*g9_19 + (int64_t)f8*g8_19
		+ (int64_t)f9_2*g7_19;

	h7 = (int64_t)f0*g7 + (int64_t)f1*g6 + (int64_t)f2*g5
		+ (int64_t)f3*g4 + (int64_t)f4*g3 + (int64_t)f5*g2
		+ (int64_t)f6*g1 + (int64_t)f7*g0 + (int64_t)f8*g9_19
		+ (int64_t)f9*g8_19;

	h8 = (int64_t)f0*g8 + (int64_t)f1_2*g7 + (int64_t)f2*g6
		+ (int64_t)f3_2*g5 + (int64_t)f4*g4 + (int64_t)f5_2*g3
		+ (int64_t)f6*g2 + (int64_t)f7_2*g1 + (int64_t)f8*g0
		+ (int64_t)f9_2*g9_19;

	h9 = (int64_t)f0*g9 + (int64_t)f1*g8 + (int64_t)f2*g7
		+ (int64_t)f3*g6 + (int64_t)f4*g5 + (int64_t)f5*g4
		+ (int64_t)f6*g3 + (int64_t)f7*g2 + (int64_t)f8*g1
		+ (int64_t)f9*g0;

	/* ---- two-pass carry propagation ---------------------------------- */
	/*
	* Even limbs are 26-bit slots (bias 2^25 before right-shifting 26).
	* Odd  limbs are 25-bit slots (bias 2^24 before right-shifting 25).
	* After the first pass h9's carry wraps back via ×19.
	* One additional C26(0,1) cleans any residual overflow in h0.
	*/
	{
		int64_t c;
#define C26(i,j)  c=(h##i+(int64_t)(1<<25))>>26; h##j+=c; h##i-=c<<26
#define C25(i,j)  c=(h##i+(int64_t)(1<<24))>>25; h##j+=c; h##i-=c<<25

		C26(0, 1); C25(1, 2); C26(2, 3); C25(3, 4);
		C26(4, 5); C25(5, 6); C26(6, 7); C25(7, 8);
		C26(8, 9);
		c = (h9 + (int64_t)(1 << 24)) >> 25; h0 += c * 19; h9 -= c << 25;
		C26(0, 1);

#undef C26
#undef C25
	}

	h[0] = (int32_t)h0; h[1] = (int32_t)h1; h[2] = (int32_t)h2;
	h[3] = (int32_t)h3; h[4] = (int32_t)h4; h[5] = (int32_t)h5;
	h[6] = (int32_t)h6; h[7] = (int32_t)h7; h[8] = (int32_t)h8;
	h[9] = (int32_t)h9;
}

/*
* fe_sq — h = f^2
* Delegates to fe_mul.  A hand-unrolled squaring (exploiting the 2*fi*fj
* symmetry) saves ~45 multiplies per call and is a worthwhile optimisation
* if fe_sq in fe_invert becomes a bottleneck.
*/
static void fe_sq(fe h, const fe f)
{
	fe_mul(h, f, f);
}

/*
* fe_mul121666 — h = f * 121666
*
* 121666 = (486662 - 2) / 4 is the A24 constant used in the Montgomery
* ladder formula.  Implemented as 10 scalar multiplications with a single
* carry-propagation pass.
*/
static void fe_mul121666(fe h, const fe f)
{
	int64_t h0 = (int64_t)f[0] * 121666, h1 = (int64_t)f[1] * 121666;
	int64_t h2 = (int64_t)f[2] * 121666, h3 = (int64_t)f[3] * 121666;
	int64_t h4 = (int64_t)f[4] * 121666, h5 = (int64_t)f[5] * 121666;
	int64_t h6 = (int64_t)f[6] * 121666, h7 = (int64_t)f[7] * 121666;
	int64_t h8 = (int64_t)f[8] * 121666, h9 = (int64_t)f[9] * 121666;
	int64_t c;

	c = h9 >> 25; h0 += c * 19; h9 -= c << 25;
	c = h0 >> 26; h1 += c;    h0 -= c << 26;
	c = h1 >> 25; h2 += c;    h1 -= c << 25;
	c = h2 >> 26; h3 += c;    h2 -= c << 26;
	c = h3 >> 25; h4 += c;    h3 -= c << 25;
	c = h4 >> 26; h5 += c;    h4 -= c << 26;
	c = h5 >> 25; h6 += c;    h5 -= c << 25;
	c = h6 >> 26; h7 += c;    h6 -= c << 26;
	c = h7 >> 25; h8 += c;    h7 -= c << 25;
	c = h8 >> 26; h9 += c;    h8 -= c << 26;

	h[0] = (int32_t)h0; h[1] = (int32_t)h1; h[2] = (int32_t)h2;
	h[3] = (int32_t)h3; h[4] = (int32_t)h4; h[5] = (int32_t)h5;
	h[6] = (int32_t)h6; h[7] = (int32_t)h7; h[8] = (int32_t)h8;
	h[9] = (int32_t)h9;
}

/*
* fe_invert — h = f^{-1} mod 2^255-19
*
* Uses the identity  f^{-1} = f^{2^255-21}  via the standard addition chain
* from the Ed25519 reference implementation.
* Cost: 254 squarings + 11 multiplications.
*/
static void fe_invert(fe out, const fe z)
{
	fe t0, t1, t2, t3;
	int i;

	fe_sq(t0, z);                              /* t0 = z^2              */
	fe_sq(t1, t0); fe_sq(t1, t1);             /* t1 = z^8              */
	fe_mul(t1, z, t1);                         /* t1 = z^9              */
	fe_mul(t0, t0, t1);                        /* t0 = z^11             */
	fe_sq(t2, t0);                             /* t2 = z^22             */
	fe_mul(t1, t1, t2);                        /* t1 = z^(2^5-1)        */

	fe_sq(t2, t1);
	for (i = 1; i<5; i++) fe_sq(t2, t2);       /* t2 = z^(2^10-2^5)     */
	fe_mul(t1, t2, t1);                        /* t1 = z^(2^10-1)       */

	fe_sq(t2, t1);
	for (i = 1; i<10; i++) fe_sq(t2, t2);       /* t2 = z^(2^20-2^10)    */
	fe_mul(t2, t2, t1);                        /* t2 = z^(2^20-1)       */

	fe_sq(t3, t2);
	for (i = 1; i<20; i++) fe_sq(t3, t3);       /* t3 = z^(2^40-2^20)    */
	fe_mul(t2, t3, t2);                        /* t2 = z^(2^40-1)       */

	fe_sq(t2, t2);
	for (i = 1; i<10; i++) fe_sq(t2, t2);       /* t2 = z^(2^50-2^10)    */
	fe_mul(t1, t2, t1);                        /* t1 = z^(2^50-1)       */

	fe_sq(t2, t1);
	for (i = 1; i<50; i++) fe_sq(t2, t2);       /* t2 = z^(2^100-2^50)   */
	fe_mul(t2, t2, t1);                        /* t2 = z^(2^100-1)      */

	fe_sq(t3, t2);
	for (i = 1; i<100; i++) fe_sq(t3, t3);      /* t3 = z^(2^200-2^100)  */
	fe_mul(t2, t3, t2);                        /* t2 = z^(2^200-1)      */

	fe_sq(t2, t2);
	for (i = 1; i<50; i++) fe_sq(t2, t2);       /* t2 = z^(2^250-2^50)   */
	fe_mul(t1, t2, t1);                        /* t1 = z^(2^250-1)      */

	fe_sq(t1, t1);
	fe_sq(t1, t1);
	fe_sq(t1, t1);
	fe_sq(t1, t1);
	fe_sq(t1, t1);                             /* t1 = z^(2^255-32)     */
	fe_mul(out, t1, t0);                       /* out = z^(2^255-21)    */
}

/* =========================================================================
* Serialisation
* ====================================================================== */

/*
* fe_frombytes — decode 32 little-endian bytes into a field element.
*
* The input is first loaded into eight 32-bit words w[0..7] (LE), then
* split into ten limbs at the bit boundaries listed in the table at the top
* of the file.  Bit 255 (the MSB of byte 31) is masked per RFC 7748 §5.
*
* Shift derivation:
*   For limb h[i] starting at bit BASE[i]:
*     word j          = BASE[i] / 32
*     shift_right     = BASE[i] % 32          (bits to discard from w[j])
*     shift_left      = 32 - shift_right      (bits to take from w[j+1])
*   If WIDTH[i] > (32 - shift_right), the limb spans two words.
*
*   h[0]  BASE=  0: w[0]>>0               (no overflow)
*   h[1]  BASE= 26: w[0]>>26 | w[1]<< 6
*   h[2]  BASE= 51: w[1]>>19 | w[2]<<13
*   h[3]  BASE= 77: w[2]>>13 | w[3]<<19
*   h[4]  BASE=102: w[3]>>6               (no overflow: 102%32=6, 32-6=26=WIDTH)
*   h[5]  BASE=128: w[4]>>0               (no overflow)
*   h[6]  BASE=153: w[4]>>25 | w[5]<< 7
*   h[7]  BASE=179: w[5]>>19 | w[6]<<13
*   h[8]  BASE=204: w[6]>>12 | w[7]<<20
*   h[9]  BASE=230: w[7]>>6               (no overflow: 230%32=6, 32-6=26 > WIDTH=25, but
*                                          h[9] is the top limb so no w[8] needed)
*/
static void fe_frombytes(fe h, const uint8_t s[32])
{
	uint32_t w[8];
	int i;

	for (i = 0; i < 8; i++)
		w[i] = (uint32_t)s[i * 4 + 0]
		| ((uint32_t)s[i * 4 + 1] << 8)
		| ((uint32_t)s[i * 4 + 2] << 16)
		| ((uint32_t)s[i * 4 + 3] << 24);

	w[7] &= 0x7fffffff;  /* mask bit 255 per RFC 7748 §5 */

	h[0] = (int32_t)(w[0] & 0x3ffffffU);
	h[1] = (int32_t)(((w[0] >> 26) | (w[1] << 6)) & 0x1ffffffU);
	h[2] = (int32_t)(((w[1] >> 19) | (w[2] << 13)) & 0x3ffffffU);
	h[3] = (int32_t)(((w[2] >> 13) | (w[3] << 19)) & 0x1ffffffU);
	h[4] = (int32_t)((w[3] >> 6) & 0x3ffffffU);
	h[5] = (int32_t)(w[4] & 0x1ffffffU);
	h[6] = (int32_t)(((w[4] >> 25) | (w[5] << 7)) & 0x3ffffffU);
	h[7] = (int32_t)(((w[5] >> 19) | (w[6] << 13)) & 0x1ffffffU);  /* >>19 / <<13 */
	h[8] = (int32_t)(((w[6] >> 12) | (w[7] << 20)) & 0x3ffffffU);  /* >>12 / <<20 */
	h[9] = (int32_t)((w[7] >> 6) & 0x1ffffffU);  /* >>6         */
}

/*
* fe_tobytes — encode a field element to 32 little-endian bytes.
*
* Performs a canonical reduction (result in [0, p-1]) before packing.
*
* The packing is the exact inverse of fe_frombytes:
*
*   w[0] =  h[0]       | h[1]<<26
*   w[1] =  h[1]>> 6   | h[2]<<19
*   w[2] =  h[2]>>13   | h[3]<<13
*   w[3] =  h[3]>>19   | h[4]<< 6
*   w[4] =  h[5]       | h[6]<<25
*   w[5] =  h[6]>> 7   | h[7]<<19
*   w[6] =  h[7]>>13   | h[8]<<12
*   w[7] =  h[8]>>20   | h[9]<< 6
*/
static void fe_tobytes(uint8_t s[32], const fe h)
{
	int32_t h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4];
	int32_t h5 = h[5], h6 = h[6], h7 = h[7], h8 = h[8], h9 = h[9];
	int32_t q, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9;
	uint32_t w[8];
	int i;

	/*
	* Compute q = floor((h + 19) / 2^255).
	* Propagating the carry of adding 19 through all limbs gives q,
	* indicating how many full copies of p sit in h.
	*/
	q = (19 * h9 + (1 << 24)) >> 25;
	q = (h0 + q) >> 26; q = (h1 + q) >> 25; q = (h2 + q) >> 26; q = (h3 + q) >> 25;
	q = (h4 + q) >> 26; q = (h5 + q) >> 25; q = (h6 + q) >> 26; q = (h7 + q) >> 25;
	q = (h8 + q) >> 26; q = (h9 + q) >> 25;

	/* Subtract q*p by adding 19*q (clears the implicit 2^255 term) */
	h0 += 19 * q;

	/* Final carry propagation to bring each limb into its canonical range */
	c0 = h0 >> 26; h1 += c0; h0 -= c0 << 26;
	c1 = h1 >> 25; h2 += c1; h1 -= c1 << 25;
	c2 = h2 >> 26; h3 += c2; h2 -= c2 << 26;
	c3 = h3 >> 25; h4 += c3; h3 -= c3 << 25;
	c4 = h4 >> 26; h5 += c4; h4 -= c4 << 26;
	c5 = h5 >> 25; h6 += c5; h5 -= c5 << 25;
	c6 = h6 >> 26; h7 += c6; h6 -= c6 << 26;
	c7 = h7 >> 25; h8 += c7; h7 -= c7 << 25;
	c8 = h8 >> 26; h9 += c8; h8 -= c8 << 26;
	c9 = h9 >> 25;         h9 -= c9 << 25;

	/* Pack limbs into eight 32-bit words (inverse of fe_frombytes) */
	w[0] = (uint32_t)h0 | ((uint32_t)h1 << 26);
	w[1] = ((uint32_t)h1 >> 6) | ((uint32_t)h2 << 19);
	w[2] = ((uint32_t)h2 >> 13) | ((uint32_t)h3 << 13);
	w[3] = ((uint32_t)h3 >> 19) | ((uint32_t)h4 << 6);
	w[4] = (uint32_t)h5 | ((uint32_t)h6 << 25);
	w[5] = ((uint32_t)h6 >> 7) | ((uint32_t)h7 << 19);  /* <<19 */
	w[6] = ((uint32_t)h7 >> 13) | ((uint32_t)h8 << 12);  /* >>13 / <<12 */
	w[7] = ((uint32_t)h8 >> 20) | ((uint32_t)h9 << 6);  /* >>20 / <<6  */

	for (i = 0; i < 8; i++) {
		s[i * 4 + 0] = (uint8_t)(w[i] >> 0);
		s[i * 4 + 1] = (uint8_t)(w[i] >> 8);
		s[i * 4 + 2] = (uint8_t)(w[i] >> 16);
		s[i * 4 + 3] = (uint8_t)(w[i] >> 24);
	}
}

/* =========================================================================
* Montgomery ladder
* ====================================================================== */

/*
* x25519_ladder — Montgomery ladder scalar multiplication on Curve25519.
*
* Computes the affine x-coordinate of [k]u using the projective differential
* addition formulas from RFC 7748 §5 / Bernstein 2006.  The loop runs from
* bit 254 down to 0; bit 255 is always zero after clamping.
*
* All branches are eliminated via fe_cswap, making the loop body
* constant-time with respect to the scalar.
*
* Variables x2,z2 hold the current point; x3,z3 the "phantom" point one
* step ahead (needed for the differential addition).  At the end:
*   result = X2 * Z2^{-1}  (affine x-coordinate)
*/
static void x25519_ladder(fe out, const uint8_t k[32], const fe u)
{
	fe x1, x2, z2, x3, z3, tmp0, tmp1;
	int swap = 0;
	int i;

	fe_copy(x1, u);
	fe_1(x2);  fe_0(z2);
	fe_copy(x3, u); fe_1(z3);

	for (i = 254; i >= 0; i--) {
		int bit = (k[i >> 3] >> (i & 7)) & 1;
		swap ^= bit;
		fe_cswap(x2, x3, swap);
		fe_cswap(z2, z3, swap);
		swap = bit;

		/* One step of the Montgomery ladder (RFC 7748 §5): */
		fe_sub(tmp0, x3, z3);
		fe_sub(tmp1, x2, z2);
		fe_add(x2, x2, z2);
		fe_add(z2, x3, z3);
		fe_mul(z3, tmp0, x2);
		fe_mul(z2, z2, tmp1);
		fe_sq(tmp0, tmp1);
		fe_sq(tmp1, x2);
		fe_add(x3, z3, z2);
		fe_sub(z2, z3, z2);
		fe_mul(x2, tmp1, tmp0);
		fe_sub(tmp1, tmp1, tmp0);
		fe_sq(z2, z2);
		fe_mul121666(z3, tmp1);
		fe_sq(x3, x3);
		fe_add(tmp0, tmp0, z3);
		fe_mul(z3, x1, z2);
		fe_mul(z2, tmp1, tmp0);
	}

	/* Final conditional swap to undo the last iteration's swap state */
	fe_cswap(x2, x3, swap);
	fe_cswap(z2, z3, swap);

	/* Convert from projective to affine: result = X2 / Z2 */
	fe_invert(z2, z2);
	fe_mul(out, x2, z2);
}

/* =========================================================================
* Public API
* ====================================================================== */

/*
* clamp — apply the RFC 7748 §5 scalar clamping in-place:
*   - Clear bits 0-2 of byte  0  (ensure scalar is divisible by the cofactor 8)
*   - Clear bit  7  of byte 31  (keep scalar below 2^255)
*   - Set   bit  6  of byte 31  (ensure scalar is in the prime-order subgroup range)
*/
static void clamp(uint8_t k[32])
{
	k[0] &= 248;   /* clear bits 0-2 */
	k[31] &= 127;   /* clear bit 7    */
	k[31] |= 64;    /* set   bit 6    */
}

void curve25519_keygen(const uint8_t rand32[CURVE25519_KEY_LEN],
	uint8_t       priv_out[CURVE25519_KEY_LEN],
	uint8_t       pub_out[CURVE25519_KEY_LEN])
{
	memcpy(priv_out, rand32, CURVE25519_KEY_LEN);
	clamp(priv_out);
	curve25519_scalarmult_base(pub_out, priv_out);
}

int curve25519_scalarmult(uint8_t       shared_out[CURVE25519_KEY_LEN],
	const uint8_t scalar[CURVE25519_KEY_LEN],
	const uint8_t point[CURVE25519_KEY_LEN])
{
	fe u, result;
	uint8_t k[CURVE25519_KEY_LEN];
	uint8_t all_zero;
	int i;

	memcpy(k, scalar, CURVE25519_KEY_LEN);
	clamp(k);

	fe_frombytes(u, point);
	x25519_ladder(result, k, u);
	fe_tobytes(shared_out, result);

	/*
	* Reject low-order inputs (RFC 7748 §6 recommendation).
	* A low-order public key causes the shared secret to be the all-zero
	* string regardless of the private key; this is a signal to abort.
	* The output is already fully computed before this check.
	*/
	all_zero = 0;
	for (i = 0; i < CURVE25519_KEY_LEN; i++)
		all_zero |= shared_out[i];

	return all_zero ? 0 : -1;
}

void curve25519_scalarmult_base(uint8_t       pub_out[CURVE25519_KEY_LEN],
	const uint8_t scalar[CURVE25519_KEY_LEN])
{
	/* Curve25519 base point: u-coordinate = 9 */
	static const uint8_t basepoint[CURVE25519_KEY_LEN] = { 9 };
	curve25519_scalarmult(pub_out, scalar, basepoint);
}
