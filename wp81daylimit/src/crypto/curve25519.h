#pragma once

/*
* curve25519.h  -  X25519 Diffie-Hellman (RFC 7748)
*
* Implements scalar multiplication on Curve25519 using the
* Montgomery ladder over a 64-bit limb representation of GF(2^255-19).
* No external dependencies.
*/

#include <stdint.h>

#define CURVE25519_KEY_LEN  32

/*
* Generate an X25519 key pair.
*   priv_out : 32 random bytes clamped as per RFC 7748 §5
*   pub_out  : corresponding public key (scalar mult of base point)
*
* The caller must supply 32 cryptographically random bytes in rand32.
* The function clamps them and derives the public key.
*/
void curve25519_keygen(const uint8_t rand32[CURVE25519_KEY_LEN],
	uint8_t       priv_out[CURVE25519_KEY_LEN],
	uint8_t       pub_out[CURVE25519_KEY_LEN]);

/*
* X25519 scalar multiplication.
*   shared_out : 32-byte result
*   scalar     : 32-byte (clamped) private key
*   point      : 32-byte peer public key (u-coordinate)
*
* Returns 0 on success, -1 if the result is the all-zero point (low-order
* input — caller should reject the handshake).
*/
int curve25519_scalarmult(uint8_t       shared_out[CURVE25519_KEY_LEN],
	const uint8_t scalar[CURVE25519_KEY_LEN],
	const uint8_t point[CURVE25519_KEY_LEN]);

/*
* X25519 base-point multiplication (derives public key from private).
*/
void curve25519_scalarmult_base(uint8_t       pub_out[CURVE25519_KEY_LEN],
	const uint8_t scalar[CURVE25519_KEY_LEN]);