/*
 * Copyright 2024 Benjamin Edgington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "blst.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////
// Macros
////////////////////////////////////////////////////////////////////////////////////////////////////

/** The number of bytes in a KZG commitment. */
#define BYTES_PER_COMMITMENT 48

/** The number of bytes in a KZG proof. */
#define BYTES_PER_PROOF 48

/** The number of bytes in a BLS scalar field element. */
#define BYTES_PER_FIELD_ELEMENT 32

/** The number of field elements in a blob. */
#define FIELD_ELEMENTS_PER_BLOB 4096

/** The number of bytes in a blob. */
#define BYTES_PER_BLOB (FIELD_ELEMENTS_PER_BLOB * BYTES_PER_FIELD_ELEMENT)

/** The number of bits in a BLS scalar field element. */
#define BITS_PER_FIELD_ELEMENT 255

/** Length of the domain strings above. */
#define DOMAIN_STR_LENGTH 16

/** Returns number of elements in a statically defined array. */
#define NUM_ELEMENTS(a) (sizeof(a) / sizeof(a[0]))

/**
 * Helper macro to release memory allocated on the heap. Unlike free(), c_kzg_free() macro sets the
 * pointer value to NULL after freeing it.
 */
#define c_kzg_free(p) \
    do { \
        free(p); \
        (p) = NULL; \
    } while (0)

////////////////////////////////////////////////////////////////////////////////////////////////////
// Types
////////////////////////////////////////////////////////////////////////////////////////////////////

/** The common return type for all routines in which something can go wrong. */
typedef enum {
    C_KZG_OK = 0,  /**< Success! */
    C_KZG_BADARGS, /**< The supplied data is invalid in some way. */
    C_KZG_ERROR,   /**< Internal error - this should never occur. */
    C_KZG_MALLOC,  /**< Could not allocate memory. */
} C_KZG_RET;

typedef blst_p1 g1_t; /**< Internal G1 group element type. */
typedef blst_p2 g2_t; /**< Internal G2 group element type. */
typedef blst_fr fr_t; /**< Internal Fr field element type. */

/** An array of 32 bytes. Represents an untrusted (potentially invalid) field element. */
typedef struct {
    uint8_t bytes[32];
} Bytes32;

/** An array of 48 bytes. Represents an untrusted (potentially invalid) commitment/proof. */
typedef struct {
    uint8_t bytes[48];
} Bytes48;

/** A basic blob data. */
typedef struct {
    uint8_t bytes[BYTES_PER_BLOB];
} Blob;

/** A trusted (valid) KZG commitment. */
typedef Bytes48 KZGCommitment;

/** A trusted (valid) KZG proof. */
typedef Bytes48 KZGProof;

/** Stores the setup and parameters needed for computing KZG proofs. */
typedef struct {
    /** The size of our multiplicative subgroup (the roots of unity). This is the size of
     *  the extended domain (after the RS encoding has been applied), so the size of
     *  the subgroup is FIELD_ELEMENTS_PER_EXT_BLOB. */
    uint64_t max_width;
    /** Roots of unity in bit-reversal permutation order.
     *  The array contains `domain_size` elements. */
    fr_t *brp_roots_of_unity;
    /** Roots of unity for the subgroup of size `domain_size`.
     *  The array contains `domain_size + 1` elements, it starts and ends with Fr::one(). */
    fr_t *expanded_roots_of_unity;
    /** Roots of unity for the subgroup of size `domain_size` reversed. Only used in FFTs.
     *  The array contains `domain_size + 1` elements: it starts and ends with Fr::one(). */
    fr_t *reverse_roots_of_unity;
    /** G1 group elements from the trusted setup in monomial form. */
    g1_t *g1_values_monomial;
    /** G1 group elements from the trusted setup in Lagrange form and bit-reversed order. */
    g1_t *g1_values_lagrange_brp;
    /** G2 group elements from the trusted setup in monomial form. */
    g2_t *g2_values_monomial;
    /** Data used during FK20 proof generation. */
    g1_t **x_ext_fft_columns;
    /** The precomputed tables for fixed-base MSM. */
    blst_p1_affine **tables;
    /** The window size for the fixed-base MSM. */
    size_t wbits;
    /** The scratch size for the fixed-base MSM. */
    size_t scratch_size;
} KZGSettings;

////////////////////////////////////////////////////////////////////////////////////////////////////
// Constants
////////////////////////////////////////////////////////////////////////////////////////////////////

/** Deserialized form of the G1 identity/infinity point. */
static const g1_t G1_IDENTITY = {
    {0L, 0L, 0L, 0L, 0L, 0L}, {0L, 0L, 0L, 0L, 0L, 0L}, {0L, 0L, 0L, 0L, 0L, 0L}
};

/** The zero field element. */
static const fr_t FR_ZERO = {0L, 0L, 0L, 0L};

/** This is 1 in blst's `blst_fr` limb representation. Crazy but true. */
static const fr_t FR_ONE = {
    0x00000001fffffffeL, 0x5884b7fa00034802L, 0x998c4fefecbc4ff5L, 0x1824b159acc5056fL
};

/** This used to represent a missing element. It's an invalid value. */
static const fr_t FR_NULL = {
    0xffffffffffffffffL, 0xffffffffffffffffL, 0xffffffffffffffffL, 0xffffffffffffffffL
};

/**
 * The first 32 roots of unity in the finite field F_r. SCALE2_ROOT_OF_UNITY[i] is a 2^i'th root of
 * unity.
 *
 * For element `{A, B, C, D}`, the field element value is `A + B * 2^64 + C * 2^128 + D * 2^192`.
 * This format may be converted to an `fr_t` type via the blst_fr_from_uint64() function.
 *
 * The decimal values may be calculated with the following Python code:
 * @code{.py}
 * MODULUS = 52435875175126190479447740508185965837690552500527637822603658699938581184513
 * PRIMITIVE_ROOT = 7
 * [pow(PRIMITIVE_ROOT, (MODULUS - 1) // (2**i), MODULUS) for i in range(32)]
 * @endcode
 *
 * Note: Being a "primitive root" in this context means that `r^k != 1` for any `k < q-1` where q is
 * the modulus. So powers of r generate the field. This is also known as being a "primitive
 * element".
 *
 * In the formula above, the restriction can be slightly relaxed to `r` being a non-square. This is
 * easy to check: We just require that r^((q-1)/2) == -1. Instead of 7, we could use 10, 13, 14, 15,
 * 20... to create the 2^i'th roots of unity below. Generally, there are a lot of primitive roots:
 * https://crypto.stanford.edu/pbc/notes/numbertheory/gen.html
 */
static const uint64_t SCALE2_ROOT_OF_UNITY[][4] = {
    {0x0000000000000001L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L},
    {0xffffffff00000000L, 0x53bda402fffe5bfeL, 0x3339d80809a1d805L, 0x73eda753299d7d48L},
    {0x0001000000000000L, 0xec03000276030000L, 0x8d51ccce760304d0L, 0x0000000000000000L},
    {0x7228fd3397743f7aL, 0xb38b21c28713b700L, 0x8c0625cd70d77ce2L, 0x345766f603fa66e7L},
    {0x53ea61d87742bcceL, 0x17beb312f20b6f76L, 0xdd1c0af834cec32cL, 0x20b1ce9140267af9L},
    {0x360c60997369df4eL, 0xbf6e88fb4c38fb8aL, 0xb4bcd40e22f55448L, 0x50e0903a157988baL},
    {0x8140d032f0a9ee53L, 0x2d967f4be2f95155L, 0x14a1e27164d8fdbdL, 0x45af6345ec055e4dL},
    {0x5130c2c1660125beL, 0x98d0caac87f5713cL, 0xb7c68b4d7fdd60d0L, 0x6898111413588742L},
    {0x4935bd2f817f694bL, 0x0a0865a899e8deffL, 0x6b368121ac0cf4adL, 0x4f9b4098e2e9f12eL},
    {0x4541b8ff2ee0434eL, 0xd697168a3a6000feL, 0x39feec240d80689fL, 0x095166525526a654L},
    {0x3c28d666a5c2d854L, 0xea437f9626fc085eL, 0x8f4de02c0f776af3L, 0x325db5c3debf77a1L},
    {0x4a838b5d59cd79e5L, 0x55ea6811be9c622dL, 0x09f1ca610a08f166L, 0x6d031f1b5c49c834L},
    {0xe206da11a5d36306L, 0x0ad1347b378fbf96L, 0xfc3e8acfe0f8245fL, 0x564c0a11a0f704f4L},
    {0x6fdd00bfc78c8967L, 0x146b58bc434906acL, 0x2ccddea2972e89edL, 0x485d512737b1da3dL},
    {0x034d2ff22a5ad9e1L, 0xae4622f6a9152435L, 0xdc86b01c0d477fa6L, 0x56624634b500a166L},
    {0xfbd047e11279bb6eL, 0xc8d5f51db3f32699L, 0x483405417a0cbe39L, 0x3291357ee558b50dL},
    {0xd7118f85cd96b8adL, 0x67a665ae1fcadc91L, 0x88f39a78f1aeb578L, 0x2155379d12180caaL},
    {0x08692405f3b70f10L, 0xcd7f2bd6d0711b7dL, 0x473a2eef772c33d6L, 0x224262332d8acbf4L},
    {0x6f421a7d8ef674fbL, 0xbb97a3bf30ce40fdL, 0x652f717ae1c34bb0L, 0x2d3056a530794f01L},
    {0x194e8c62ecb38d9dL, 0xad8e16e84419c750L, 0xdf625e80d0adef90L, 0x520e587a724a6955L},
    {0xfece7e0e39898d4bL, 0x2f69e02d265e09d9L, 0xa57a6e07cb98de4aL, 0x03e1c54bcb947035L},
    {0xcd3979122d3ea03aL, 0x46b3105f04db5844L, 0xc70d0874b0691d4eL, 0x47c8b5817018af4fL},
    {0xc6e7a6ffb08e3363L, 0xe08fec7c86389beeL, 0xf2d38f10fbb8d1bbL, 0x0abe6a5e5abcaa32L},
    {0x5616c57de0ec9eaeL, 0xc631ffb2585a72dbL, 0x5121af06a3b51e3cL, 0x73560252aa0655b2L},
    {0x92cf4deb77bd779cL, 0x72cf6a8029b7d7bcL, 0x6e0bcd91ee762730L, 0x291cf6d68823e687L},
    {0xce32ef844e11a51eL, 0xc0ba12bb3da64ca5L, 0x0454dc1edc61a1a3L, 0x019fe632fd328739L},
    {0x531a11a0d2d75182L, 0x02c8118402867ddcL, 0x116168bffbedc11dL, 0x0a0a77a3b1980c0dL},
    {0xe2d0a7869f0319edL, 0xb94f1101b1d7a628L, 0xece8ea224f31d25dL, 0x23397a9300f8f98bL},
    {0xd7b688830a4f2089L, 0x6558e9e3f6ac7b41L, 0x99e276b571905a7dL, 0x52dd465e2f094256L},
    {0x474650359d8e211bL, 0x84d37b826214abc6L, 0x8da40c1ef2bb4598L, 0x0c83ea7744bf1beeL},
    {0x694341f608c9dd56L, 0xed3a181fabb30adcL, 0x1339a815da8b398fL, 0x2c6d4e4511657e1eL},
    {0x63e7cb4906ffc93fL, 0xf070bb00e28a193dL, 0xad1715b02e5713b5L, 0x4b5371495990693fL}
};

////////////////////////////////////////////////////////////////////////////////////////////////////
// Public Functions
////////////////////////////////////////////////////////////////////////////////////////////////////

/*
 * Memory Allocation:
 */
C_KZG_RET c_kzg_malloc(void **out, size_t size);
C_KZG_RET c_kzg_calloc(void **out, size_t count, size_t size);
C_KZG_RET new_g1_array(g1_t **x, size_t n);
C_KZG_RET new_g2_array(g2_t **x, size_t n);
C_KZG_RET new_fr_array(fr_t **x, size_t n);

/*
 * General Helper Functions:
 */
bool is_power_of_two(uint64_t n);
int log2_pow2(uint32_t n);
uint32_t reverse_bits(uint32_t n);
C_KZG_RET bit_reversal_permutation(void *values, size_t size, uint64_t n);

/*
 * Conversion and Validation:
 */
void bytes_from_g1(Bytes48 *out, const g1_t *in);
void bytes_from_bls_field(Bytes32 *out, const fr_t *in);
void bytes_from_uint64(uint8_t out[8], uint64_t n);
C_KZG_RET bytes_to_bls_field(fr_t *out, const Bytes32 *b);
C_KZG_RET bytes_to_kzg_commitment(g1_t *out, const Bytes48 *b);
C_KZG_RET bytes_to_kzg_proof(g1_t *out, const Bytes48 *b);
void fr_from_uint64(fr_t *out, uint64_t n);
void hash_to_bls_field(fr_t *out, const Bytes32 *b);
C_KZG_RET blob_to_polynomial(fr_t *p, const Blob *blob);

/*
 * Field Operations:
 */
bool fr_equal(const fr_t *a, const fr_t *b);
bool fr_is_one(const fr_t *p);
void fr_div(fr_t *out, const fr_t *a, const fr_t *b);
void fr_pow(fr_t *out, const fr_t *a, uint64_t n);
void compute_powers(fr_t *out, const fr_t *x, uint64_t n);

/*
 * Point Operations:
 */
void g1_sub(g1_t *out, const g1_t *a, const g1_t *b);
void g1_mul(g1_t *out, const g1_t *a, const fr_t *b);
bool pairings_verify(const g1_t *a1, const g2_t *a2, const g1_t *b1, const g2_t *b2);
void g1_lincomb_naive(g1_t *out, const g1_t *p, const fr_t *coeffs, uint64_t len);
C_KZG_RET g1_lincomb_fast(g1_t *out, const g1_t *p, const fr_t *coeffs, size_t len);
C_KZG_RET g1_fft(g1_t *out, const g1_t *in, size_t n, const KZGSettings *s);
C_KZG_RET g1_ifft(g1_t *out, const g1_t *in, size_t n, const KZGSettings *s);

#ifdef __cplusplus
}
#endif
