/*
 * Copyright 2021 Benjamin Edgington
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

/**
 * @file c_kzg_4844.c
 *
 * Minimal implementation of the polynomial commitments API for EIP-4844.
 */
#include "c_kzg_4844.h"

#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

///////////////////////////////////////////////////////////////////////////////
// Macros
///////////////////////////////////////////////////////////////////////////////

/** Returns C_KZG_BADARGS if the condition is not met. */
#define CHECK(cond) \
    if (!(cond)) return C_KZG_BADARGS

/** Returns number of elements in a statically defined array. */
#define NUM_ELEMENTS(a) (sizeof(a) / sizeof(a[0]))

/**
 * Helper macro to release memory allocated on the heap. Unlike free(),
 * c_kzg_free() macro sets the pointer value to NULL after freeing it.
 */
#define c_kzg_free(p) \
    do { \
        free(p); \
        (p) = NULL; \
    } while (0)

///////////////////////////////////////////////////////////////////////////////
// Types
///////////////////////////////////////////////////////////////////////////////

/** Internal representation of a polynomial. */
typedef struct {
    fr_t evals[FIELD_ELEMENTS_PER_BLOB];
} Polynomial;

///////////////////////////////////////////////////////////////////////////////
// Constants
///////////////////////////////////////////////////////////////////////////////

/** The domain separator for the Fiat-Shamir protocol. */
static const char *FIAT_SHAMIR_PROTOCOL_DOMAIN = "FSBLOBVERIFY_V1_";

/** The domain separator for a random challenge. */
static const char *RANDOM_CHALLENGE_KZG_BATCH_DOMAIN = "RCKZGBATCH___V1_";

/** Length of the domain strings above. */
#define DOMAIN_STR_LENGTH 16

/** The number of bytes in a g1 point. */
#define BYTES_PER_G1 48

/** The number of bytes in a g2 point. */
#define BYTES_PER_G2 96

/** The number of g1 points in a trusted setup. */
#define TRUSTED_SETUP_NUM_G1_POINTS FIELD_ELEMENTS_PER_BLOB

/** The number of g2 points in a trusted setup. */
#define TRUSTED_SETUP_NUM_G2_POINTS 65

// clang-format off

/** Deserialized form of the G1 identity/infinity point. */
static const g1_t G1_IDENTITY = {
    {0L, 0L, 0L, 0L, 0L, 0L},
    {0L, 0L, 0L, 0L, 0L, 0L},
    {0L, 0L, 0L, 0L, 0L, 0L}};

/**
 * The first 32 roots of unity in the finite field F_r.
 * SCALE2_ROOT_OF_UNITY[i] is a 2^i'th root of unity.
 *
 * For element `{A, B, C, D}`, the field element value is
 * `A + B * 2^64 + C * 2^128 + D * 2^192`. This format may be converted to
 * an `fr_t` type via the blst_fr_from_uint64() function.
 *
 * The decimal values may be calculated with the following Python code:
 * @code{.py}
 * MODULUS = 52435875175126190479447740508185965837690552500527637822603658699938581184513
 * PRIMITIVE_ROOT = 7
 * [pow(PRIMITIVE_ROOT, (MODULUS - 1) // (2**i), MODULUS) for i in range(32)]
 * @endcode
 *
 * Note: Being a "primitive root" in this context means that `r^k != 1` for any
 * `k < q-1` where q is the modulus. So powers of r generate the field. This is
 * also known as being a "primitive element".
 *
 * In the formula above, the restriction can be slightly relaxed to `r` being a non-square.
 * This is easy to check: We just require that r^((q-1)/2) == -1. Instead of
 * 7, we could use 10, 13, 14, 15, 20... to create the 2^i'th roots of unity below.
 * Generally, there are a lot of primitive roots:
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
    {0x63e7cb4906ffc93fL, 0xf070bb00e28a193dL, 0xad1715b02e5713b5L, 0x4b5371495990693fL}};

/** The zero field element. */
static const fr_t FR_ZERO = {0L, 0L, 0L, 0L};

/** This is 1 in Blst's `blst_fr` limb representation. Crazy but true. */
static const fr_t FR_ONE = {
    0x00000001fffffffeL, 0x5884b7fa00034802L,
    0x998c4fefecbc4ff5L, 0x1824b159acc5056fL};

/** This used to represent a missing element. It's a invalid value. */
static const fr_t FR_NULL = {
    0xffffffffffffffffL, 0xffffffffffffffffL,
    0xffffffffffffffffL, 0xffffffffffffffffL};

// clang-format on

///////////////////////////////////////////////////////////////////////////////
// Memory Allocation Functions
///////////////////////////////////////////////////////////////////////////////

/**
 * Wrapped malloc() that reports failures to allocate.
 *
 * @remark Will return C_KZG_BADARGS if the requested size is zero.
 *
 * @param[out] out  Pointer to the allocated space
 * @param[in]  size The number of bytes to be allocated
 */
static C_KZG_RET c_kzg_malloc(void **out, size_t size) {
    *out = NULL;
    if (size == 0) return C_KZG_BADARGS;
    *out = malloc(size);
    return *out != NULL ? C_KZG_OK : C_KZG_MALLOC;
}

/**
 * Wrapped calloc() that reports failures to allocate.
 *
 * @remark Will return C_KZG_BADARGS if the requested size is zero.
 *
 * @param[out] out   Pointer to the allocated space
 * @param[in]  count The number of elements
 * @param[in]  size  The size of each element
 */
static C_KZG_RET c_kzg_calloc(void **out, size_t count, size_t size) {
    *out = NULL;
    if (count == 0 || size == 0) return C_KZG_BADARGS;
    *out = calloc(count, size);
    return *out != NULL ? C_KZG_OK : C_KZG_MALLOC;
}

/**
 * Allocate memory for an array of G1 group elements.
 *
 * @remark Free the space later using c_kzg_free().
 *
 * @param[out] x Pointer to the allocated space
 * @param[in]  n The number of G1 elements to be allocated
 */
static C_KZG_RET new_g1_array(g1_t **x, size_t n) {
    return c_kzg_calloc((void **)x, n, sizeof(g1_t));
}

/**
 * Allocate memory for an array of G2 group elements.
 *
 * @remark Free the space later using c_kzg_free().
 *
 * @param[out] x Pointer to the allocated space
 * @param[in]  n The number of G2 elements to be allocated
 */
static C_KZG_RET new_g2_array(g2_t **x, size_t n) {
    return c_kzg_calloc((void **)x, n, sizeof(g2_t));
}

/**
 * Allocate memory for an array of field elements.
 *
 * @remark Free the space later using c_kzg_free().
 *
 * @param[out] x Pointer to the allocated space
 * @param[in]  n The number of field elements to be allocated
 */
static C_KZG_RET new_fr_array(fr_t **x, size_t n) {
    return c_kzg_calloc((void **)x, n, sizeof(fr_t));
}

///////////////////////////////////////////////////////////////////////////////
// Helper Functions
///////////////////////////////////////////////////////////////////////////////

/**
 * Get the minimum of two unsigned integers.
 *
 * @param[in]   a   An unsigned integer
 * @param[in]   b   An unsigned integer
 *
 * @return Whichever value is smaller.
 */
static inline size_t min(size_t a, size_t b) {
    return a < b ? a : b;
}

/**
 * Test whether the operand is one in the finite field.
 *
 * @param[in] p The field element to be checked
 *
 * @retval true  The element is one
 * @retval false The element is not one
 */
static bool fr_is_one(const fr_t *p) {
    uint64_t a[4];
    blst_uint64_from_fr(a, p);
    return a[0] == 1 && a[1] == 0 && a[2] == 0 && a[3] == 0;
}

/**
 * Test whether the operand is zero in the finite field.
 *
 * @param[in] p The field element to be checked
 *
 * @retval true  The element is zero
 * @retval false The element is not zero
 */
static bool fr_is_zero(const fr_t *p) {
    uint64_t a[4];
    blst_uint64_from_fr(a, p);
    return a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0;
}

/**
 * Test whether two field elements are equal.
 *
 * @param[in] aa The first element
 * @param[in] bb The second element
 *
 * @retval true  if @p aa and @p bb are equal
 * @retval false otherwise
 */
static bool fr_equal(const fr_t *aa, const fr_t *bb) {
    uint64_t a[4], b[4];
    blst_uint64_from_fr(a, aa);
    blst_uint64_from_fr(b, bb);
    return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3];
}

/**
 * Test whether the operand is null (all 0xff's).
 *
 * @param[in] p The field element to be checked
 *
 * @retval true  The element is null
 * @retval false The element is not null
 */
static bool fr_is_null(const fr_t *p) {
    return fr_equal(p, &FR_NULL);
}

/**
 * Divide a field element by another.
 *
 * @remark The behaviour for @p b == 0 is unspecified.
 *
 * @remark This function does support in-place computation, i.e. @p out == @p a
 * or @p out == @p b work.
 *
 * @param[out] out @p a divided by @p b in the field
 * @param[in]  a   The dividend
 * @param[in]  b   The divisor
 */
static void fr_div(fr_t *out, const fr_t *a, const fr_t *b) {
    blst_fr tmp;
    blst_fr_eucl_inverse(&tmp, b);
    blst_fr_mul(out, a, &tmp);
}

/**
 * Exponentiation of a field element.
 *
 * Uses square and multiply for log(@p n) performance.
 *
 * @remark A 64-bit exponent is sufficient for our needs here.
 *
 * @remark This function does support in-place computation, i.e. @p a == @p out
 * works.
 *
 * @param[out] out @p a raised to the power of @p n
 * @param[in]  a   The field element to be exponentiated
 * @param[in]  n   The exponent
 */
static void fr_pow(fr_t *out, const fr_t *a, uint64_t n) {
    fr_t tmp = *a;
    *out = FR_ONE;

    while (true) {
        if (n & 1) {
            blst_fr_mul(out, out, &tmp);
        }
        if ((n >>= 1) == 0) break;
        blst_fr_sqr(&tmp, &tmp);
    }
}

/**
 * Create a field element from a single 64-bit unsigned integer.
 *
 * @remark This can only generate a tiny fraction of possible field elements,
 * and is mostly useful for testing.
 *
 * @param[out] out The field element equivalent of @p n
 * @param[in]  n   The 64-bit integer to be converted
 */
static void fr_from_uint64(fr_t *out, uint64_t n) {
    uint64_t vals[] = {n, 0, 0, 0};
    blst_fr_from_uint64(out, vals);
}

/**
 * Montgomery batch inversion in finite field.
 *
 * @remark Return C_KZG_BADARGS if a zero is found in the input. In this case,
 * the `out` output array has already been mutated.
 *
 * @remark This function does not support in-place computation (i.e. `a` MUST
 * NOT point to the same place as `out`)
 *
 * @remark This function only supports len > 0.
 *
 * @param[out] out The inverses of @p a, length @p len
 * @param[in]  a   A vector of field elements, length @p len
 * @param[in]  len The number of field elements
 */
static C_KZG_RET fr_batch_inv(fr_t *out, const fr_t *a, int len) {
    int i;

    assert(len > 0);
    assert(a != out);

    fr_t accumulator = FR_ONE;

    for (i = 0; i < len; i++) {
        out[i] = accumulator;
        blst_fr_mul(&accumulator, &accumulator, &a[i]);
    }

    /* Bail on any zero input */
    if (fr_is_zero(&accumulator)) {
        return C_KZG_BADARGS;
    }

    blst_fr_eucl_inverse(&accumulator, &accumulator);

    for (i = len - 1; i >= 0; i--) {
        blst_fr_mul(&out[i], &out[i], &accumulator);
        blst_fr_mul(&accumulator, &accumulator, &a[i]);
    }

    return C_KZG_OK;
}

/**
 * Multiply a G1 group element by a field element.
 *
 * @param[out] out @p a * @p b
 * @param[in]  a   The G1 group element
 * @param[in]  b   The multiplier
 */
static void g1_mul(g1_t *out, const g1_t *a, const fr_t *b) {
    blst_scalar s;
    blst_scalar_from_fr(&s, b);
    /* The last argument is the number of bits in the scalar */
    blst_p1_mult(out, a, s.b, 8 * sizeof(blst_scalar));
}

/**
 * Multiply a G2 group element by a field element.
 *
 * @param[out] out @p a * @p b
 * @param[in]  a   The G2 group element
 * @param[in]  b   The multiplier
 */
static void g2_mul(g2_t *out, const g2_t *a, const fr_t *b) {
    blst_scalar s;
    blst_scalar_from_fr(&s, b);
    /* The last argument is the number of bits in the scalar */
    blst_p2_mult(out, a, s.b, 8 * sizeof(blst_scalar));
}

/**
 * Subtraction of G1 group elements.
 *
 * @param[out] out @p a - @p b
 * @param[in]  a   A G1 group element
 * @param[in]  b   The G1 group element to be subtracted
 */
static void g1_sub(g1_t *out, const g1_t *a, const g1_t *b) {
    g1_t bneg = *b;
    blst_p1_cneg(&bneg, true);
    blst_p1_add_or_double(out, a, &bneg);
}

/**
 * Subtraction of G2 group elements.
 *
 * @param[out] out @p a - @p b
 * @param[in]  a   A G2 group element
 * @param[in]  b   The G2 group element to be subtracted
 */
static void g2_sub(g2_t *out, const g2_t *a, const g2_t *b) {
    g2_t bneg = *b;
    blst_p2_cneg(&bneg, true);
    blst_p2_add_or_double(out, a, &bneg);
}

/**
 * Perform pairings and test whether the outcomes are equal in G_T.
 *
 * Tests whether `e(a1, a2) == e(b1, b2)`.
 *
 * @param[in] a1 A G1 group point for the first pairing
 * @param[in] a2 A G2 group point for the first pairing
 * @param[in] b1 A G1 group point for the second pairing
 * @param[in] b2 A G2 group point for the second pairing
 *
 * @retval true  The pairings were equal
 * @retval false The pairings were not equal
 */
static bool pairings_verify(
    const g1_t *a1, const g2_t *a2, const g1_t *b1, const g2_t *b2
) {
    blst_fp12 loop0, loop1, gt_point;
    blst_p1_affine aa1, bb1;
    blst_p2_affine aa2, bb2;

    /*
     * As an optimisation, we want to invert one of the pairings,
     * so we negate one of the points.
     */
    g1_t a1neg = *a1;
    blst_p1_cneg(&a1neg, true);

    blst_p1_to_affine(&aa1, &a1neg);
    blst_p1_to_affine(&bb1, b1);
    blst_p2_to_affine(&aa2, a2);
    blst_p2_to_affine(&bb2, b2);

    blst_miller_loop(&loop0, &aa2, &aa1);
    blst_miller_loop(&loop1, &bb2, &bb1);

    blst_fp12_mul(&gt_point, &loop0, &loop1);
    blst_final_exp(&gt_point, &gt_point);

    return blst_fp12_is_one(&gt_point);
}

///////////////////////////////////////////////////////////////////////////////
// Bytes Conversion Helper Functions
///////////////////////////////////////////////////////////////////////////////

/**
 * Serialize a G1 group element into bytes.
 *
 * @param[out] out A 48-byte array to store the serialized G1 element
 * @param[in]  in  The G1 element to be serialized
 */
static void bytes_from_g1(Bytes48 *out, const g1_t *in) {
    blst_p1_compress(out->bytes, in);
}

/**
 * Serialize a BLS field element into bytes.
 *
 * @param[out] out A 32-byte array to store the serialized field element
 * @param[in] in The field element to be serialized
 */
static void bytes_from_bls_field(Bytes32 *out, const fr_t *in) {
    blst_scalar s;
    blst_scalar_from_fr(&s, in);
    blst_bendian_from_scalar(out->bytes, &s);
}

/**
 * Serialize a 64-bit unsigned integer into bytes.
 *
 * @remark The output format is big-endian.
 *
 * @param[out] out An 8-byte array to store the serialized integer
 * @param[in]  n   The integer to be serialized
 */
static void bytes_from_uint64(uint8_t out[8], uint64_t n) {
    for (int i = 7; i >= 0; i--) {
        out[i] = n & 0xFF;
        n >>= 8;
    }
}

///////////////////////////////////////////////////////////////////////////////
// BLS12-381 Helper Functions
///////////////////////////////////////////////////////////////////////////////

/**
 * Map bytes to a BLS field element.
 *
 * @param[out] out The field element to store the result
 * @param[in]  b   A 32-byte array containing the input
 */
static void hash_to_bls_field(fr_t *out, const Bytes32 *b) {
    blst_scalar tmp;
    blst_scalar_from_bendian(&tmp, b->bytes);
    blst_fr_from_scalar(out, &tmp);
}

/**
 * Convert untrusted bytes to a trusted and validated BLS scalar field
 * element.
 *
 * @param[out] out The field element to store the deserialized data
 * @param[in]  b   A 32-byte array containing the serialized field element
 */
static C_KZG_RET bytes_to_bls_field(fr_t *out, const Bytes32 *b) {
    blst_scalar tmp;
    blst_scalar_from_bendian(&tmp, b->bytes);
    if (!blst_scalar_fr_check(&tmp)) return C_KZG_BADARGS;
    blst_fr_from_scalar(out, &tmp);
    return C_KZG_OK;
}

/**
 * Perform BLS validation required by the types KZGProof and KZGCommitment.
 *
 * @remark This function deviates from the spec because it returns (via an
 *     output argument) the g1 point. This way is more efficient (faster)
 *     but the function name is a bit misleading.
 *
 * @param[out]  out The output g1 point
 * @param[in]   b   The proof/commitment bytes
 */
static C_KZG_RET validate_kzg_g1(g1_t *out, const Bytes48 *b) {
    blst_p1_affine p1_affine;

    /* Convert the bytes to a p1 point */
    /* The uncompress routine checks that the point is on the curve */
    if (blst_p1_uncompress(&p1_affine, b->bytes) != BLST_SUCCESS)
        return C_KZG_BADARGS;
    blst_p1_from_affine(out, &p1_affine);

    /* The point at infinity is accepted! */
    if (blst_p1_is_inf(out)) return C_KZG_OK;
    /* The point must be on the right subgroup */
    if (!blst_p1_in_g1(out)) return C_KZG_BADARGS;

    return C_KZG_OK;
}

/**
 * Convert untrusted bytes into a trusted and validated KZGCommitment.
 *
 * @param[out]  out The output commitment
 * @param[in]   b   The commitment bytes
 */
static C_KZG_RET bytes_to_kzg_commitment(g1_t *out, const Bytes48 *b) {
    return validate_kzg_g1(out, b);
}

/**
 * Convert untrusted bytes into a trusted and validated KZGProof.
 *
 * @param[out]  out The output proof
 * @param[in]   b   The proof bytes
 */
static C_KZG_RET bytes_to_kzg_proof(g1_t *out, const Bytes48 *b) {
    return validate_kzg_g1(out, b);
}

/**
 * Deserialize a Blob (array of bytes) into a Polynomial (array of field
 * elements).
 *
 * @param[out] p    The output polynomial (array of field elements)
 * @param[in]  blob The blob (an array of bytes)
 */
static C_KZG_RET blob_to_polynomial(Polynomial *p, const Blob *blob) {
    C_KZG_RET ret;
    for (size_t i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++) {
        ret = bytes_to_bls_field(
            &p->evals[i], (Bytes32 *)&blob->bytes[i * BYTES_PER_FIELD_ELEMENT]
        );
        if (ret != C_KZG_OK) return ret;
    }
    return C_KZG_OK;
}

/* Input size to the Fiat-Shamir challenge computation. */
#define CHALLENGE_INPUT_SIZE \
    (DOMAIN_STR_LENGTH + 16 + BYTES_PER_BLOB + BYTES_PER_COMMITMENT)

/**
 * Return the Fiat-Shamir challenge required to verify `blob` and
 * `commitment`.
 *
 * @remark This function should compute challenges even if `n==0`.
 *
 * @param[out] eval_challenge_out The evaluation challenge
 * @param[in]  blob               A blob
 * @param[in]  commitment         A commitment
 */
static void compute_challenge(
    fr_t *eval_challenge_out, const Blob *blob, const g1_t *commitment
) {
    Bytes32 eval_challenge;
    uint8_t bytes[CHALLENGE_INPUT_SIZE];

    /* Pointer tracking `bytes` for writing on top of it */
    uint8_t *offset = bytes;

    /* Copy domain separator */
    memcpy(offset, FIAT_SHAMIR_PROTOCOL_DOMAIN, DOMAIN_STR_LENGTH);
    offset += DOMAIN_STR_LENGTH;

    /* Copy polynomial degree (16-bytes, big-endian) */
    bytes_from_uint64(offset, 0);
    offset += sizeof(uint64_t);
    bytes_from_uint64(offset, FIELD_ELEMENTS_PER_BLOB);
    offset += sizeof(uint64_t);

    /* Copy blob */
    memcpy(offset, blob->bytes, BYTES_PER_BLOB);
    offset += BYTES_PER_BLOB;

    /* Copy commitment */
    bytes_from_g1((Bytes48 *)offset, commitment);
    offset += BYTES_PER_COMMITMENT;

    /* Make sure we wrote the entire buffer */
    assert(offset == bytes + CHALLENGE_INPUT_SIZE);

    /* Now let's create the challenge! */
    blst_sha256(eval_challenge.bytes, bytes, CHALLENGE_INPUT_SIZE);
    hash_to_bls_field(eval_challenge_out, &eval_challenge);
}

/**
 * Calculate a linear combination of G1 group elements.
 *
 * Calculates `[coeffs_0]p_0 + [coeffs_1]p_1 + ... + [coeffs_n]p_n`
 * where `n` is `len - 1`.
 *
 * This function computes the result naively without using Pippenger's
 * algorithm.
 */
static void g1_lincomb_naive(
    g1_t *out, const g1_t *p, const fr_t *coeffs, uint64_t len
) {
    g1_t tmp;
    *out = G1_IDENTITY;
    for (uint64_t i = 0; i < len; i++) {
        g1_mul(&tmp, &p[i], &coeffs[i]);
        blst_p1_add_or_double(out, out, &tmp);
    }
}

/**
 * Calculate a linear combination of G1 group elements.
 *
 * Calculates `[coeffs_0]p_0 + [coeffs_1]p_1 + ... + [coeffs_n]p_n`
 * where `n` is `len - 1`.
 *
 * @remark This function MUST NOT be called with the point at infinity in `p`.
 *
 * @remark While this function is significantly faster than
 * `g1_lincomb_naive()`, we refrain from using it in security-critical places
 * (like verification) because the blst Pippenger code has not been
 * audited. In those critical places, we prefer using `g1_lincomb_naive()` which
 * is much simpler.
 *
 * @param[out] out    The resulting sum-product
 * @param[in]  p      Array of G1 group elements, length @p len
 * @param[in]  coeffs Array of field elements, length @p len
 * @param[in]  len    The number of group/field elements
 *
 * For the benefit of future generations (since Blst has no documentation to
 * speak of), there are two ways to pass the arrays of scalars and points
 * into blst_p1s_mult_pippenger().
 *
 * 1. Pass `points` as an array of pointers to the points, and pass
 *    `scalars` as an array of pointers to the scalars, each of length @p len.
 * 2. Pass an array where the first element is a pointer to the contiguous
 *    array of points and the second is null, and similarly for scalars.
 *
 * We do the second of these to save memory here.
 */
static C_KZG_RET g1_lincomb_fast(
    g1_t *out, const g1_t *p, const fr_t *coeffs, uint64_t len
) {
    C_KZG_RET ret;
    void *scratch = NULL;
    blst_p1_affine *p_affine = NULL;
    blst_scalar *scalars = NULL;

    /* Tunable parameter: must be at least 2 since blst fails for 0 or 1 */
    if (len < 8) {
        g1_lincomb_naive(out, p, coeffs, len);
    } else {
        /* blst's implementation of the Pippenger method */
        size_t scratch_size = blst_p1s_mult_pippenger_scratch_sizeof(len);
        ret = c_kzg_malloc(&scratch, scratch_size);
        if (ret != C_KZG_OK) goto out;
        ret = c_kzg_calloc((void **)&p_affine, len, sizeof(blst_p1_affine));
        if (ret != C_KZG_OK) goto out;
        ret = c_kzg_calloc((void **)&scalars, len, sizeof(blst_scalar));
        if (ret != C_KZG_OK) goto out;

        /* Transform the points to affine representation */
        const blst_p1 *p_arg[2] = {p, NULL};
        blst_p1s_to_affine(p_affine, p_arg, len);

        /* Transform the field elements to 256-bit scalars */
        for (uint64_t i = 0; i < len; i++) {
            blst_scalar_from_fr(&scalars[i], &coeffs[i]);
        }

        /* Call the Pippenger implementation */
        const byte *scalars_arg[2] = {(byte *)scalars, NULL};
        const blst_p1_affine *points_arg[2] = {p_affine, NULL};
        blst_p1s_mult_pippenger(
            out, points_arg, len, scalars_arg, 255, scratch
        );
    }

    ret = C_KZG_OK;

out:
    c_kzg_free(scratch);
    c_kzg_free(p_affine);
    c_kzg_free(scalars);
    return ret;
}

/**
 * Compute and return [ x^0, x^1, ..., x^{n-1} ].
 *
 * @remark `out` is left untouched if `n == 0`.
 *
 * @param[out] out The array to store the powers
 * @param[in]  x   The field element to raise to powers
 * @param[in]  n   The number of powers to compute
 */
static void compute_powers(fr_t *out, const fr_t *x, uint64_t n) {
    fr_t current_power = FR_ONE;
    for (uint64_t i = 0; i < n; i++) {
        out[i] = current_power;
        blst_fr_mul(&current_power, &current_power, x);
    }
}

///////////////////////////////////////////////////////////////////////////////
// Polynomials Functions
///////////////////////////////////////////////////////////////////////////////

/**
 * Evaluate a polynomial in evaluation form at a given point.
 *
 * @param[out] out The result of the evaluation
 * @param[in]  p   The polynomial in evaluation form
 * @param[in]  x   The point to evaluate the polynomial at
 * @param[in]  s   The trusted setup
 */
static C_KZG_RET evaluate_polynomial_in_evaluation_form(
    fr_t *out, const Polynomial *p, const fr_t *x, const KZGSettings *s
) {
    C_KZG_RET ret;
    fr_t tmp;
    fr_t *inverses_in = NULL;
    fr_t *inverses = NULL;
    uint64_t i;
    const fr_t *roots_of_unity = s->roots_of_unity;

    ret = new_fr_array(&inverses_in, FIELD_ELEMENTS_PER_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&inverses, FIELD_ELEMENTS_PER_BLOB);
    if (ret != C_KZG_OK) goto out;

    for (i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++) {
        /*
         * If the point to evaluate at is one of the evaluation points by which
         * the polynomial is given, we can just return the result directly.
         * Note that special-casing this is necessary, as the formula below
         * would divide by zero otherwise.
         */
        if (fr_equal(x, &roots_of_unity[i])) {
            *out = p->evals[i];
            ret = C_KZG_OK;
            goto out;
        }
        blst_fr_sub(&inverses_in[i], x, &roots_of_unity[i]);
    }

    ret = fr_batch_inv(inverses, inverses_in, FIELD_ELEMENTS_PER_BLOB);
    if (ret != C_KZG_OK) goto out;

    *out = FR_ZERO;
    for (i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++) {
        blst_fr_mul(&tmp, &inverses[i], &roots_of_unity[i]);
        blst_fr_mul(&tmp, &tmp, &p->evals[i]);
        blst_fr_add(out, out, &tmp);
    }
    fr_from_uint64(&tmp, FIELD_ELEMENTS_PER_BLOB);
    fr_div(out, out, &tmp);
    fr_pow(&tmp, x, FIELD_ELEMENTS_PER_BLOB);
    blst_fr_sub(&tmp, &tmp, &FR_ONE);
    blst_fr_mul(out, out, &tmp);

out:
    c_kzg_free(inverses_in);
    c_kzg_free(inverses);
    return ret;
}

///////////////////////////////////////////////////////////////////////////////
// KZG Functions
///////////////////////////////////////////////////////////////////////////////

/**
 * Compute a KZG commitment from a polynomial (in monomial form).
 *
 * @param[out] out The resulting commitment
 * @param[in]  p   The polynomial to commit to
 * @param[in]  n   The polynomial length
 * @param[in]  s   The trusted setup
 */
static C_KZG_RET poly_to_kzg_commitment_monomial(
    g1_t *out, const fr_t *p, size_t n, const KZGSettings *s
) {
    return g1_lincomb_fast(out, s->g1_values, p, n);
}

/**
 * Compute a KZG commitment from a polynomial (in lagrange form).
 *
 * @param[out] out The resulting commitment
 * @param[in]  p   The polynomial to commit to
 * @param[in]  n   The polynomial length
 * @param[in]  s   The trusted setup
 */
C_KZG_RET poly_to_kzg_commitment_lagrange(
    g1_t *out, const fr_t *p, size_t n, const KZGSettings *s
) {
    return g1_lincomb_fast(out, s->g1_values_lagrange, p, n);
}

/**
 * Convert a blob to a KZG commitment.
 *
 * @param[out] out  The resulting commitment
 * @param[in]  blob The blob representing the polynomial to be committed to
 * @param[in]  s    The trusted setup
 */
C_KZG_RET blob_to_kzg_commitment(
    KZGCommitment *out, const Blob *blob, const KZGSettings *s
) {
    C_KZG_RET ret;
    Polynomial p;
    g1_t commitment;

    ret = blob_to_polynomial(&p, blob);
    if (ret != C_KZG_OK) return ret;
    ret = poly_to_kzg_commitment_lagrange(
        &commitment, p.evals, FIELD_ELEMENTS_PER_BLOB, s
    );
    if (ret != C_KZG_OK) return ret;
    bytes_from_g1(out, &commitment);
    return C_KZG_OK;
}

/* Forward function declaration */
static C_KZG_RET verify_kzg_proof_impl(
    bool *ok,
    const g1_t *commitment,
    const fr_t *z,
    const fr_t *y,
    const g1_t *proof,
    const KZGSettings *s
);

/**
 * Verify a KZG proof claiming that `p(z) == y`.
 *
 * @param[out] ok         True if the proofs are valid, otherwise false
 * @param[in]  commitment The KZG commitment corresponding to poly p(x)
 * @param[in]  z          The evaluation point
 * @param[in]  y          The claimed evaluation result
 * @param[in]  kzg_proof  The KZG proof
 * @param[in]  s          The trusted setup
 */
C_KZG_RET verify_kzg_proof(
    bool *ok,
    const Bytes48 *commitment_bytes,
    const Bytes32 *z_bytes,
    const Bytes32 *y_bytes,
    const Bytes48 *proof_bytes,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    fr_t z_fr, y_fr;
    g1_t commitment_g1, proof_g1;

    *ok = false;

    /* Convert untrusted inputs to trusted inputs */
    ret = bytes_to_kzg_commitment(&commitment_g1, commitment_bytes);
    if (ret != C_KZG_OK) return ret;
    ret = bytes_to_bls_field(&z_fr, z_bytes);
    if (ret != C_KZG_OK) return ret;
    ret = bytes_to_bls_field(&y_fr, y_bytes);
    if (ret != C_KZG_OK) return ret;
    ret = bytes_to_kzg_proof(&proof_g1, proof_bytes);
    if (ret != C_KZG_OK) return ret;

    /* Call helper to do pairings check */
    return verify_kzg_proof_impl(
        ok, &commitment_g1, &z_fr, &y_fr, &proof_g1, s
    );
}

/**
 * Helper function: Verify KZG proof claiming that `p(z) == y`.
 *
 * Given a @p commitment to a polynomial, a @p proof for @p z, and the
 * claimed value @p y at @p z, verify the claim.
 *
 * @param[out] out        `true` if the proof is valid, `false` if not
 * @param[in]  commitment The commitment to a polynomial
 * @param[in]  z          The point at which the proof is to be checked
 *                        (opened)
 * @param[in]  y          The claimed value of the polynomial at @p z
 * @param[in]  proof      A proof of the value of the polynomial at the
 *                        point @p z
 * @param[in]  s          The trusted setup
 */
static C_KZG_RET verify_kzg_proof_impl(
    bool *ok,
    const g1_t *commitment,
    const fr_t *z,
    const fr_t *y,
    const g1_t *proof,
    const KZGSettings *s
) {
    g2_t x_g2, X_minus_z;
    g1_t y_g1, P_minus_y;

    /* Calculate: X_minus_z */
    g2_mul(&x_g2, blst_p2_generator(), z);
    g2_sub(&X_minus_z, &s->g2_values[1], &x_g2);

    /* Calculate: P_minus_y */
    g1_mul(&y_g1, blst_p1_generator(), y);
    g1_sub(&P_minus_y, commitment, &y_g1);

    /* Verify: P - y = Q * (X - z) */
    *ok = pairings_verify(&P_minus_y, blst_p2_generator(), proof, &X_minus_z);

    return C_KZG_OK;
}

/* Forward function declaration */
static C_KZG_RET compute_kzg_proof_impl(
    KZGProof *proof_out,
    fr_t *y_out,
    const Polynomial *polynomial,
    const fr_t *z,
    const KZGSettings *s
);

/**
 * Compute KZG proof for polynomial in Lagrange form at position z.
 *
 * @param[out] proof_out The combined proof as a single G1 element
 * @param[out] y_out     The evaluation of the polynomial at the evaluation
 *                       point z
 * @param[in]  blob      The blob (polynomial) to generate a proof for
 * @param[in]  z         The generator z-value for the evaluation points
 * @param[in]  s         The trusted setup
 */
C_KZG_RET compute_kzg_proof(
    KZGProof *proof_out,
    Bytes32 *y_out,
    const Blob *blob,
    const Bytes32 *z_bytes,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    Polynomial polynomial;
    fr_t frz, fry;

    ret = blob_to_polynomial(&polynomial, blob);
    if (ret != C_KZG_OK) goto out;
    ret = bytes_to_bls_field(&frz, z_bytes);
    if (ret != C_KZG_OK) goto out;
    ret = compute_kzg_proof_impl(proof_out, &fry, &polynomial, &frz, s);
    if (ret != C_KZG_OK) goto out;
    bytes_from_bls_field(y_out, &fry);

out:
    return ret;
}

/**
 * Helper function for compute_kzg_proof() and
 * compute_blob_kzg_proof().
 *
 * @param[out] proof_out  The combined proof as a single G1 element
 * @param[out] y_out      The evaluation of the polynomial at the evaluation
 *                        point z
 * @param[in]  polynomial The polynomial in Lagrange form
 * @param[in]  z          The evaluation point
 * @param[in]  s          The trusted setup
 */
static C_KZG_RET compute_kzg_proof_impl(
    KZGProof *proof_out,
    fr_t *y_out,
    const Polynomial *polynomial,
    const fr_t *z,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    fr_t *inverses_in = NULL;
    fr_t *inverses = NULL;

    ret = evaluate_polynomial_in_evaluation_form(y_out, polynomial, z, s);
    if (ret != C_KZG_OK) goto out;

    fr_t tmp;
    Polynomial q;
    const fr_t *roots_of_unity = s->roots_of_unity;
    uint64_t i;
    /* m != 0 indicates that the evaluation point z equals root_of_unity[m-1] */
    uint64_t m = 0;

    ret = new_fr_array(&inverses_in, FIELD_ELEMENTS_PER_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&inverses, FIELD_ELEMENTS_PER_BLOB);
    if (ret != C_KZG_OK) goto out;

    for (i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++) {
        if (fr_equal(z, &roots_of_unity[i])) {
            /* We are asked to compute a KZG proof inside the domain */
            m = i + 1;
            inverses_in[i] = FR_ONE;
            continue;
        }
        // (p_i - y) / (ω_i - z)
        blst_fr_sub(&q.evals[i], &polynomial->evals[i], y_out);
        blst_fr_sub(&inverses_in[i], &roots_of_unity[i], z);
    }

    ret = fr_batch_inv(inverses, inverses_in, FIELD_ELEMENTS_PER_BLOB);
    if (ret != C_KZG_OK) goto out;

    for (i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++) {
        blst_fr_mul(&q.evals[i], &q.evals[i], &inverses[i]);
    }

    if (m != 0) { /* ω_{m-1} == z */
        q.evals[--m] = FR_ZERO;
        for (i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++) {
            if (i == m) continue;
            /* Build denominator: z * (z - ω_i) */
            blst_fr_sub(&tmp, z, &roots_of_unity[i]);
            blst_fr_mul(&inverses_in[i], &tmp, z);
        }

        ret = fr_batch_inv(inverses, inverses_in, FIELD_ELEMENTS_PER_BLOB);
        if (ret != C_KZG_OK) goto out;

        for (i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++) {
            if (i == m) continue;
            /* Build numerator: ω_i * (p_i - y) */
            blst_fr_sub(&tmp, &polynomial->evals[i], y_out);
            blst_fr_mul(&tmp, &tmp, &roots_of_unity[i]);
            /* Do the division: (p_i - y) * ω_i / (z * (z - ω_i)) */
            blst_fr_mul(&tmp, &tmp, &inverses[i]);
            blst_fr_add(&q.evals[m], &q.evals[m], &tmp);
        }
    }

    g1_t out_g1;
    ret = g1_lincomb_fast(
        &out_g1,
        s->g1_values_lagrange,
        (const fr_t *)(&q.evals),
        FIELD_ELEMENTS_PER_BLOB
    );
    if (ret != C_KZG_OK) goto out;

    bytes_from_g1(proof_out, &out_g1);

out:
    c_kzg_free(inverses_in);
    c_kzg_free(inverses);
    return ret;
}

/**
 * Given a blob and a commitment, return the KZG proof that is used to verify
 * it against the commitment. This function does not verify that the commitment
 * is correct with respect to the blob.
 *
 * @param[out] out              The resulting proof
 * @param[in]  blob             A blob
 * @param[in]  commitment_bytes Commitment to verify
 * @param[in]  s                The trusted setup
 */
C_KZG_RET compute_blob_kzg_proof(
    KZGProof *out,
    const Blob *blob,
    const Bytes48 *commitment_bytes,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    Polynomial polynomial;
    g1_t commitment_g1;
    fr_t evaluation_challenge_fr;
    fr_t y;

    /* Do conversions first to fail fast, compute_challenge is expensive */
    ret = bytes_to_kzg_commitment(&commitment_g1, commitment_bytes);
    if (ret != C_KZG_OK) goto out;
    ret = blob_to_polynomial(&polynomial, blob);
    if (ret != C_KZG_OK) goto out;

    /* Compute the challenge for the given blob/commitment */
    compute_challenge(&evaluation_challenge_fr, blob, &commitment_g1);

    /* Call helper function to compute proof and y */
    ret = compute_kzg_proof_impl(
        out, &y, &polynomial, &evaluation_challenge_fr, s
    );
    if (ret != C_KZG_OK) goto out;

out:
    return ret;
}

/**
 * Given a blob and its proof, verify that it corresponds to the provided
 * commitment.
 *
 * @param[out] ok               True if the proofs are valid, otherwise false
 * @param[in]  blob             Blob to verify
 * @param[in]  commitment_bytes Commitment to verify
 * @param[in]  proof_bytes      Proof used for verification
 * @param[in]  s                The trusted setup
 */
C_KZG_RET verify_blob_kzg_proof(
    bool *ok,
    const Blob *blob,
    const Bytes48 *commitment_bytes,
    const Bytes48 *proof_bytes,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    Polynomial polynomial;
    fr_t evaluation_challenge_fr, y_fr;
    g1_t commitment_g1, proof_g1;

    *ok = false;

    /* Do conversions first to fail fast, compute_challenge is expensive */
    ret = bytes_to_kzg_commitment(&commitment_g1, commitment_bytes);
    if (ret != C_KZG_OK) return ret;
    ret = blob_to_polynomial(&polynomial, blob);
    if (ret != C_KZG_OK) return ret;
    ret = bytes_to_kzg_proof(&proof_g1, proof_bytes);
    if (ret != C_KZG_OK) return ret;

    /* Compute challenge for the blob/commitment */
    compute_challenge(&evaluation_challenge_fr, blob, &commitment_g1);

    /* Evaluate challenge to get y */
    ret = evaluate_polynomial_in_evaluation_form(
        &y_fr, &polynomial, &evaluation_challenge_fr, s
    );
    if (ret != C_KZG_OK) return ret;

    /* Call helper to do pairings check */
    return verify_kzg_proof_impl(
        ok, &commitment_g1, &evaluation_challenge_fr, &y_fr, &proof_g1, s
    );
}

/**
 * Compute random linear combination challenge scalars for batch verification.
 *
 * @param[out]  r_powers_out   The output challenges
 * @param[in]   commitments_g1 The input commitments
 * @param[in]   zs_fr          The input evaluation points
 * @param[in]   ys_fr          The input evaluation results
 * @param[in]   proofs_g1      The input proofs
 */
static C_KZG_RET compute_r_powers(
    fr_t *r_powers_out,
    const g1_t *commitments_g1,
    const fr_t *zs_fr,
    const fr_t *ys_fr,
    const g1_t *proofs_g1,
    size_t n
) {
    C_KZG_RET ret;
    uint8_t *bytes = NULL;
    Bytes32 r_bytes;
    fr_t r;

    size_t input_size = DOMAIN_STR_LENGTH + sizeof(uint64_t) +
                        sizeof(uint64_t) +
                        (n * (BYTES_PER_COMMITMENT +
                              2 * BYTES_PER_FIELD_ELEMENT + BYTES_PER_PROOF));
    ret = c_kzg_malloc((void **)&bytes, input_size);
    if (ret != C_KZG_OK) goto out;

    /* Pointer tracking `bytes` for writing on top of it */
    uint8_t *offset = bytes;

    /* Copy domain separator */
    memcpy(offset, RANDOM_CHALLENGE_KZG_BATCH_DOMAIN, DOMAIN_STR_LENGTH);
    offset += DOMAIN_STR_LENGTH;

    /* Copy degree of the polynomial */
    bytes_from_uint64(offset, FIELD_ELEMENTS_PER_BLOB);
    offset += sizeof(uint64_t);

    /* Copy number of commitments */
    bytes_from_uint64(offset, n);
    offset += sizeof(uint64_t);

    for (size_t i = 0; i < n; i++) {
        /* Copy commitment */
        bytes_from_g1((Bytes48 *)offset, &commitments_g1[i]);
        offset += BYTES_PER_COMMITMENT;

        /* Copy z */
        bytes_from_bls_field((Bytes32 *)offset, &zs_fr[i]);
        offset += BYTES_PER_FIELD_ELEMENT;

        /* Copy y */
        bytes_from_bls_field((Bytes32 *)offset, &ys_fr[i]);
        offset += BYTES_PER_FIELD_ELEMENT;

        /* Copy proof */
        bytes_from_g1((Bytes48 *)offset, &proofs_g1[i]);
        offset += BYTES_PER_PROOF;
    }

    /* Now let's create the challenge! */
    blst_sha256(r_bytes.bytes, bytes, input_size);
    hash_to_bls_field(&r, &r_bytes);

    compute_powers(r_powers_out, &r, n);

    /* Make sure we wrote the entire buffer */
    assert(offset == bytes + input_size);

out:
    c_kzg_free(bytes);
    return ret;
}

/**
 * Helper function for verify_blob_kzg_proof_batch(): actually perform the
 * verification.
 *
 * @remark This function assumes that `n` is trusted and that all input arrays
 *     contain `n` elements. `n` should be the actual size of the arrays and not
 *     read off a length field in the protocol.
 *
 * @remark This function only works for `n > 0`.
 *
 * @param[out] ok             True if the proofs are valid, otherwise false
 * @param[in]  commitments_g1 Array of commitments to verify
 * @param[in]  zs_fr          Array of evaluation points for the KZG proofs
 * @param[in]  ys_fr          Array of evaluation results for the KZG proofs
 * @param[in]  proofs_g1      Array of proofs used for verification
 * @param[in]  n              The number of blobs/commitments/proofs
 * @param[in]  s              The trusted setup
 */
static C_KZG_RET verify_kzg_proof_batch(
    bool *ok,
    const g1_t *commitments_g1,
    const fr_t *zs_fr,
    const fr_t *ys_fr,
    const g1_t *proofs_g1,
    size_t n,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    g1_t proof_lincomb, proof_z_lincomb, C_minus_y_lincomb, rhs_g1;
    fr_t *r_powers = NULL;
    g1_t *C_minus_y = NULL;
    fr_t *r_times_z = NULL;

    assert(n > 0);

    *ok = false;

    /* First let's allocate our arrays */
    ret = new_fr_array(&r_powers, n);
    if (ret != C_KZG_OK) goto out;
    ret = new_g1_array(&C_minus_y, n);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&r_times_z, n);
    if (ret != C_KZG_OK) goto out;

    /* Compute the random lincomb challenges */
    ret = compute_r_powers(
        r_powers, commitments_g1, zs_fr, ys_fr, proofs_g1, n
    );
    if (ret != C_KZG_OK) goto out;

    /* Compute \sum r^i * Proof_i */
    g1_lincomb_naive(&proof_lincomb, proofs_g1, r_powers, n);

    for (size_t i = 0; i < n; i++) {
        g1_t ys_encrypted;
        /* Get [y_i] */
        g1_mul(&ys_encrypted, blst_p1_generator(), &ys_fr[i]);
        /* Get C_i - [y_i] */
        g1_sub(&C_minus_y[i], &commitments_g1[i], &ys_encrypted);
        /* Get r^i * z_i */
        blst_fr_mul(&r_times_z[i], &r_powers[i], &zs_fr[i]);
    }

    /* Get \sum r^i z_i Proof_i */
    g1_lincomb_naive(&proof_z_lincomb, proofs_g1, r_times_z, n);
    /* Get \sum r^i (C_i - [y_i]) */
    g1_lincomb_naive(&C_minus_y_lincomb, C_minus_y, r_powers, n);
    /* Get C_minus_y_lincomb + proof_z_lincomb */
    blst_p1_add_or_double(&rhs_g1, &C_minus_y_lincomb, &proof_z_lincomb);

    /* Do the pairing check! */
    *ok = pairings_verify(
        &proof_lincomb, &s->g2_values[1], &rhs_g1, blst_p2_generator()
    );

out:
    c_kzg_free(r_powers);
    c_kzg_free(C_minus_y);
    c_kzg_free(r_times_z);
    return ret;
}

/**
 * Given a list of blobs and blob KZG proofs, verify that they correspond to the
 * provided commitments.
 *
 * @remark This function assumes that `n` is trusted and that all input arrays
 * contain `n` elements. `n` should be the actual size of the arrays and not
 * read off a length field in the protocol.
 *
 * @remark This function accepts if called with `n==0`.
 *
 * @param[out] ok                True if the proofs are valid, otherwise false
 * @param[in]  blobs             Array of blobs to verify
 * @param[in]  commitments_bytes Array of commitments to verify
 * @param[in]  proofs_bytes      Array of proofs used for verification
 * @param[in]  n                 The number of blobs/commitments/proofs
 * @param[in]  s                 The trusted setup
 */
C_KZG_RET verify_blob_kzg_proof_batch(
    bool *ok,
    const Blob *blobs,
    const Bytes48 *commitments_bytes,
    const Bytes48 *proofs_bytes,
    size_t n,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    g1_t *commitments_g1 = NULL;
    g1_t *proofs_g1 = NULL;
    fr_t *evaluation_challenges_fr = NULL;
    fr_t *ys_fr = NULL;

    /* Exit early if we are given zero blobs */
    if (n == 0) {
        *ok = true;
        return C_KZG_OK;
    }

    /* For a single blob, just do a regular single verification */
    if (n == 1) {
        return verify_blob_kzg_proof(
            ok, &blobs[0], &commitments_bytes[0], &proofs_bytes[0], s
        );
    }

    /* We will need a bunch of arrays to store our objects... */
    ret = new_g1_array(&commitments_g1, n);
    if (ret != C_KZG_OK) goto out;
    ret = new_g1_array(&proofs_g1, n);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&evaluation_challenges_fr, n);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&ys_fr, n);
    if (ret != C_KZG_OK) goto out;

    for (size_t i = 0; i < n; i++) {
        Polynomial polynomial;

        /* Convert each commitment to a g1 point */
        ret = bytes_to_kzg_commitment(
            &commitments_g1[i], &commitments_bytes[i]
        );
        if (ret != C_KZG_OK) goto out;

        /* Convert each blob from bytes to a poly */
        ret = blob_to_polynomial(&polynomial, &blobs[i]);
        if (ret != C_KZG_OK) goto out;

        compute_challenge(
            &evaluation_challenges_fr[i], &blobs[i], &commitments_g1[i]
        );

        ret = evaluate_polynomial_in_evaluation_form(
            &ys_fr[i], &polynomial, &evaluation_challenges_fr[i], s
        );
        if (ret != C_KZG_OK) goto out;

        ret = bytes_to_kzg_proof(&proofs_g1[i], &proofs_bytes[i]);
        if (ret != C_KZG_OK) goto out;
    }

    ret = verify_kzg_proof_batch(
        ok, commitments_g1, evaluation_challenges_fr, ys_fr, proofs_g1, n, s
    );

out:
    c_kzg_free(commitments_g1);
    c_kzg_free(proofs_g1);
    c_kzg_free(evaluation_challenges_fr);
    c_kzg_free(ys_fr);
    return ret;
}

///////////////////////////////////////////////////////////////////////////////
// FFT for G1 points
///////////////////////////////////////////////////////////////////////////////

/**
 * Utility function to test whether the argument is a power of two.
 *
 * @remark This method returns `true` for `is_power_of_two(0)` which is a bit
 *     weird, but not an issue in the contexts in which we use it.
 *
 * @param[in] n The number to test
 * @retval true  if @p n is a power of two or zero
 * @retval false otherwise
 */
static bool is_power_of_two(uint64_t n) {
    return (n & (n - 1)) == 0;
}

/**
 * Fast Fourier Transform.
 *
 * Recursively divide and conquer.
 *
 * @param[out] out          The results (array of length @p n)
 * @param[in]  in           The input data (array of length @p n * @p stride)
 * @param[in]  stride       The input data stride
 * @param[in]  roots        Roots of unity
 *                          (array of length @p n * @p roots_stride)
 * @param[in]  roots_stride The stride interval among the roots of unity
 * @param[in]  n            Length of the FFT, must be a power of two
 */
static void fft_g1_fast(
    g1_t *out,
    const g1_t *in,
    uint64_t stride,
    const fr_t *roots,
    uint64_t roots_stride,
    uint64_t n
) {
    uint64_t half = n / 2;
    if (half > 0) { /* Tunable parameter */
        fft_g1_fast(out, in, stride * 2, roots, roots_stride * 2, half);
        fft_g1_fast(
            out + half, in + stride, stride * 2, roots, roots_stride * 2, half
        );
        for (uint64_t i = 0; i < half; i++) {
            g1_t y_times_root;
            if (fr_is_one(&roots[i * roots_stride])) {
                /* Don't do the scalar multiplication if the scalar is one */
                y_times_root = out[i + half];
            } else {
                g1_mul(&y_times_root, &out[i + half], &roots[i * roots_stride]);
            }
            g1_sub(&out[i + half], &out[i], &y_times_root);
            blst_p1_add_or_double(&out[i], &out[i], &y_times_root);
        }
    } else {
        *out = *in;
    }
}

/**
 * The entry point for forward FFT over G1 points.
 *
 * @param[out]  out The results (array of length n)
 * @param[in]   in  The input data (array of length n)
 * @param[in]   n   Length of the arrays
 * @param[in]   s   The trusted setup
 *
 * @remark The array lengths must be a power of two.
 * @remark Use ifft_g1 for inverse transformation.
 */
C_KZG_RET fft_g1(g1_t *out, const g1_t *in, size_t n, const KZGSettings *s) {
    CHECK(n <= s->max_width);
    CHECK(is_power_of_two(n));

    uint64_t stride = s->max_width / n;
    fft_g1_fast(out, in, 1, s->expanded_roots_of_unity, stride, n);

    return C_KZG_OK;
}

/**
 * The entry point for inverse FFT over G1 points.
 *
 * @param[out]  out The results (array of length n)
 * @param[in]   in  The input data (array of length n)
 * @param[in]   n   Length of the arrays
 * @param[in]   s   The trusted setup
 *
 * @remark The array lengths must be a power of two.
 * @remark Use fft_g1 for forward transformation.
 */
C_KZG_RET ifft_g1(g1_t *out, const g1_t *in, size_t n, const KZGSettings *s) {
    CHECK(n <= s->max_width);
    CHECK(is_power_of_two(n));

    uint64_t stride = s->max_width / n;
    fft_g1_fast(out, in, 1, s->reverse_roots_of_unity, stride, n);

    fr_t inv_len;
    fr_from_uint64(&inv_len, n);
    blst_fr_eucl_inverse(&inv_len, &inv_len);
    for (uint64_t i = 0; i < n; i++) {
        g1_mul(&out[i], &out[i], &inv_len);
    }

    return C_KZG_OK;
}

///////////////////////////////////////////////////////////////////////////////
// Trusted Setup Functions
///////////////////////////////////////////////////////////////////////////////

/**
 * Reverse the bit order in a 32-bit integer.
 *
 * @param[in] a The integer to be reversed
 * @return An integer with the bits of @p a reversed
 */
static uint32_t reverse_bits(uint32_t n) {
    uint32_t result = 0;
    for (int i = 0; i < 32; ++i) {
        result <<= 1;
        result |= (n & 1);
        n >>= 1;
    }
    return result;
}

/**
 * Calculate log base two of a power of two.
 *
 * In other words, the bit index of the one bit.
 *
 * @remark Works only for n a power of two, and only for n up to 2^31.
 * @remark Not the fastest implementation, but it doesn't need to be fast.
 *
 * @param[in] n The power of two
 *
 * @return the log base two of n
 */
static int log2_pow2(uint32_t n) {
    int position = 0;
    while (n >>= 1)
        position++;
    return position;
}

/**
 * Reverse the low-order bits in a 32-bit integer.
 *
 * @remark n must be a power of two.
 *
 * @param[in]   n       To reverse `b` bits, set `n = 2 ^ b`
 * @param[in]   value   The bits to be reversed
 *
 * @return The reversal of the lowest log_2(n) bits of the input value
 */
static uint32_t reverse_bits_limited(uint32_t n, uint32_t value) {
    size_t unused_bit_len = 32 - log2_pow2(n);
    return reverse_bits(value) >> unused_bit_len;
}

/**
 * Reorder an array in reverse bit order of its indices.
 *
 * @remark Operates in-place on the array.
 * @remark Can handle arrays of any type: provide the element size in @p size.
 * @remark This means that input[n] == output[n'], where input and output
 *         denote the input and output array and n' is obtained from n by
 *         bit-reversing n. As opposed to reverse_bits, this bit-reversal
 *         operates on log2(@p n)-bit numbers.
 *
 * @param[in,out] values The array, which is re-ordered in-place
 * @param[in]     size   The size in bytes of an element of the array
 * @param[in]     n      The length of the array, must be a power of two
 *                       strictly greater than 1 and less than 2^32.
 */
static C_KZG_RET bit_reversal_permutation(
    void *values, size_t size, uint64_t n
) {
    CHECK(n != 0);
    CHECK(n >> 32 == 0);
    CHECK(is_power_of_two(n));
    CHECK(log2_pow2(n) != 0);

    /* copy pointer and convert from void* to byte* */
    byte *v = values;

    /* allocate scratch space for swapping an entry of the values array */
    byte *tmp = NULL;
    C_KZG_RET ret = c_kzg_malloc((void **)&tmp, size);
    if (ret != C_KZG_OK) {
        return ret;
    }

    int unused_bit_len = 32 - log2_pow2(n);
    for (uint32_t i = 0; i < n; i++) {
        uint32_t r = reverse_bits(i) >> unused_bit_len;
        if (r > i) {
            /* Swap the two elements */
            memcpy(tmp, v + (i * size), size);
            memcpy(v + (i * size), v + (r * size), size);
            memcpy(v + (r * size), tmp, size);
        }
    }
    c_kzg_free(tmp);

    return C_KZG_OK;
}

/**
 * Generate powers of a root of unity in the field.
 *
 * @remark @p root must be such that @p root ^ @p width is equal to one, but
 * no smaller power of @p root is equal to one.
 *
 * @param[out] out   The generated powers of the root of unity
 *                   (array size @p width + 1)
 * @param[in]  root  A root of unity
 * @param[in]  width One less than the size of @p out
 */
static C_KZG_RET expand_root_of_unity(
    fr_t *out, const fr_t *root, uint64_t width
) {
    uint64_t i;
    CHECK(width >= 2);
    out[0] = FR_ONE;
    out[1] = *root;

    for (i = 2; i <= width; i++) {
        blst_fr_mul(&out[i], &out[i - 1], root);
        if (fr_is_one(&out[i])) break;
    }
    CHECK(i == width);
    CHECK(fr_is_one(&out[width]));

    return C_KZG_OK;
}

/**
 * Initialize the roots of unity.
 *
 * @param[out]  s   Pointer to KZGSettings
 */
static C_KZG_RET compute_roots_of_unity(KZGSettings *s) {
    C_KZG_RET ret;
    fr_t root_of_unity;

    uint32_t max_scale = 0;
    while ((1ULL << max_scale) < s->max_width)
        max_scale++;

    /* Get the root of unity */
    CHECK(max_scale < NUM_ELEMENTS(SCALE2_ROOT_OF_UNITY));
    blst_fr_from_uint64(&root_of_unity, SCALE2_ROOT_OF_UNITY[max_scale]);

    /*
     * Allocate an array to store the expanded roots of unity. We do this
     * instead of re-using roots_of_unity_out because the expansion requires
     * max_width+1 elements.
     */
    ret = new_fr_array(&s->expanded_roots_of_unity, s->max_width + 1);
    if (ret != C_KZG_OK) goto out;

    /* Populate the roots of unity */
    ret = expand_root_of_unity(
        s->expanded_roots_of_unity, &root_of_unity, s->max_width
    );
    if (ret != C_KZG_OK) goto out;

    /* Copy all but the last root to the roots of unity */
    memcpy(
        s->roots_of_unity,
        s->expanded_roots_of_unity,
        sizeof(fr_t) * s->max_width
    );

    /* Permute the roots of unity */
    ret = bit_reversal_permutation(
        s->roots_of_unity, sizeof(fr_t), s->max_width
    );
    if (ret != C_KZG_OK) goto out;

    /* Populate reverse roots of unity */
    for (uint64_t i = 0; i <= s->max_width; i++) {
        s->reverse_roots_of_unity[i] =
            s->expanded_roots_of_unity[s->max_width - i];
    }

out:
    return ret;
}

/**
 * Free a trusted setup (KZGSettings).
 *
 * @remark It's a NOP if `s` is NULL.
 *
 * @param[in] s The trusted setup to free
 */
void free_trusted_setup(KZGSettings *s) {
    if (s == NULL) return;
    s->max_width = 0;
    c_kzg_free(s->roots_of_unity);
    c_kzg_free(s->expanded_roots_of_unity);
    c_kzg_free(s->reverse_roots_of_unity);
    c_kzg_free(s->g1_values);
    c_kzg_free(s->g1_values_lagrange);
    c_kzg_free(s->g2_values);
    for (size_t i = 0; i < SAMPLE_SIZE; i++) {
        c_kzg_free(s->x_ext_fft_files[i]);
    }
    c_kzg_free(s->x_ext_fft_files);
}

/* Forward function declaration */
static C_KZG_RET toeplitz_part_1(
    g1_t *out, const g1_t *x, uint64_t n, const KZGSettings *s
);

/**
 * Initialize fields for FK20 multi-proof computations.
 *
 * @param[out]  s   Pointer to KZGSettings to initialize
 */
static C_KZG_RET init_fk20_multi_settings(KZGSettings *s) {
    C_KZG_RET ret;
    uint64_t n, k;
    g1_t *x = NULL;

    n = s->max_width / 2;
    k = n / SAMPLE_SIZE;

    if (SAMPLE_SIZE >= TRUSTED_SETUP_NUM_G2_POINTS) {
        ret = C_KZG_BADARGS;
        goto out;
    }

    /* Allocate space for array of pointers, this is a 2D array */
    void **tmp = (void **)&s->x_ext_fft_files;
    ret = c_kzg_calloc(tmp, SAMPLE_SIZE, __SIZEOF_POINTER__);
    if (ret != C_KZG_OK) goto out;

    ret = new_g1_array(&x, k);
    if (ret != C_KZG_OK) goto out;

    for (uint64_t offset = 0; offset < SAMPLE_SIZE; offset++) {
        uint64_t start = n - SAMPLE_SIZE - 1 - offset;
        for (uint64_t i = 0, j = start; i + 1 < k; i++, j -= SAMPLE_SIZE) {
            x[i] = s->g1_values[j];
        }
        x[k - 1] = G1_IDENTITY;

        ret = new_g1_array(&s->x_ext_fft_files[offset], 2 * k);
        if (ret != C_KZG_OK) goto out;
        ret = toeplitz_part_1(s->x_ext_fft_files[offset], x, k, s);
        if (ret != C_KZG_OK) goto out;
    }

out:
    c_kzg_free(x);
    return ret;
}

/**
 * Basic sanity check that the trusted setup was loaded in Lagrange form.
 *
 * @param[in] s  Pointer to the stored trusted setup data
 * @param[in] n1 Number of `g1` points in trusted_setup
 * @param[in] n2 Number of `g2` points in trusted_setup
 */
static C_KZG_RET is_trusted_setup_in_lagrange_form(
    const KZGSettings *s, size_t n1, size_t n2
) {
    /* Trusted setup is too small; we can't work with this */
    if (n1 < 2 || n2 < 2) {
        return C_KZG_BADARGS;
    }

    /*
     * If the following pairing equation checks out:
     *     e(G1_SETUP[1], G2_SETUP[0]) ?= e(G1_SETUP[0], G2_SETUP[1])
     * then the trusted setup was loaded in monomial form.
     * If so, error out since we want the trusted setup in Lagrange form.
     */
    bool is_monomial_form = pairings_verify(
        &s->g1_values[1], &s->g2_values[0], &s->g1_values[0], &s->g2_values[1]
    );
    return is_monomial_form ? C_KZG_BADARGS : C_KZG_OK;
}

/**
 * Load trusted setup into a KZGSettings.
 *
 * @remark Free after use with free_trusted_setup().
 *
 * @param[out] out      Pointer to the stored trusted setup data
 * @param[in]  g1_bytes Array of G1 points in Lagrange form
 * @param[in]  n1       Number of `g1` points in g1_bytes
 * @param[in]  g2_bytes Array of G2 points in monomial form
 * @param[in]  n2       Number of `g2` points in g2_bytes
 */
C_KZG_RET load_trusted_setup(
    KZGSettings *out,
    const uint8_t *g1_bytes,
    size_t n1,
    const uint8_t *g2_bytes,
    size_t n2
) {
    C_KZG_RET ret;

    out->max_width = 0;
    out->roots_of_unity = NULL;
    out->expanded_roots_of_unity = NULL;
    out->reverse_roots_of_unity = NULL;
    out->g1_values = NULL;
    out->g1_values_lagrange = NULL;
    out->g2_values = NULL;
    out->x_ext_fft_files = NULL;

    /* Sanity check in case this is called directly */
    CHECK(n1 == TRUSTED_SETUP_NUM_G1_POINTS);
    CHECK(n2 == TRUSTED_SETUP_NUM_G2_POINTS);

    /* 1<<max_scale is the smallest power of 2 >= n1 */
    uint32_t max_scale = 0;
    while ((1ULL << max_scale) < n1)
        max_scale++;

    /* Set the max_width */
    out->max_width = 1ULL << max_scale;

    /* For DAS reconstruction */
    out->max_width *= 2;
    CHECK(out->max_width == DATA_POINTS_PER_BLOB);

    /* Allocate all of our arrays */
    ret = new_fr_array(&out->roots_of_unity, out->max_width);
    if (ret != C_KZG_OK) goto out_error;
    ret = new_fr_array(&out->expanded_roots_of_unity, out->max_width + 1);
    if (ret != C_KZG_OK) goto out_error;
    ret = new_fr_array(&out->reverse_roots_of_unity, out->max_width + 1);
    if (ret != C_KZG_OK) goto out_error;
    ret = new_g1_array(&out->g1_values, n1);
    if (ret != C_KZG_OK) goto out_error;
    ret = new_g1_array(&out->g1_values_lagrange, n1);
    if (ret != C_KZG_OK) goto out_error;
    ret = new_g2_array(&out->g2_values, n2);
    if (ret != C_KZG_OK) goto out_error;

    /* Convert all g1 bytes to g1 points */
    for (uint64_t i = 0; i < n1; i++) {
        blst_p1_affine g1_affine;
        BLST_ERROR err = blst_p1_uncompress(
            &g1_affine, &g1_bytes[BYTES_PER_G1 * i]
        );
        if (err != BLST_SUCCESS) {
            ret = C_KZG_BADARGS;
            goto out_error;
        }
        blst_p1_from_affine(&out->g1_values_lagrange[i], &g1_affine);

        /* Copying, will modify later */
        out->g1_values[i] = out->g1_values_lagrange[i];
    }

    /* Convert all g2 bytes to g2 points */
    for (uint64_t i = 0; i < n2; i++) {
        blst_p2_affine g2_affine;
        BLST_ERROR err = blst_p2_uncompress(
            &g2_affine, &g2_bytes[BYTES_PER_G2 * i]
        );
        if (err != BLST_SUCCESS) {
            ret = C_KZG_BADARGS;
            goto out_error;
        }
        blst_p2_from_affine(&out->g2_values[i], &g2_affine);
    }

    /* Make sure the trusted setup was loaded in Lagrange form */
    ret = is_trusted_setup_in_lagrange_form(out, n1, n2);
    if (ret != C_KZG_OK) goto out_error;

    /* Compute roots of unity and permute the G1 trusted setup */
    ret = compute_roots_of_unity(out);
    if (ret != C_KZG_OK) goto out_error;

    /* Get monomial, non-bit-reversed form */
    ret = fft_g1(out->g1_values, out->g1_values_lagrange, n1, out);
    if (ret != C_KZG_OK) goto out_error;

    /* Bit reverse the Lagrange form points */
    ret = bit_reversal_permutation(out->g1_values_lagrange, sizeof(g1_t), n1);
    if (ret != C_KZG_OK) goto out_error;

    /* Stuff for sample proofs */
    ret = init_fk20_multi_settings(out);
    if (ret != C_KZG_OK) goto out_error;

    goto out_success;

out_error:
    /*
     * Note: this only frees the fields in the KZGSettings structure. It does
     * not free the KZGSettings structure memory. If necessary, that must be
     * done by the caller.
     */
    free_trusted_setup(out);
out_success:
    return ret;
}

/**
 * Load trusted setup from a file.
 *
 * @remark The file format is `n1 n2 g1_1 g1_2 ... g1_n1 g2_1 ... g2_n2` where
 *     the first two numbers are in decimal and the remainder are hexstrings
 *     and any whitespace can be used as separators.
 *
 * @remark See also load_trusted_setup().
 * @remark The input file will not be closed.
 *
 * @param[out] out Pointer to the loaded trusted setup data
 * @param[in]  in  File handle for input
 */
C_KZG_RET load_trusted_setup_file(KZGSettings *out, FILE *in) {
    int num_matches;
    uint64_t i;
    uint8_t g1_bytes[TRUSTED_SETUP_NUM_G1_POINTS * BYTES_PER_G1];
    uint8_t g2_bytes[TRUSTED_SETUP_NUM_G2_POINTS * BYTES_PER_G2];

    /* Read the number of g1 points */
    num_matches = fscanf(in, "%" SCNu64, &i);
    CHECK(num_matches == 1);
    CHECK(i == TRUSTED_SETUP_NUM_G1_POINTS);

    /* Read the number of g2 points */
    num_matches = fscanf(in, "%" SCNu64, &i);
    CHECK(num_matches == 1);
    CHECK(i == TRUSTED_SETUP_NUM_G2_POINTS);

    /* Read all of the g1 points, byte by byte */
    for (i = 0; i < TRUSTED_SETUP_NUM_G1_POINTS * BYTES_PER_G1; i++) {
        num_matches = fscanf(in, "%2hhx", &g1_bytes[i]);
        CHECK(num_matches == 1);
    }

    /* Read all of the g2 points, byte by byte */
    for (i = 0; i < TRUSTED_SETUP_NUM_G2_POINTS * BYTES_PER_G2; i++) {
        num_matches = fscanf(in, "%2hhx", &g2_bytes[i]);
        CHECK(num_matches == 1);
    }

    return load_trusted_setup(
        out,
        g1_bytes,
        TRUSTED_SETUP_NUM_G1_POINTS,
        g2_bytes,
        TRUSTED_SETUP_NUM_G2_POINTS
    );
}

///////////////////////////////////////////////////////////////////////////////
// Fast Fourier Transform
///////////////////////////////////////////////////////////////////////////////

/**
 * Fast Fourier Transform.
 *
 * Recursively divide and conquer.
 *
 * @param[out] out    The results (array of length @p n)
 * @param[in]  in     The input data (array of length @p n * @p stride)
 * @param[in]  stride The input data stride
 * @param[in]  roots  Roots of unity (array of length @p n * @p roots_stride)
 * @param[in]  roots_stride The stride interval among the roots of unity
 * @param[in]  n      Length of the FFT, must be a power of two
 */
static void fft_fr_fast(
    fr_t *out,
    const fr_t *in,
    size_t stride,
    const fr_t *roots,
    size_t roots_stride,
    size_t n
) {
    size_t half = n / 2;
    if (half > 0) { // Tunable parameter
        fr_t y_times_root;
        fft_fr_fast(out, in, stride * 2, roots, roots_stride * 2, half);
        fft_fr_fast(
            out + half, in + stride, stride * 2, roots, roots_stride * 2, half
        );
        for (size_t i = 0; i < half; i++) {
            blst_fr_mul(
                &y_times_root, &out[i + half], &roots[i * roots_stride]
            );
            blst_fr_sub(&out[i + half], &out[i], &y_times_root);
            blst_fr_add(&out[i], &out[i], &y_times_root);
        }
    } else {
        *out = *in;
    }
}

/**
 * The entry point for forward FFT over field elements.
 *
 * @param[out]  out     The results (array of length n)
 * @param[in]   in      The input data (array of length n)
 * @param[in]   n       Length of the arrays
 * @param[in]   s       The trusted setup
 *
 * @remark The array lengths must be a power of two.
 * @remark Use ifft_fr for inverse transformation.
 */
static C_KZG_RET fft_fr(
    fr_t *out, const fr_t *in, size_t n, const KZGSettings *s
) {
    CHECK(n <= s->max_width);
    CHECK(is_power_of_two(n));

    size_t stride = s->max_width / n;
    fft_fr_fast(out, in, 1, s->expanded_roots_of_unity, stride, n);

    return C_KZG_OK;
}

/**
 * The entry point for inverse FFT over field elements.
 *
 * @param[out]  out The results (array of length n)
 * @param[in]   in  The input data (array of length n)
 * @param[in]   n   Length of the arrays
 * @param[in]   s   The trusted setup
 *
 * @remark The array lengths must be a power of two.
 * @remark Use fft_fr for forward transformation.
 */
static C_KZG_RET ifft_fr(
    fr_t *out, const fr_t *in, size_t n, const KZGSettings *s
) {
    CHECK(n <= s->max_width);
    CHECK(is_power_of_two(n));

    size_t stride = s->max_width / n;
    fft_fr_fast(out, in, 1, s->reverse_roots_of_unity, stride, n);

    fr_t inv_len;
    fr_from_uint64(&inv_len, n);
    blst_fr_inverse(&inv_len, &inv_len);
    for (size_t i = 0; i < n; i++) {
        blst_fr_mul(&out[i], &out[i], &inv_len);
    }
    return C_KZG_OK;
}

///////////////////////////////////////////////////////////////////////////////
// Zero poly
///////////////////////////////////////////////////////////////////////////////

typedef struct {
    fr_t *coeffs;
    size_t length;
} poly_t;

static C_KZG_RET new_poly(poly_t *out, uint64_t length) {
    out->length = length;
    return new_fr_array(&out->coeffs, length);
}

static void free_poly(poly_t *p) {
    if (p->coeffs != NULL) {
        c_kzg_free(p->coeffs);
    }
}

/**
 * Return the next highest power of two.
 *
 * @param[in]   v   A 64-bit unsigned integer <= 2^31
 * @return The lowest power of two equal or larger than @p v
 *
 * @remark If v is already a power of two, it is returned as-is.
 */
static inline uint64_t next_power_of_two(uint64_t v) {
    if (v == 0) return 1;
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v |= v >> 32;
    v++;
    return v;
}

/**
 * Calculates the minimal polynomial that evaluates to zero for powers of roots
 * of unity at the given indices.
 *
 * Uses straightforward long multiplication to calculate the product of `(x -
 * r^i)` where `r` is a root of unity and the `i`s are the indices at which it
 * must evaluate to zero. This results in a polynomial of degree @p len_indices.
 *
 * @param[in,out] dst      The zero polynomial for @p indices. The space
 * allocated for coefficients must be at least @p len_indices + 1, as indicated
 * by the `length` value on entry.
 * @param[in]  indices     Array of missing indices of length @p len_indices
 * @param[in]  len_indices Length of the missing indices array, @p indices
 * @param[in]  stride      Stride length through the powers of the root of unity
 * @param[in]   s           The trusted setup
 */
static C_KZG_RET do_zero_poly_mul_partial(
    fr_t *dst,
    size_t *dst_len,
    const uint64_t *indices,
    uint64_t len_indices,
    uint64_t stride,
    const KZGSettings *s
) {
    if (len_indices == 0) {
        return C_KZG_BADARGS;
    }

    blst_fr_cneg(
        &dst[0], &s->expanded_roots_of_unity[indices[0] * stride], true
    );

    for (size_t i = 1; i < len_indices; i++) {
        fr_t neg_di;
        blst_fr_cneg(
            &neg_di, &s->expanded_roots_of_unity[indices[i] * stride], true
        );
        dst[i] = neg_di;
        blst_fr_add(&dst[i], &dst[i], &dst[i - 1]);
        for (size_t j = i - 1; j > 0; j--) {
            blst_fr_mul(&dst[j], &dst[j], &neg_di);
            blst_fr_add(&dst[j], &dst[j], &dst[j - 1]);
        }
        blst_fr_mul(&dst[0], &dst[0], &neg_di);
    }

    dst[len_indices] = FR_ONE;
    for (size_t i = len_indices + 1; i < *dst_len; i++) {
        dst[i] = FR_ZERO;
    }
    *dst_len = len_indices + 1;

    return C_KZG_OK;
}

/**
 * Copy polynomial and set remaining fields to zero.
 *
 * @param[out]  out     The output polynomial with padded zeros
 * @param[out]  out_len The length of the output polynomial
 * @param[in]   in      The input polynomial to be copied
 * @param[in]   out_len The length of the input polynomial
 */
static C_KZG_RET pad_p(
    fr_t *out, size_t out_len, const fr_t *in, size_t in_len
) {
    /* Ensure out is big enough */
    if (out_len < in_len) {
        return C_KZG_BADARGS;
    }

    /* Copy polynomial fields */
    for (size_t i = 0; i < in_len; i++) {
        out[i] = in[i];
    }

    /* Set remaining fields to zero */
    for (size_t i = in_len; i < out_len; i++) {
        out[i] = FR_ZERO;
    }

    return C_KZG_OK;
}

/**
 * Calculate the product of the input polynomials via convolution.
 *
 * Pad the polynomials in @p ps, perform FFTs, point-wise multiply the results
 * together, and apply an inverse FFT to the result.
 *
 * @param[out] out         Polynomial with @p len_out space allocated. The
 * length will be set on return.
 * @param[in]  len_out     Length of the domain of evaluation, a power of two
 * @param      scratch     Scratch space of size at least 3 times the @p len_out
 * @param[in]  len_scratch Length of @p scratch, at least 3 times @p len_out
 * @param[in]  partials    Array of polynomials to be multiplied together
 * @param[in]  partial_count The number of polynomials to be multiplied together
 * @param[in]   s           The trusted setup
 */
static C_KZG_RET reduce_partials(
    poly_t *out,
    uint64_t len_out,
    fr_t *scratch,
    uint64_t len_scratch,
    const poly_t *partials,
    uint64_t partial_count,
    const KZGSettings *s
) {
    C_KZG_RET ret;

    CHECK(is_power_of_two(len_out));
    CHECK(len_scratch >= 3 * len_out);
    CHECK(partial_count > 0);

    // The degree of the output polynomial is the sum of the degrees of the
    // input polynomials.
    uint64_t out_degree = 0;
    for (size_t i = 0; i < partial_count; i++) {
        out_degree += partials[i].length - 1;
    }
    CHECK(out_degree + 1 <= len_out);

    // Split `scratch` up into three equally sized working arrays
    fr_t *p_padded = scratch;
    fr_t *mul_eval_ps = scratch + len_out;
    fr_t *p_eval = scratch + 2 * len_out;

    // Do the last partial first: it is no longer than the others and the
    // padding can remain in place for the rest.
    ret = pad_p(
        p_padded,
        len_out,
        partials[partial_count - 1].coeffs,
        partials[partial_count - 1].length
    );
    if (ret != C_KZG_OK) goto out;
    ret = fft_fr(mul_eval_ps, p_padded, len_out, s);
    if (ret != C_KZG_OK) goto out;

    for (uint64_t i = 0; i < partial_count - 1; i++) {
        ret = pad_p(
            p_padded, partials[i].length, partials[i].coeffs, partials[i].length
        );
        if (ret != C_KZG_OK) goto out;
        ret = fft_fr(p_eval, p_padded, len_out, s);
        if (ret != C_KZG_OK) goto out;
        for (uint64_t j = 0; j < len_out; j++) {
            blst_fr_mul(&mul_eval_ps[j], &mul_eval_ps[j], &p_eval[j]);
        }
    }

    ret = ifft_fr(out->coeffs, mul_eval_ps, len_out, s);
    if (ret != C_KZG_OK) goto out;

    out->length = out_degree + 1;

out:
    return ret;
}

/**
 * Calculate the minimal polynomial that evaluates to zero for powers of roots
 * of unity that correspond to missing indices.
 *
 * This is done simply by multiplying together `(x - r^i)` for all the `i` that
 * are missing indices, using a combination of direct multiplication
 * (#do_zero_poly_mul_partial) and iterated multiplication via convolution
 * (#reduce_partials).
 *
 * Also calculates the FFT (the "evaluation polynomial").
 *
 * @remark This fails when all the indices in our domain are missing (@p
 * len_missing == @p length), since the resulting polynomial exceeds the size
 * allocated. But we know that the answer is `x^length - 1` in that case if we
 * ever need it.
 *
 * @param[out] zero_eval The "evaluation polynomial": the coefficients are the
 * values of @p zero_poly for each power of `r`. Space required is @p length.
 * @param[out] zero_poly The zero polynomial. On return the length will be set
 * to `len_missing + 1` and the remaining coefficients set to zero.  Space
 * required is @p length.
 * @param[in]  length    Size of the domain of evaluation (number of powers of
 * `r`)
 * @param[in]  missing_indices Array length @p len_missing containing the
 * indices of the missing coefficients
 * @param[in]  len_missing     Length of @p missing_indices
 * @param[in]   s           The trusted setup
 *
 * @todo What is the performance impact of tuning `degree_of_partial` and
 * `reduction factor`?
 */
static C_KZG_RET zero_polynomial_via_multiplication(
    fr_t *zero_eval,
    poly_t *zero_poly,
    uint64_t length,
    const uint64_t *missing_indices,
    uint64_t len_missing,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    if (len_missing == 0) {
        zero_poly->length = 0;
        for (uint64_t i = 0; i < length; i++) {
            zero_eval[i] = FR_ZERO;
            zero_poly->coeffs[i] = FR_ZERO;
        }
        return C_KZG_OK;
    }
    CHECK(len_missing < length);
    CHECK(length <= s->max_width);
    CHECK(is_power_of_two(length));

    // Tunable parameter. Must be a power of two.
    uint64_t degree_of_partial = 32;
    uint64_t missing_per_partial = degree_of_partial - 1;
    uint64_t domain_stride = s->max_width / length;
    uint64_t partial_count = (len_missing + missing_per_partial - 1) /
                             missing_per_partial;
    uint64_t n = min(
        next_power_of_two(partial_count * degree_of_partial), length
    );

    if (len_missing <= missing_per_partial) {
        ret = do_zero_poly_mul_partial(
            zero_poly->coeffs,
            &zero_poly->length,
            missing_indices,
            len_missing,
            domain_stride,
            s
        );
        if (ret != C_KZG_OK) goto out;
        ret = fft_fr(zero_eval, zero_poly->coeffs, length, s);
        if (ret != C_KZG_OK) goto out;
    } else {

        // Work space for building and reducing the partials
        fr_t *work;
        ret = new_fr_array(
            &work, next_power_of_two(partial_count * degree_of_partial)
        );
        if (ret != C_KZG_OK) goto out;

        // Build the partials from the missing indices

        // Just allocate pointers here since we're re-using `work` for the
        // partial processing Combining partials can be done mostly in-place,
        // using a scratchpad.
        poly_t *partials;
        ret = c_kzg_calloc((void **)&partials, partial_count, sizeof(poly_t));
        if (ret != C_KZG_OK) goto out;

        uint64_t offset = 0, out_offset = 0, max = len_missing;
        for (size_t i = 0; i < partial_count; i++) {
            uint64_t end = min(offset + missing_per_partial, max);
            partials[i].coeffs = &work[out_offset];
            partials[i].length = degree_of_partial;
            do_zero_poly_mul_partial(
                partials[i].coeffs,
                &partials[i].length,
                &missing_indices[offset],
                end - offset,
                domain_stride,
                s
            );
            if (ret != C_KZG_OK) goto out;
            offset += missing_per_partial;
            out_offset += degree_of_partial;
        }
        // Adjust the length of the last partial
        partials[partial_count - 1].length = 1 + len_missing -
                                             (partial_count - 1) *
                                                 missing_per_partial;

        // Reduce all the partials to a single polynomial
        int reduction_factor =
            4; // must be a power of 2 (for sake of the FFTs in reduce_partials)
        fr_t *scratch;
        new_fr_array(&scratch, n * 3);
        if (ret != C_KZG_OK) goto out;

        while (partial_count > 1) {
            uint64_t reduced_count = (partial_count + reduction_factor - 1) /
                                     reduction_factor;
            uint64_t partial_size = next_power_of_two(partials[0].length);
            for (uint64_t i = 0; i < reduced_count; i++) {
                uint64_t start = i * reduction_factor;
                uint64_t out_end = min(
                    (start + reduction_factor) * partial_size, n
                );
                uint64_t reduced_len = min(
                    out_end - start * partial_size, length
                );
                uint64_t partials_num = min(
                    reduction_factor, partial_count - start
                );
                partials[i].coeffs = work + start * partial_size;
                if (partials_num > 1) {
                    reduce_partials(
                        &partials[i],
                        reduced_len,
                        scratch,
                        n * 3,
                        &partials[start],
                        partials_num,
                        s
                    );
                    if (ret != C_KZG_OK) goto out;
                } else {
                    partials[i].length = partials[start].length;
                }
            }
            partial_count = reduced_count;
        }

        // Process final output
        ret = pad_p(
            zero_poly->coeffs, length, partials[0].coeffs, partials[0].length
        );
        if (ret != C_KZG_OK) goto out;
        ret = fft_fr(zero_eval, zero_poly->coeffs, length, s);
        if (ret != C_KZG_OK) goto out;

        zero_poly->length = partials[0].length;

        c_kzg_free(work);
        c_kzg_free(partials);
        c_kzg_free(scratch);
    }

out:
    return C_KZG_OK;
}

///////////////////////////////////////////////////////////////////////////////
// Sample Recovery
///////////////////////////////////////////////////////////////////////////////

/**
 * Currently five. This is a primitive element, but actually this can be pretty
 * much anything not zero or a low-degree root of unity.
 */
static const fr_t SCALE_FACTOR = {
    0x0000000afffffff5L,
    0x66d9f3df00120c0bL,
    0xcc83b7a7960bb7c5L,
    0x04c9cf6d363b9de5L
};
static const fr_t INV_SCALE_FACTOR = {
    0x0000000066666666L,
    0x11b424cb999a419aL,
    0x51e8dcc995bf4331L,
    0x04d4237855c10116L
};

/**
 * Scale a polynomial in place.
 *
 * Multiplies each coefficient by `1 / scale_factor ^ i`. Equivalent to
 * creating a polynomial that evaluates at `x * k` rather than `x`.
 *
 * @param[out,in]   p       The polynomial coefficients to be scaled
 * @param[in]       len_p   Length of the polynomial coefficients
 */
static void scale_poly(fr_t *p, uint64_t len_p) {
    fr_t factor_power = FR_ONE;
    for (uint64_t i = 1; i < len_p; i++) {
        blst_fr_mul(&factor_power, &factor_power, &INV_SCALE_FACTOR);
        blst_fr_mul(&p[i], &p[i], &factor_power);
    }
}

/**
 * Unscale a polynomial in place.
 *
 * Multiplies each coefficient by `scale_factor ^ i`. Equivalent to creating a
 * polynomial that evaluates at `x / k` rather than `x`.
 *
 * @param[out,in]   p       The polynomial coefficients to be unscaled
 * @param[in]       len_p   Length of the polynomial coefficients
 */
static void unscale_poly(fr_t *p, uint64_t len_p) {
    fr_t factor_power = FR_ONE;
    for (uint64_t i = 1; i < len_p; i++) {
        blst_fr_mul(&factor_power, &factor_power, &SCALE_FACTOR);
        blst_fr_mul(&p[i], &p[i], &factor_power);
    }
}

/**
 * Given a dataset with up to half the entries missing, return the
 * reconstructed original. Assumes that the inverse FFT of the original data
 * has the upper half of its values equal to zero.
 *
 * @param[out]  recovered   A preallocated array for recovered samples
 * @param[in]   samples     The samples that you have
 * @param[in]   s           The trusted setup
 *
 * @remark `recovered` and `samples` can point to the same memory.
 * @remark The array of samples must be 2n length and in the correct order.
 * @remark Missing samples should be equal to FR_NULL.
 */
static C_KZG_RET recover_samples_impl(
    fr_t *recovered, fr_t *samples, const KZGSettings *s
) {
    C_KZG_RET ret;
    uint64_t *missing = NULL;
    fr_t *zero_eval = NULL;
    fr_t *poly_evaluations_with_zero = NULL;
    fr_t *poly_with_zero = NULL;
    fr_t *eval_scaled_poly_with_zero = NULL;
    fr_t *eval_scaled_zero_poly = NULL;
    fr_t *scaled_reconstructed_poly = NULL;
    fr_t *samples_brp = NULL;

    poly_t zero_poly = {NULL, 0};
    zero_poly.coeffs = NULL;

    /* Allocate space for arrays */
    ret = c_kzg_calloc((void **)&missing, s->max_width, sizeof(uint64_t));
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&zero_eval, s->max_width);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&poly_evaluations_with_zero, s->max_width);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&poly_with_zero, s->max_width);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&eval_scaled_poly_with_zero, s->max_width);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&eval_scaled_zero_poly, s->max_width);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&scaled_reconstructed_poly, s->max_width);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&samples_brp, s->max_width);
    if (ret != C_KZG_OK) goto out;

    /* Allocate space for the zero poly */
    ret = new_fr_array(&zero_poly.coeffs, s->max_width);
    if (ret != C_KZG_OK) goto out;
    zero_poly.length = s->max_width;

    /* Bit-reverse the data points */
    memcpy(samples_brp, samples, s->max_width * sizeof(fr_t));
    ret = bit_reversal_permutation(
        samples_brp, sizeof(samples_brp[0]), s->max_width
    );
    if (ret != C_KZG_OK) goto out;

    /* Identify missing samples */
    uint64_t len_missing = 0;
    for (uint64_t i = 0; i < s->max_width; i++) {
        if (fr_is_null(&samples_brp[i])) {
            missing[len_missing++] = i;
        }
    }

    /* Check that we have enough samples */
    if (len_missing > s->max_width / 2) {
        ret = C_KZG_BADARGS;
        goto out;
    }

    // Calculate `Z_r,I`
    ret = zero_polynomial_via_multiplication(
        zero_eval, &zero_poly, s->max_width, missing, len_missing, s
    );
    if (ret != C_KZG_OK) goto out;

    // Construct E * Z_r,I: the loop makes the evaluation polynomial
    for (size_t i = 0; i < s->max_width; i++) {
        if (fr_is_null(&samples_brp[i])) {
            poly_evaluations_with_zero[i] = FR_ZERO;
        } else {
            blst_fr_mul(
                &poly_evaluations_with_zero[i], &samples_brp[i], &zero_eval[i]
            );
        }
    }

    // Now inverse FFT so that poly_with_zero is (E * Z_r,I)(x) = (D * Z_r,I)(x)
    ret = ifft_fr(poly_with_zero, poly_evaluations_with_zero, s->max_width, s);
    if (ret != C_KZG_OK) goto out;

    // x -> k * x
    scale_poly(poly_with_zero, s->max_width);
    scale_poly(zero_poly.coeffs, zero_poly.length);

    // Q1 = (D * Z_r,I)(k * x)
    fr_t *scaled_poly_with_zero = poly_with_zero; // Renaming
    // Q2 = Z_r,I(k * x)
    fr_t *scaled_zero_poly = zero_poly.coeffs; // Renaming

    // Polynomial division by convolution: Q3 = Q1 / Q2
    ret = fft_fr(
        eval_scaled_poly_with_zero, scaled_poly_with_zero, s->max_width, s
    );
    if (ret != C_KZG_OK) goto out;

    ret = fft_fr(eval_scaled_zero_poly, scaled_zero_poly, s->max_width, s);
    if (ret != C_KZG_OK) goto out;

    fr_t *eval_scaled_reconstructed_poly = eval_scaled_poly_with_zero;
    for (uint64_t i = 0; i < s->max_width; i++) {
        fr_div(
            &eval_scaled_reconstructed_poly[i],
            &eval_scaled_poly_with_zero[i],
            &eval_scaled_zero_poly[i]
        );
    }

    // The result of the division is D(k * x):
    ret = ifft_fr(
        scaled_reconstructed_poly,
        eval_scaled_reconstructed_poly,
        s->max_width,
        s
    );
    if (ret != C_KZG_OK) goto out;

    // k * x -> x
    unscale_poly(scaled_reconstructed_poly, s->max_width);

    // Finally we have D(x) which evaluates to our original data at the powers
    // of roots of unity
    fr_t *reconstructed_poly = scaled_reconstructed_poly; // Renaming

    // The evaluation polynomial for D(x) is the reconstructed data:
    ret = fft_fr(recovered, reconstructed_poly, s->max_width, s);
    if (ret != C_KZG_OK) goto out;

    /* Bit-reverse the recovered data points */
    ret = bit_reversal_permutation(
        recovered, sizeof(recovered[0]), s->max_width
    );
    if (ret != C_KZG_OK) goto out;

out:
    c_kzg_free(missing);
    c_kzg_free(zero_eval);
    c_kzg_free(poly_evaluations_with_zero);
    c_kzg_free(poly_with_zero);
    c_kzg_free(eval_scaled_poly_with_zero);
    c_kzg_free(eval_scaled_zero_poly);
    c_kzg_free(scaled_reconstructed_poly);
    c_kzg_free(zero_poly.coeffs);
    c_kzg_free(samples_brp);
    return ret;
}

///////////////////////////////////////////////////////////////////////////////
// Polynomial Conversion Functions
///////////////////////////////////////////////////////////////////////////////

C_KZG_RET poly_monomial_to_lagrange(
    fr_t *monomial, const fr_t *lagrange, size_t len, const KZGSettings *s
) {
    C_KZG_RET ret;

    ret = fft_fr(monomial, lagrange, len, s);
    if (ret != C_KZG_OK) goto out;
    ret = bit_reversal_permutation(monomial, sizeof(fr_t), len);
    if (ret != C_KZG_OK) goto out;

out:
    return ret;
}

C_KZG_RET poly_lagrange_to_monomial(
    fr_t *lagrange, const fr_t *monomial, size_t len, const KZGSettings *s
) {
    C_KZG_RET ret;
    fr_t *monomial_brp = NULL;

    ret = new_fr_array(&monomial_brp, len);
    if (ret != C_KZG_OK) goto out;

    memcpy(monomial_brp, monomial, sizeof(fr_t) * len);

    ret = bit_reversal_permutation(monomial_brp, sizeof(fr_t), len);
    if (ret != C_KZG_OK) goto out;
    ret = ifft_fr(lagrange, monomial_brp, len, s);
    if (ret != C_KZG_OK) goto out;

out:
    return ret;
}

///////////////////////////////////////////////////////////////////////////////
// Sample Proofs
///////////////////////////////////////////////////////////////////////////////

/**
 * The first part of the Toeplitz matrix multiplication algorithm: the Fourier
 * transform of the vector @p x extended.
 *
 * @param[out] out The FFT of the extension of @p x, size @p n * 2
 * @param[in]  x   The input vector, size @p n
 * @param[in]  n   The length of the input vector @p x
 * @param[in]  fs  The FFT settings previously initialised with
 * #new_fft_settings
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_ERROR   An internal error occurred
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
static C_KZG_RET toeplitz_part_1(
    g1_t *out, const g1_t *x, uint64_t n, const KZGSettings *s
) {
    C_KZG_RET ret;
    uint64_t n2 = n * 2;
    g1_t *x_ext;

    ret = new_g1_array(&x_ext, n2);
    if (ret != C_KZG_OK) goto out;

    for (uint64_t i = 0; i < n; i++) {
        x_ext[i] = x[i];
    }
    for (uint64_t i = n; i < n2; i++) {
        x_ext[i] = G1_IDENTITY;
    }

    ret = fft_g1(out, x_ext, n2, s);
    if (ret != C_KZG_OK) goto out;

out:
    c_kzg_free(x_ext);
    return ret;
}

/**
 * The second part of the Toeplitz matrix multiplication algorithm.
 *
 * @param[out] out Array of G1 group elements, length `n`
 * @param[in]  toeplitz_coeffs Toeplitz coefficients, a polynomial length `n`
 * @param[in]  x_ext_fft The Fourier transform of the extended `x` vector,
 * length `n`
 * @param[in]  fs  The FFT settings previously initialised with
 * #new_fft_settings
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_ERROR   An internal error occurred
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
static C_KZG_RET toeplitz_part_2(
    g1_t *out,
    const poly_t *toeplitz_coeffs,
    const g1_t *x_ext_fft,
    const KZGSettings *fs
) {
    C_KZG_RET ret;

    fr_t *toeplitz_coeffs_fft;

    // CHECK(toeplitz_coeffs->length == fk->x_ext_fft_len); // TODO: how to
    // implement?

    ret = new_fr_array(&toeplitz_coeffs_fft, toeplitz_coeffs->length);
    if (ret != C_KZG_OK) goto out;

    ret = fft_fr(
        toeplitz_coeffs_fft,
        toeplitz_coeffs->coeffs,
        toeplitz_coeffs->length,
        fs
    );
    if (ret != C_KZG_OK) goto out;

    for (uint64_t i = 0; i < toeplitz_coeffs->length; i++) {
        g1_mul(&out[i], &x_ext_fft[i], &toeplitz_coeffs_fft[i]);
    }

out:
    c_kzg_free(toeplitz_coeffs_fft);
    return ret;
}

/**
 * The third part of the Toeplitz matrix multiplication algorithm: transform
 * back and zero the top half.
 *
 * @param[out] out Array of G1 group elements, length @p n2
 * @param[in]  h_ext_fft FFT of the extended `h` values, length @p n2
 * @param[in]  n2  Size of the arrays
 * @param[in]  fs  The FFT settings previously initialised with
 * #new_fft_settings
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_ERROR   An internal error occurred
 */
static C_KZG_RET toeplitz_part_3(
    g1_t *out, const g1_t *h_ext_fft, uint64_t n2, const KZGSettings *fs
) {
    C_KZG_RET ret;
    uint64_t n = n2 / 2;

    ret = ifft_g1(out, h_ext_fft, n2, fs);
    if (ret != C_KZG_OK) goto out;

    // Zero the second half of h
    for (uint64_t i = n; i < n2; i++) {
        out[i] = G1_IDENTITY;
    }

out:
    return ret;
}

/**
 * Reorder and extend polynomial coefficients for the toeplitz method, strided
 * version.
 *
 * @remark The upper half of the input polynomial coefficients is treated as
 * being zero.
 *
 * @param[out] out The reordered polynomial, size `n * 2 / stride`
 * @param[in]  in  The input polynomial, size `n`
 * @param[in]  offset The offset
 * @param[in]  stride The stride
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
static C_KZG_RET toeplitz_coeffs_stride(
    poly_t *out, const poly_t *in, uint64_t offset, uint64_t stride
) {
    uint64_t n = in->length, k, k2;

    CHECK(stride > 0);

    k = n / stride;
    k2 = k * 2;

    CHECK(out->length >= k2);

    out->coeffs[0] = in->coeffs[n - 1 - offset];
    for (uint64_t i = 1; i <= k + 1 && i < k2; i++) {
        out->coeffs[i] = FR_ZERO;
    }
    for (uint64_t i = k + 2, j = 2 * stride - offset - 1; i < k2;
         i++, j += stride) {
        out->coeffs[i] = in->coeffs[j];
    }

    return C_KZG_OK;
}

/**
 * FK20 multi-proof method, optimized for data availability where the top half
 * of polynomial coefficients is zero.
 *
 * @remark Only the lower half of the polynomial is supplied; the upper, zero,
 * half is assumed. The #toeplitz_coeffs_stride routine does the right thing.
 *
 * @param[out] out The proofs, array size `2 * n / s->chunk_length`
 * @param[in]  p   The polynomial, length `n`
 * @param[in]  s  FK20 multi settings previously initialised by
 * #new_fk20_multi_settings
 */
static C_KZG_RET fk20_multi_da_opt(
    g1_t *out, const poly_t *p, const KZGSettings *s
) {
    C_KZG_RET ret;
    uint64_t n = p->length, n2 = n * 2, k, k2;
    g1_t *h_ext_fft = NULL, *h_ext_fft_file = NULL, *h = NULL;
    poly_t toeplitz_coeffs = {NULL, 0};

    CHECK(n2 <= s->max_width);
    CHECK(is_power_of_two(n));

    n = n2 / 2;
    k = n / SAMPLE_SIZE;
    k2 = k * 2;

    ret = new_g1_array(&h_ext_fft, k2);
    if (ret != C_KZG_OK) goto out;
    for (uint64_t i = 0; i < k2; i++) {
        h_ext_fft[i] = G1_IDENTITY;
    }

    ret = new_poly(&toeplitz_coeffs, n2 / SAMPLE_SIZE);
    if (ret != C_KZG_OK) goto out;
    ret = new_g1_array(&h_ext_fft_file, toeplitz_coeffs.length);
    if (ret != C_KZG_OK) goto out;
    for (uint64_t i = 0; i < SAMPLE_SIZE; i++) {
        ret = toeplitz_coeffs_stride(&toeplitz_coeffs, p, i, SAMPLE_SIZE);
        if (ret != C_KZG_OK) goto out;
        ret = toeplitz_part_2(
            h_ext_fft_file, &toeplitz_coeffs, s->x_ext_fft_files[i], s
        );
        if (ret != C_KZG_OK) goto out;

        for (uint64_t j = 0; j < k2; j++) {
            blst_p1_add_or_double(
                &h_ext_fft[j], &h_ext_fft[j], &h_ext_fft_file[j]
            );
        }
    }

    // Calculate `h`
    ret = new_g1_array(&h, k2);
    if (ret != C_KZG_OK) goto out;
    ret = toeplitz_part_3(h, h_ext_fft, k2, s);
    if (ret != C_KZG_OK) goto out;

    // Overwrite the second half of `h` with zero
    for (uint64_t i = k; i < k2; i++) {
        h[i] = G1_IDENTITY;
    }

    ret = fft_g1(out, h, k2, s);
    if (ret != C_KZG_OK) goto out;

out:
    free_poly(&toeplitz_coeffs);
    c_kzg_free(h_ext_fft_file);
    c_kzg_free(h_ext_fft);
    c_kzg_free(h);
    return ret;
}

/**
 * Computes all the KZG proofs for data availability checks. This involves
 * sampling on the double domain and reordering according to reverse bit order.
 */
static C_KZG_RET da_using_fk20_multi(
    g1_t *out, const poly_t *p, const KZGSettings *s
) {
    C_KZG_RET ret;

    ret = fk20_multi_da_opt(out, p, s);
    if (ret != C_KZG_OK) goto out;
    ret = bit_reversal_permutation(out, sizeof out[0], SAMPLES_PER_BLOB);
    if (ret != C_KZG_OK) goto out;

out:
    return ret;
}

/**
 * Check a proof for a KZG commitment for evaluations `f(x * w^i) = y_i`.
 *
 * Given a @p commitment to a polynomial, a @p proof for @p x, and the claimed
 * values @p y at values @p x `* w^i`, verify the claim. Here, `w` is an `n`th
 * root of unity.
 *
 * @param[out] out        `true` if the proof is valid, `false` if not
 * @param[in]  commitment The commitment to a polynomial
 * @param[in]  proof      A proof of the value of the polynomial at the points
 * @p x * w^i
 * @param[in]  x          The generator x-value for the evaluation points
 * @param[in]  ys         The claimed value of the polynomial at the points @p x
 * * w^i
 * @param[in]  n          The number of points at which to evaluate the
 * polynomial, must be a power of two
 * @param[in]  ks         The settings containing the secrets, previously
 * initialised with #new_kzg_settings
 */
static C_KZG_RET verify_kzg_proof_multi_impl(
    bool *out,
    const g1_t *commitment,
    const g1_t *proof,
    const fr_t *x,
    const fr_t *ys,
    size_t n,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    poly_t interp = {NULL, 0};
    fr_t inv_x, inv_x_pow, x_pow;
    g2_t xn2, xn_minus_yn;
    g1_t is1, commit_minus_interp;

    CHECK(is_power_of_two(n));

    // Interpolate at a coset.
    ret = new_poly(&interp, n);
    if (ret != C_KZG_OK) goto out;
    ret = ifft_fr(interp.coeffs, ys, n, s);
    if (ret != C_KZG_OK) goto out;

    // Because it is a coset, not the subgroup, we have to multiply the
    // polynomial coefficients by x^-i
    blst_fr_eucl_inverse(&inv_x, x);
    inv_x_pow = inv_x;
    for (uint64_t i = 1; i < n; i++) {
        blst_fr_mul(&interp.coeffs[i], &interp.coeffs[i], &inv_x_pow);
        blst_fr_mul(&inv_x_pow, &inv_x_pow, &inv_x);
    }

    // [x^n]_2
    blst_fr_eucl_inverse(&x_pow, &inv_x_pow);
    g2_mul(&xn2, blst_p2_generator(), &x_pow);

    // [s^n - x^n]_2
    g2_sub(&xn_minus_yn, &s->g2_values[n], &xn2);

    // [interpolation_polynomial(s)]_1
    ret = poly_to_kzg_commitment_monomial(&is1, interp.coeffs, n, s);
    if (ret != C_KZG_OK) return ret;

    // [commitment - interpolation_polynomial(s)]_1 = [commit]_1 -
    // [interpolation_polynomial(s)]_1
    g1_sub(&commit_minus_interp, commitment, &is1);

    *out = pairings_verify(
        &commit_minus_interp, blst_p2_generator(), proof, &xn_minus_yn
    );

out:
    free_poly(&interp);
    return ret;
}

///////////////////////////////////////////////////////////////////////////////
// Helper Functions for 2D Recovery
///////////////////////////////////////////////////////////////////////////////

static size_t get_missing_count(const fr_t *data, size_t length) {
    size_t missing_count = 0;
    for (size_t i = 0; i < length; i++) {
        if (fr_equal(&data[i], &FR_NULL)) {
            missing_count++;
        }
    }
    return missing_count;
}

static void get_column(fr_t *column, fr_t **data, size_t index) {
    for (size_t i = 0; i < SAMPLES_PER_BLOB; i++) {
        for (size_t j = 0; j < SAMPLE_SIZE; j++) {
            size_t col_index = (i * SAMPLE_SIZE) + j;
            size_t row_index = (index * SAMPLE_SIZE) + j;
            column[col_index] = data[i][row_index];
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// Data Availability Sampling Functions
///////////////////////////////////////////////////////////////////////////////

/**
 * Given DATA_POINTS_PER_BLOB data points, get a blob.
 *
 * @param[out]  blob    The resultant blob from the data points
 * @param[in]   data    An array of DATA_POINTS_PER_BLOB data points
 * @param[in]   s       The trusted setup
 *
 * @remark The array of data points must be in the correct order.
 */
C_KZG_RET samples_to_blob(
    Blob *blob, const Bytes32 *data, const KZGSettings *s
) {
    (void)s; // Will be used later.
    memcpy(&blob->bytes, data, BYTES_PER_BLOB);
    return C_KZG_OK;
}

/**
 * Given a blob, get DATA_POINTS_PER_BLOB data points and SAMPLES_PER_BLOB proofs.
 *
 * @param[out]  data    An array of DATA_POINTS_PER_BLOB data points
 * @param[out]  proofs  An array of SAMPLES_PER_BLOB proofs
 * @param[in]   blob    The blob to get samples for
 * @param[in]   s       The trusted setup
 *
 * @remark Use samples_to_blob to convert the data points into a blob.
 * @remark Up to half of these samples may be lost.
 * @remark Use recover_samples to recover missing samples.
 * @remark If `data` is NULL, samples won't be computed.
 * @remark If `proofs` is NULL, proofs won't be computed.
 */
C_KZG_RET get_samples_and_proofs(
    Bytes32 *data, KZGProof *proofs, const Blob *blob, const KZGSettings *s
) {
    C_KZG_RET ret;
    fr_t *poly_monomial = NULL;
    fr_t *poly_lagrange = NULL;
    fr_t *data_fr = NULL;
    g1_t *proofs_g1 = NULL;

    /* Allocate space fr-form arrays */
    ret = new_fr_array(&poly_monomial, s->max_width);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&poly_lagrange, s->max_width);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&data_fr, SAMPLES_PER_BLOB * SAMPLE_SIZE);
    if (ret != C_KZG_OK) goto out;
    ret = new_g1_array(&proofs_g1, SAMPLES_PER_BLOB);
    if (ret != C_KZG_OK) goto out;

    /* Initialize all of the polynomial fields to zero */
    memset(poly_monomial, 0, sizeof(fr_t) * s->max_width);
    memset(poly_lagrange, 0, sizeof(fr_t) * s->max_width);

    /*
     * Convert the blob to a polynomial. Note that only the first 4096 fields
     * of the polynomial will be set. The upper 4096 fields will remain zero.
     * This is required because the polynomial will be evaluated with 8192
     * roots of unity.
     */
    ret = blob_to_polynomial((Polynomial *)poly_lagrange, blob);
    if (ret != C_KZG_OK) goto out;

    ret = poly_lagrange_to_monomial(
        poly_monomial, poly_lagrange, FIELD_ELEMENTS_PER_BLOB, s
    );
    if (ret != C_KZG_OK) goto out;

    if (data != NULL) {
        /* Get the data points via forward transformation */
        ret = fft_fr(data_fr, poly_monomial, s->max_width, s);
        if (ret != C_KZG_OK) goto out;

        /* Convert all of the samples to byte-form */
        for (size_t i = 0; i < s->max_width; i++) {
            bytes_from_bls_field(&data[i], &data_fr[i]);
        }

        /* Bit-reverse the data points */
        ret = bit_reversal_permutation(data, sizeof(data[0]), s->max_width);
        if (ret != C_KZG_OK) goto out;
    }

    if (proofs != NULL) {
        poly_t p = {NULL, 0};
        p.length = s->max_width / 2;
        p.coeffs = poly_monomial;
        ret = da_using_fk20_multi(proofs_g1, &p, s);
        if (ret != C_KZG_OK) goto out;

        /* Convert all of the proofs to byte-form */
        for (size_t i = 0; i < SAMPLES_PER_BLOB; i++) {
            bytes_from_g1(&proofs[i], &proofs_g1[i]);
        }
    }

out:
    c_kzg_free(poly_monomial);
    c_kzg_free(poly_lagrange);
    c_kzg_free(data_fr);
    c_kzg_free(proofs_g1);
    return ret;
}

/**
 * Given BLOB_COUNT blobs, generate a 2D array of samples and proofs.
 *
 * @param[out]  data    An array of DATA_POINTS_PER_BLOB**2 data points
 * @param[out]  proofs  An array of SAMPLES_PER_BLOB**2 proofs
 * @param[in]   blobs   The blobs to generate samples for
 * @param[in]   s       The trusted setup
 *
 * @remark If `proofs` is NULL, they won't be computed.
 * @remark Proof computation is REALLY slow.
 */
C_KZG_RET get_2d_samples_and_proofs(
    Bytes32 *data, KZGProof *proofs, const Blob *blobs, const KZGSettings *s
) {
    C_KZG_RET ret;
    fr_t **data_fr = NULL;
    fr_t **monomial_polys = NULL;
    fr_t **lagrange_polys = NULL;
    size_t n = 2 * BLOB_COUNT;
    fr_t *column_poly = NULL;
    fr_t *column_poly_lagrange = NULL;
    fr_t *column_data = NULL;
    g1_t *proofs_g1 = NULL;

    /* Allocate 2D arrays */
    ret = c_kzg_calloc((void **)&data_fr, n, sizeof(fr_t *));
    if (ret != C_KZG_OK) goto out_pre_2d;
    ret = c_kzg_calloc((void **)&monomial_polys, n, sizeof(fr_t *));
    if (ret != C_KZG_OK) goto out_pre_2d;
    ret = c_kzg_calloc((void **)&lagrange_polys, n, sizeof(fr_t *));
    if (ret != C_KZG_OK) goto out_pre_2d;

    /* Initialize 2D arrays as NULL */
    for (size_t i = 0; i < n; i++) {
        data_fr[i] = NULL;
        monomial_polys[i] = NULL;
        lagrange_polys[i] = NULL;
    }

    /* Allocate 2D arrays */
    for (size_t i = 0; i < n; i++) {
        ret = new_fr_array(&data_fr[i], s->max_width);
        if (ret != C_KZG_OK) goto out;
        ret = new_fr_array(&monomial_polys[i], s->max_width);
        if (ret != C_KZG_OK) goto out;
        ret = new_fr_array(&lagrange_polys[i], s->max_width);
        if (ret != C_KZG_OK) goto out;
    }

    /* Allocate arrays for the column poly */
    ret = new_fr_array(&column_poly, s->max_width);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&column_poly_lagrange, s->max_width);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&column_data, s->max_width);
    if (ret != C_KZG_OK) goto out;

    /* Allocate array for single row of proofs */
    ret = new_g1_array(&proofs_g1, SAMPLES_PER_BLOB);
    if (ret != C_KZG_OK) goto out;

    /* Extend each blob */
    for (size_t i = 0; i < BLOB_COUNT; i++) {
        /* Initialize all of the polynomial fields to zero */
        memset(monomial_polys[i], 0, sizeof(fr_t) * s->max_width);
        memset(lagrange_polys[i], 0, sizeof(fr_t) * s->max_width);

        /* Convert blob to lagrange & monomial forms */
        ret = blob_to_polynomial((Polynomial *)lagrange_polys[i], &blobs[i]);
        if (ret != C_KZG_OK) goto out;
        ret = poly_lagrange_to_monomial(
            monomial_polys[i], lagrange_polys[i], FIELD_ELEMENTS_PER_BLOB, s
        );
        if (ret != C_KZG_OK) goto out;

        /* Get the data points via forward transformation */
        ret = fft_fr(data_fr[i], monomial_polys[i], s->max_width, s);
        if (ret != C_KZG_OK) goto out;

        /* Bit-reverse the data points */
        ret = bit_reversal_permutation(
            data_fr[i], sizeof(data_fr[i][0]), s->max_width
        );
        if (ret != C_KZG_OK) goto out;
    }

    /* Extend each column */
    for (size_t i = 0; i < SAMPLES_PER_BLOB; i++) {
        /* Initialize the poly to all zeros */
        memset(column_poly, 0, sizeof(fr_t) * s->max_width);
        size_t index = 0;

        /* Make the column polynomial */
        for (size_t j = 0; j < BLOB_COUNT; j++) {
            for (size_t k = 0; k < SAMPLE_SIZE; k++) {
                size_t row_index = (i * SAMPLE_SIZE) + k;
                column_poly[index] = data_fr[j][row_index];
                index++;
            }
        }

        /* Convert the column to lagrange form */
        ret = poly_lagrange_to_monomial(
            column_poly_lagrange, column_poly, FIELD_ELEMENTS_PER_BLOB, s
        );
        if (ret != C_KZG_OK) goto out;

        /* Generate samples for poly */
        ret = fft_fr(column_data, column_poly_lagrange, s->max_width, s);
        if (ret != C_KZG_OK) goto out;

        /* Bit-reverse the data points */
        ret = bit_reversal_permutation(
            column_data, sizeof(column_data[0]), s->max_width
        );
        if (ret != C_KZG_OK) goto out;

        /* Copy column back into data array */
        for (size_t j = BLOB_COUNT; j < n; j++) {
            for (size_t k = 0; k < SAMPLE_SIZE; k++) {
                size_t row_index = (i * SAMPLE_SIZE) + k;
                data_fr[j][row_index] = column_data[index];
                index++;
            }
        }
    }

    /* Convert the results to bytes */
    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < s->max_width; j++) {
            bytes_from_bls_field(&data[i * s->max_width + j], &data_fr[i][j]);
        }
    }

    if (proofs != NULL) {
        /* Convert the extended polys to monomial form */
        for (size_t i = BLOB_COUNT; i < n; i++) {
            /* Initialize all of the polynomial fields to zero */
            memset(monomial_polys[i], 0, sizeof(fr_t) * s->max_width);
            memset(lagrange_polys[i], 0, sizeof(fr_t) * s->max_width);

            Blob blob;
            ret = samples_to_blob(&blob, &data[i * s->max_width], s);
            if (ret != C_KZG_OK) goto out;

            /* Convert blob to lagrange & monomial forms */
            ret = blob_to_polynomial((Polynomial *)lagrange_polys[i], &blob);
            if (ret != C_KZG_OK) goto out;
            ret = poly_lagrange_to_monomial(
                monomial_polys[i], lagrange_polys[i], FIELD_ELEMENTS_PER_BLOB, s
            );
            if (ret != C_KZG_OK) goto out;
        }

        /* Compute proofs for each row */
        for (size_t i = 0; i < n; i++) {
            poly_t p = {NULL, 0};
            p.length = s->max_width / 2;
            p.coeffs = monomial_polys[i];
            ret = da_using_fk20_multi(proofs_g1, &p, s);
            if (ret != C_KZG_OK) goto out;

            /* Convert all of the proofs to byte-form */
            for (size_t j = 0; j < SAMPLES_PER_BLOB; j++) {
                size_t index = i * n + j;
                bytes_from_g1(&proofs[index], &proofs_g1[j]);
            }
        }
    }

out:
    for (size_t i = 0; i < n; i++) {
        c_kzg_free(monomial_polys[i]);
        c_kzg_free(lagrange_polys[i]);
        c_kzg_free(data_fr[i]);
    }
out_pre_2d:
    c_kzg_free(monomial_polys);
    c_kzg_free(lagrange_polys);
    c_kzg_free(data_fr);
    c_kzg_free(column_poly);
    c_kzg_free(column_poly_lagrange);
    c_kzg_free(column_data);
    c_kzg_free(proofs_g1);
    return ret;
}

/**
 * Given at least 50% of data points, recover the missing data points.
 *
 * @param[out]  recovered   An array of DATA_POINTS_PER_BLOB data points
 * @param[in]   data        An array of DATA_POINTS_PER_BLOB data points
 * @param[in]   s           The trusted setup
 *
 * @remark The array of data points must be in the correct order.
 * @remark Missing data points are marked as 0xffff...ffff (32 bytes).
 * @remark Recovery is faster if there are fewer missing data points.
 */
C_KZG_RET recover_samples(
    Bytes32 *recovered, const Bytes32 *data, const KZGSettings *s
) {
    C_KZG_RET ret;
    fr_t *recovered_fr = NULL;

    /* Check if there's a missing data point */
    for (size_t i = 0; i < s->max_width; i++) {
        if (!memcmp(&data[i].bytes, &FR_NULL, sizeof(Bytes32))) {
            goto recover;
        }
    }

    /* Nothing is missing, copy original data and return */
    memcpy(recovered, data, sizeof(Bytes32) * s->max_width);
    return C_KZG_OK;

recover:
    /* Allocate space fr-form arrays */
    ret = new_fr_array(&recovered_fr, s->max_width);
    if (ret != C_KZG_OK) goto out;

    /* Convert data points to fr-form */
    for (size_t i = 0; i < s->max_width; i++) {
        /* Missing data points are marked as 0xffff...ffff */
        if (!memcmp(&data[i].bytes, &FR_NULL, sizeof(Bytes32))) {
            recovered_fr[i] = FR_NULL;
        } else {
            ret = bytes_to_bls_field(&recovered_fr[i], &data[i]);
            if (ret != C_KZG_OK) goto out;
        }
    }

    /* Call the implementation function to do the bulk of the work */
    ret = recover_samples_impl(recovered_fr, recovered_fr, s);
    if (ret != C_KZG_OK) goto out;

    /* Convert the recovered data points to byte-form */
    for (size_t i = 0; i < s->max_width; i++) {
        bytes_from_bls_field(&recovered[i], &recovered_fr[i]);
    }

out:
    c_kzg_free(recovered_fr);
    return ret;
}

/**
 * Given at least 75% of data points, recover the missing data points.
 *
 * @param[out]  recovered   A flat array of DATA_POINTS_PER_BLOB**2 data points
 * @param[in]   data        A flat array of DATA_POINTS_PER_BLOB**2 data points
 * @param[in]   s           The trusted setup
 *
 * @remark The array of data points must be in the correct order.
 * @remark The 2D array is a SAMPLES_PER_BLOB by SAMPLES_PER_BLOB in size.
 * @remark Missing data points are marked as 0xffff...ffff (32 bytes).
 * @remark Recovery is faster if there are fewer missing data points.
 */
C_KZG_RET recover_2d_samples(
    Bytes32 *recovered, const Bytes32 *data, const KZGSettings *s
) {
    C_KZG_RET ret;
    fr_t **recovered_fr = NULL;
    fr_t *column = NULL;
    fr_t *recovered_column = NULL;
    size_t n = 2 * BLOB_COUNT;
    size_t total_data_count = n * s->max_width;
    size_t missing_count = 0;
    bool *complete_rows = NULL;
    bool *complete_cols = NULL;

    /* Allocate space fr-form arrays */
    ret = c_kzg_calloc((void **)&recovered_fr, n, sizeof(fr_t *));
    if (ret != C_KZG_OK) goto out_pre_2d;

    /* Initialize 2D arrays as NULL */
    for (size_t i = 0; i < n; i++) {
        recovered_fr[i] = NULL;
    }

    /* Allocate 2D array values */
    for (size_t i = 0; i < n; i++) {
        ret = new_fr_array(&recovered_fr[i], s->max_width);
        if (ret != C_KZG_OK) goto out;
    }

    /* Allocate space for a column, unnecessary for rows */
    ret = new_fr_array(&column, s->max_width);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&recovered_column, s->max_width);
    if (ret != C_KZG_OK) goto out;

    /* Allocate space for incomplete tracking array */
    ret = c_kzg_calloc((void **)&complete_rows, n, sizeof(bool));
    if (ret != C_KZG_OK) goto out;
    ret = c_kzg_calloc((void **)&complete_cols, n, sizeof(bool));
    if (ret != C_KZG_OK) goto out;

    /* Initialize everything as complete */
    memset(complete_rows, true, n);
    memset(complete_cols, true, n);

    /* Convert data points to fr-form */
    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < s->max_width; j++) {
            size_t index = i * s->max_width + j;
            if (!memcmp(&data[index].bytes, &FR_NULL, sizeof(Bytes32))) {
                /* Track count */
                missing_count++;

                /* Use null value to mark it as missing */
                recovered_fr[i][j] = FR_NULL;

                /* Mark this row/col as incomplete */
                complete_rows[i] = false;
                complete_cols[j / SAMPLE_SIZE] = false;
            } else {
                /* Convert the data to fr-form */
                ret = bytes_to_bls_field(&recovered_fr[i][j], &data[index]);
                if (ret != C_KZG_OK) goto out;
            }
        }
    }

    /* If nothing is missing, copy original data and return */
    if (missing_count == 0) {
        memcpy(recovered, data, sizeof(Bytes32) * s->max_width);
        goto out;
    }

    /* Ensure there's enough info to recover */
    if (missing_count * 4 > total_data_count) {
        /* More than 25% is missing */
        ret = C_KZG_BADARGS;
        goto out;
    }

    /* Recover rows */
    for (size_t i = 0; i < n; i++) {
        /* Skip if the row is already complete */
        if (complete_rows[i]) continue;

        /* Calculate how many data points are missing */
        size_t missing = get_missing_count(recovered_fr[i], s->max_width);
        if (missing == 0 || missing > FIELD_ELEMENTS_PER_BLOB) continue;

        /* Call the implementation function to do the bulk of the work */
        ret = recover_samples_impl(recovered_fr[i], recovered_fr[i], s);
        if (ret != C_KZG_OK) goto out;

        /* Mark this row as complete */
        complete_rows[i] = true;
    }

    /* Recover columns */
    for (size_t i = 0; i < n; i++) {
        /* Skip if the column is already complete */
        if (complete_cols[i]) continue;

        /* Get the column for this index */
        get_column(column, recovered_fr, i);

        /* Calculate how many data points are missing */
        size_t missing = get_missing_count(column, s->max_width);
        if (missing == 0 || missing > FIELD_ELEMENTS_PER_BLOB) continue;

        /* Call the implementation function to do the bulk of the work */
        ret = recover_samples_impl(recovered_column, column, s);
        if (ret != C_KZG_OK) goto out;

        /* Save column to recovered data */
        for (size_t j = 0; j < SAMPLES_PER_BLOB; j++) {
            for (size_t k = 0; k < SAMPLE_SIZE; k++) {
                size_t col_index = (j * SAMPLE_SIZE) + k;
                size_t row_index = (i * SAMPLE_SIZE) + k;
                recovered_fr[j][row_index] = recovered_column[col_index];
            }
        }
    }

    /* Recover rows */
    for (size_t i = 0; i < n; i++) {
        /* Skip if the row is already complete */
        if (complete_rows[i]) continue;

        /* Calculate how many data points are missing */
        size_t missing = get_missing_count(recovered_fr[i], s->max_width);
        if (missing == 0 || missing > FIELD_ELEMENTS_PER_BLOB) continue;

        /* Call the implementation function to do the bulk of the work */
        ret = recover_samples_impl(recovered_fr[i], recovered_fr[i], s);
        if (ret != C_KZG_OK) goto out;
    }

    /* Convert the recovered data points to byte-form */
    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < s->max_width; j++) {
            size_t index = i * s->max_width + j;
            bytes_from_bls_field(&recovered[index], &recovered_fr[i][j]);
        }
    }

out_pre_2d:
    for (size_t i = 0; i < n; i++) {
        c_kzg_free(recovered_fr[i]);
    }
out:
    c_kzg_free(recovered_fr);
    c_kzg_free(column);
    c_kzg_free(recovered_column);
    c_kzg_free(complete_rows);
    c_kzg_free(complete_cols);
    return ret;
}

/**
 * For a given sample, verify that the proof is valid.
 *
 * @param[out]  ok                  True if the proof are valid, otherwise false
 * @param[in]   commitment_bytes    The commitment to the blob's samples
 * @param[in]   proof_bytes         The proof for the sample
 * @param[in]   data                The sample to check
 * @param[in]   index               The sample/proof index
 * @param[in]   s                   The trusted setup
 */
C_KZG_RET verify_sample_proof(
    bool *ok,
    const Bytes48 *commitment_bytes,
    const Bytes48 *proof_bytes,
    const Bytes32 *data,
    size_t index,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    g1_t commitment, proof;
    fr_t x, *ys = NULL;

    *ok = false;

    /* Check that index is a valid value */
    if (index >= SAMPLES_PER_BLOB) {
        ret = C_KZG_BADARGS;
        goto out;
    }

    /* Allocate array for fr-form data points */
    ret = new_fr_array(&ys, SAMPLE_SIZE);
    if (ret != C_KZG_OK) goto out;

    /* Convert untrusted inputs */
    ret = bytes_to_kzg_commitment(&commitment, commitment_bytes);
    if (ret != C_KZG_OK) goto out;
    ret = bytes_to_kzg_proof(&proof, proof_bytes);
    if (ret != C_KZG_OK) goto out;
    for (size_t i = 0; i < SAMPLE_SIZE; i++) {
        ret = bytes_to_bls_field(&ys[i], &data[i]);
        if (ret != C_KZG_OK) goto out;
    }

    /* Calculate the input value */
    size_t pos = reverse_bits_limited(SAMPLES_PER_BLOB, index);
    x = s->expanded_roots_of_unity[pos];

    /* Reorder ys */
    ret = bit_reversal_permutation(ys, sizeof(ys[0]), SAMPLE_SIZE);
    if (ret != C_KZG_OK) goto out;

    /* Check the proof */
    ret = verify_kzg_proof_multi_impl(
        ok, &commitment, &proof, &x, ys, SAMPLE_SIZE, s
    );

out:
    c_kzg_free(ys);
    return ret;
}

/**
 * Check if a sample is uninitialized (all zeros).
 *
 * @param[in]   sample  The sample to check
 *
 * @retval  True    The sample is uninitialized.
 * @retval  False   The sample is initialized.
 */
static bool is_sample_uninit(fr_t *sample) {
    for (size_t i = 0; i < SAMPLE_SIZE; i++) {
        if (!fr_is_zero(&sample[i])) {
            return false;
        }
    }
    return true;
}

/**
 * Given some samples, verify that all of the proofs are valid.
 *
 * @param[out]  ok                  True if the proofs are valid
 * @param[in]   commitments_bytes   Commitments for ALL blobs in the matrix
 * @param[in]   num_commitments     The number of commitments being passed
 * @param[in]   proofs_bytes        Proofs which correspond to each sample
 * @param[in]   samples             The samples to check
 * @param[in]   num_samples         The number of samples provided
 * @param[in]   rows                Row indices for each sample
 * @param[in]   cols                Column indices for each sample
 * @param[in]   s                   The trusted setup
 */
C_KZG_RET verify_sample_proof_batch(
    bool *ok,
    const Bytes48 *commitments_bytes, // ALL commitments
    size_t num_commitments,
    const Bytes48 *proofs_bytes,
    const Sample *samples,
    size_t num_samples,
    const uint64_t *rows,
    const uint64_t *cols,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    fr_t *aggregated_column_samples = NULL;
    fr_t *commitment_weights = NULL;
    fr_t *r_powers = NULL;
    fr_t *used_commitment_weights = NULL;
    fr_t *weighted_powers_of_r = NULL;
    fr_t *weights = NULL;
    fr_t aggregated_interpolation_poly[SAMPLE_SIZE];
    fr_t column_interpolation_poly[SAMPLE_SIZE];
    g1_t *proofs_g1 = NULL;
    g1_t *used_commitments = NULL;
    g1_t evaluation;
    g1_t final_g1_sum;
    g1_t proof_lincomb;
    g1_t weighted_proof_lincomb;
    g2_t power_of_s = s->g2_values[SAMPLE_SIZE];
    size_t num_used_commitments = 0;

    *ok = false;

    /* Exit early if we are given zero samples */
    if (num_samples == 0) {
        *ok = true;
        return C_KZG_OK;
    }

    ///////////////////////////////////////////////////////////////////////////
    // Sanity checks
    ///////////////////////////////////////////////////////////////////////////

    /* If there are more samples than the matrix allows, error */
    if (num_samples > (SAMPLES_PER_BLOB * SAMPLES_PER_BLOB)) {
        return C_KZG_BADARGS;
    }

    for (size_t i = 0; i < num_samples; i++) {
        /* Can't have more commitments than blobs */
        if (rows[i] >= BLOB_COUNT) {
            return C_KZG_BADARGS;
        }

        /* Make sure we can reference all commitments */
        if (rows[i] >= num_commitments) {
            return C_KZG_BADARGS;
        }

        /* Can't have more columns than samples in a blob */
        if (cols[i] >= SAMPLES_PER_BLOB) {
            return C_KZG_BADARGS;
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    // Array allocations
    ///////////////////////////////////////////////////////////////////////////

    ret = new_fr_array(&r_powers, num_samples);
    if (ret != C_KZG_OK) goto out;
    ret = new_g1_array(&proofs_g1, num_samples);
    if (ret != C_KZG_OK) goto out;
    ret = new_g1_array(&used_commitments, num_commitments);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&weights, num_samples);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&weighted_powers_of_r, num_samples);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&commitment_weights, num_commitments);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&used_commitment_weights, num_commitments);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&aggregated_column_samples, DATA_POINTS_PER_BLOB);
    if (ret != C_KZG_OK) goto out;

    ///////////////////////////////////////////////////////////////////////////
    // Compute random linear combination of the proofs
    ///////////////////////////////////////////////////////////////////////////

    /*
     * Derive random factors for the linear combination. The exponents start
     * with 1, for example r^1, r^2, r^3, and so on.
     *
     * TODO: make this more random.
     */
    fr_from_uint64(&r_powers[0], 27);
    for (size_t i = 1; i < num_samples; i++) {
        blst_fr_mul(&r_powers[i], &r_powers[i - 1], &r_powers[0]);
    }

    /* There should be a proof for each sample */
    for (size_t i = 0; i < num_samples; i++) {
        ret = bytes_to_kzg_proof(&proofs_g1[i], &proofs_bytes[i]);
        if (ret != C_KZG_OK) goto out;
    }

    g1_lincomb_naive(&proof_lincomb, proofs_g1, r_powers, num_samples);

    ///////////////////////////////////////////////////////////////////////////
    // Compute sum of the commitments
    ///////////////////////////////////////////////////////////////////////////

    /* Zero out all of the weights */
    for (size_t i = 0; i < num_commitments; i++) {
        commitment_weights[i] = FR_ZERO;
    }

    /* Update commitment weights */
    for (size_t i = 0; i < num_samples; i++) {
        blst_fr_add(
            &commitment_weights[rows[i]],
            &commitment_weights[rows[i]],
            &r_powers[i]
        );
    }

    /* Generate list with only used commitments */
    for (size_t i = 0; i < num_commitments; i++) {
        if (fr_is_zero(&commitment_weights[i])) continue;

        /*
         * Convert & validate commitment. Only do this for used
         * commitments to save processing time.
         */
        ret = bytes_to_kzg_commitment(
            &used_commitments[num_used_commitments], &commitments_bytes[i]
        );
        if (ret != C_KZG_OK) goto out;

        /* Assign commitment weight and increment */
        used_commitment_weights[num_used_commitments] = commitment_weights[i];
        num_used_commitments++;
    }

    g1_lincomb_naive(
        &final_g1_sum,
        used_commitments,
        used_commitment_weights,
        num_used_commitments
    );

    ///////////////////////////////////////////////////////////////////////////
    // Compute aggregated columns
    ///////////////////////////////////////////////////////////////////////////

    for (size_t i = 0; i < SAMPLES_PER_BLOB; i++) {
        for (size_t j = 0; j < SAMPLE_SIZE; j++) {
            size_t index = i * SAMPLE_SIZE + j;
            aggregated_column_samples[index] = FR_ZERO;
        }
    }

    for (size_t i = 0; i < num_samples; i++) {
        for (size_t j = 0; j < SAMPLE_SIZE; j++) {
            fr_t field, scaled;
            ret = bytes_to_bls_field(&field, &samples[i].data[j]);
            if (ret != C_KZG_OK) goto out;
            blst_fr_mul(&scaled, &field, &r_powers[i]);
            size_t index = cols[i] * SAMPLE_SIZE + j;
            blst_fr_add(
                &aggregated_column_samples[index],
                &aggregated_column_samples[index],
                &scaled
            );
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    // Compute sum of the interpolation polynomials
    ///////////////////////////////////////////////////////////////////////////

    for (size_t j = 0; j < SAMPLE_SIZE; j++) {
        aggregated_interpolation_poly[j] = FR_ZERO;
    }

    for (size_t j = 0; j < SAMPLES_PER_BLOB; j++) {
        if (is_sample_uninit(&aggregated_column_samples[j])) continue;

        uint32_t pos = reverse_bits_limited(SAMPLES_PER_BLOB, j);
        fr_t coset_factor = s->expanded_roots_of_unity[pos];

        fr_t reversed_sample[SAMPLE_SIZE];
        for (size_t k = 0; k < SAMPLE_SIZE; k++) {
            size_t index = j * SAMPLE_SIZE + k;
            reversed_sample[k] = aggregated_column_samples[index];
        }
        ret = bit_reversal_permutation(
            reversed_sample, sizeof(fr_t), SAMPLE_SIZE
        );
        if (ret != C_KZG_OK) goto out;

        /*
         * Get interpolation polynomial for this column. To do so we first do an
         * IDFT over the roots of unity and then we scale by the coset factor.
         * We can't do an IDFT directly over the coset because it's not a
         * subgroup.
         */
        ret = ifft_fr(
            column_interpolation_poly, reversed_sample, SAMPLE_SIZE, s
        );
        if (ret != C_KZG_OK) goto out;

        fr_t inv_x, inv_x_pow;
        blst_fr_eucl_inverse(&inv_x, &coset_factor);
        inv_x_pow = inv_x;
        for (uint64_t i = 1; i < SAMPLE_SIZE; i++) {
            blst_fr_mul(
                &column_interpolation_poly[i],
                &column_interpolation_poly[i],
                &inv_x_pow
            );
            blst_fr_mul(&inv_x_pow, &inv_x_pow, &inv_x);
        }

        /* Update the aggregated poly */
        for (size_t k = 0; k < SAMPLE_SIZE; k++) {
            blst_fr_add(
                &aggregated_interpolation_poly[k],
                &aggregated_interpolation_poly[k],
                &column_interpolation_poly[k]
            );
        }
    }

    /* Commit to the final aggregated interpolation polynomial */
    g1_lincomb_naive(
        &evaluation, s->g1_values, aggregated_interpolation_poly, SAMPLE_SIZE
    );
    blst_p1_cneg(&evaluation, true);
    blst_p1_add(&final_g1_sum, &final_g1_sum, &evaluation);

    ///////////////////////////////////////////////////////////////////////////
    // Compute sum of the proofs scaled by the coset factors
    ///////////////////////////////////////////////////////////////////////////

    for (size_t i = 0; i < num_samples; i++) {
        uint32_t pos = reverse_bits_limited(SAMPLES_PER_BLOB, cols[i]);
        fr_t coset_factor = s->expanded_roots_of_unity[pos];
        fr_pow(&weights[i], &coset_factor, SAMPLE_SIZE);
        blst_fr_mul(&weighted_powers_of_r[i], &r_powers[i], &weights[i]);
    }

    g1_lincomb_naive(
        &weighted_proof_lincomb, proofs_g1, weighted_powers_of_r, num_samples
    );
    blst_p1_add(&final_g1_sum, &final_g1_sum, &weighted_proof_lincomb);

    ///////////////////////////////////////////////////////////////////////////
    // Do the final pairing check
    ///////////////////////////////////////////////////////////////////////////

    *ok = pairings_verify(
        &final_g1_sum, blst_p2_generator(), &proof_lincomb, &power_of_s
    );

out:
    c_kzg_free(aggregated_column_samples);
    c_kzg_free(commitment_weights);
    c_kzg_free(proofs_g1);
    c_kzg_free(r_powers);
    c_kzg_free(used_commitment_weights);
    c_kzg_free(used_commitments);
    c_kzg_free(weighted_powers_of_r);
    c_kzg_free(weights);
    return ret;
}
