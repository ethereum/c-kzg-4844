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

////////////////////////////////////////////////////////////////////////////////////////////////////
// Macros
////////////////////////////////////////////////////////////////////////////////////////////////////

/** Returns the smaller value. */
#define MIN(a, b) ((a) < (b) ? (a) : (b))

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

/** Internal representation of a polynomial. */
typedef struct {
    fr_t evals[FIELD_ELEMENTS_PER_BLOB];
} Polynomial;

////////////////////////////////////////////////////////////////////////////////////////////////////
// Constants
////////////////////////////////////////////////////////////////////////////////////////////////////

/** The domain separator for the Fiat-Shamir protocol. */
static const char *FIAT_SHAMIR_PROTOCOL_DOMAIN = "FSBLOBVERIFY_V1_";

/** The domain separator for verify_blob_kzg_proof's random challenge. */
static const char *RANDOM_CHALLENGE_DOMAIN_VERIFY_BLOB_KZG_PROOF_BATCH = "RCKZGBATCH___V1_";

/** The domain separator for verify_cell_kzg_proof_batch's random challenge. */
static const char *RANDOM_CHALLENGE_DOMAIN_VERIFY_CELL_KZG_PROOF_BATCH = "RCKZGCBATCH__V1_";

/** Length of the domain strings above. */
#define DOMAIN_STR_LENGTH 16

/** The number of bytes in a g1 point. */
#define BYTES_PER_G1 48

/** The number of bytes in a g2 point. */
#define BYTES_PER_G2 96

/** The number of g1 points in a trusted setup. */
#define NUM_G1_POINTS FIELD_ELEMENTS_PER_BLOB

/** The number of g2 points in a trusted setup. */
#define NUM_G2_POINTS 65

/** Deserialized form of the G1 identity/infinity point. */
static const g1_t G1_IDENTITY = {
    {0L, 0L, 0L, 0L, 0L, 0L}, {0L, 0L, 0L, 0L, 0L, 0L}, {0L, 0L, 0L, 0L, 0L, 0L}
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

/** The zero field element. */
static const fr_t FR_ZERO = {0L, 0L, 0L, 0L};

/** This is 1 in blst's `blst_fr` limb representation. Crazy but true. */
static const fr_t FR_ONE = {
    0x00000001fffffffeL, 0x5884b7fa00034802L, 0x998c4fefecbc4ff5L, 0x1824b159acc5056fL
};

/** This used to represent a missing element. It's a invalid value. */
static const fr_t FR_NULL = {
    0xffffffffffffffffL, 0xffffffffffffffffL, 0xffffffffffffffffL, 0xffffffffffffffffL
};

////////////////////////////////////////////////////////////////////////////////////////////////////
// Memory Allocation Functions
////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Wrapped malloc() that reports failures to allocate.
 *
 * @param[out] out  Pointer to the allocated space
 * @param[in]  size The number of bytes to be allocated
 *
 * @remark Will return C_KZG_BADARGS if the requested size is zero.
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
 * @param[out] out   Pointer to the allocated space
 * @param[in]  count The number of elements
 * @param[in]  size  The size of each element
 *
 * @remark Will return C_KZG_BADARGS if the requested size is zero.
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
 * @param[out] x Pointer to the allocated space
 * @param[in]  n The number of G1 elements to be allocated
 *
 * @remark Free the space later using c_kzg_free().
 */
static C_KZG_RET new_g1_array(g1_t **x, size_t n) {
    return c_kzg_calloc((void **)x, n, sizeof(g1_t));
}

/**
 * Allocate memory for an array of G2 group elements.
 *
 * @param[out] x Pointer to the allocated space
 * @param[in]  n The number of G2 elements to be allocated
 *
 * @remark Free the space later using c_kzg_free().
 */
static C_KZG_RET new_g2_array(g2_t **x, size_t n) {
    return c_kzg_calloc((void **)x, n, sizeof(g2_t));
}

/**
 * Allocate memory for an array of field elements.
 *
 * @param[out] x Pointer to the allocated space
 * @param[in]  n The number of field elements to be allocated
 *
 * @remark Free the space later using c_kzg_free().
 */
static C_KZG_RET new_fr_array(fr_t **x, size_t n) {
    return c_kzg_calloc((void **)x, n, sizeof(fr_t));
}

/**
 * Allocate memory for an array of booleans.
 *
 * @param[out] x Pointer to the allocated space
 * @param[in]  n The number of booleans to be allocated
 *
 * @remark Free the space later using c_kzg_free().
 */
static C_KZG_RET new_bool_array(bool **x, size_t n) {
    return c_kzg_calloc((void **)x, n, sizeof(bool));
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Helper Functions
////////////////////////////////////////////////////////////////////////////////////////////////////

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
 * @retval true     The two elements are equal.
 * @retval false    The two elements are not equal.
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
 * @param[out] out `a` divided by `b` in the field
 * @param[in]  a   The dividend
 * @param[in]  b   The divisor
 *
 * @remark The behavior for `b == 0` is unspecified.
 * @remark This function supports in-place computation.
 */
static void fr_div(fr_t *out, const fr_t *a, const fr_t *b) {
    blst_fr tmp;
    blst_fr_eucl_inverse(&tmp, b);
    blst_fr_mul(out, a, &tmp);
}

/**
 * Exponentiation of a field element.
 *
 * Uses square and multiply for log(n) performance.
 *
 * @param[out] out `a` raised to the power of `n`
 * @param[in]  a   The field element to be exponentiated
 * @param[in]  n   The exponent
 *
 * @remark A 64-bit exponent is sufficient for our needs here.
 * @remark This function does support in-place computation.
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
 * @param[out] out The field element equivalent of `n`
 * @param[in]  n   The 64-bit integer to be converted
 *
 * @remark This can only generate a tiny fraction of possible field elements,
 *         and is mostly useful for testing.
 */
static void fr_from_uint64(fr_t *out, uint64_t n) {
    uint64_t vals[] = {n, 0, 0, 0};
    blst_fr_from_uint64(out, vals);
}

/**
 * Montgomery batch inversion in finite field.
 *
 * @param[out] out The inverses of `a`, length `len`
 * @param[in]  a   A vector of field elements, length `len`
 * @param[in]  len The number of field elements
 *
 * @remark This function only supports len > 0.
 * @remark This function does NOT support in-place computation.
 * @remark Return C_KZG_BADARGS if a zero is found in the input. In this case,
 *         the `out` output array has already been mutated.
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
 * @param[out] out  `a * b`
 * @param[in]  a    The G1 group element
 * @param[in]  b    The multiplier
 */
static void g1_mul(g1_t *out, const g1_t *a, const fr_t *b) {
    blst_scalar s;
    blst_scalar_from_fr(&s, b);
    blst_p1_mult(out, a, s.b, BITS_PER_FIELD_ELEMENT);
}

/**
 * Multiply a G2 group element by a field element.
 *
 * @param[out] out `a * b`
 * @param[in]  a   The G2 group element
 * @param[in]  b   The multiplier
 */
static void g2_mul(g2_t *out, const g2_t *a, const fr_t *b) {
    blst_scalar s;
    blst_scalar_from_fr(&s, b);
    blst_p2_mult(out, a, s.b, BITS_PER_FIELD_ELEMENT);
}

/**
 * Subtraction of G1 group elements.
 *
 * @param[out] out `a - b`
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
 * @param[out] out `a - b`
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
static bool pairings_verify(const g1_t *a1, const g2_t *a2, const g1_t *b1, const g2_t *b2) {
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

////////////////////////////////////////////////////////////////////////////////////////////////////
// Bytes Conversion Helper Functions
////////////////////////////////////////////////////////////////////////////////////////////////////

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
 * @param[out] out An 8-byte array to store the serialized integer
 * @param[in]  n   The integer to be serialized
 *
 * @remark The output format is big-endian.
 */
static void bytes_from_uint64(uint8_t out[8], uint64_t n) {
    for (int i = 7; i >= 0; i--) {
        out[i] = n & 0xFF;
        n >>= 8;
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// BLS12-381 Helper Functions
////////////////////////////////////////////////////////////////////////////////////////////////////

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
 * Convert untrusted bytes to a trusted and validated BLS scalar field element.
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
 * @param[out]  out The output g1 point
 * @param[in]   b   The proof/commitment bytes
 *
 * @remark This function deviates from the spec because it returns (via an output argument) the g1
 * point. This way is more efficient (faster) but the function name is a bit misleading.
 */
static C_KZG_RET validate_kzg_g1(g1_t *out, const Bytes48 *b) {
    blst_p1_affine p1_affine;

    /* Convert the bytes to a p1 point */
    /* The uncompress routine checks that the point is on the curve */
    if (blst_p1_uncompress(&p1_affine, b->bytes) != BLST_SUCCESS) return C_KZG_BADARGS;
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
 * Deserialize a blob (array of bytes) into a polynomial (array of field elements).
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
#define CHALLENGE_INPUT_SIZE (DOMAIN_STR_LENGTH + 16 + BYTES_PER_BLOB + BYTES_PER_COMMITMENT)

/**
 * Return the Fiat-Shamir challenge required to verify `blob` and `commitment`.
 *
 * @param[out] eval_challenge_out The evaluation challenge
 * @param[in]  blob               A blob
 * @param[in]  commitment         A commitment
 *
 * @remark This function should compute challenges even if `n == 0`.
 */
static void compute_challenge(fr_t *eval_challenge_out, const Blob *blob, const g1_t *commitment) {
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
 * This function computes the result naively without using Pippenger's algorithm.
 */
static void g1_lincomb_naive(g1_t *out, const g1_t *p, const fr_t *coeffs, uint64_t len) {
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
 * Calculates `[coeffs_0]p_0 + [coeffs_1]p_1 + ... + [coeffs_n]p_n` where `n` is `len - 1`.
 *
 * @param[out] out    The resulting sum-product
 * @param[in]  p      Array of G1 group elements, length `len`
 * @param[in]  coeffs Array of field elements, length `len`
 * @param[in]  len    The number of group/field elements
 *
 * @remark This function CAN be called with the point at infinity in `p`.
 * @remark While this function is significantly faster than g1_lincomb_naive(), we refrain from
 * using it in security-critical places (like verification) because the blst Pippenger code has not
 * been audited. In those critical places, we prefer using g1_lincomb_naive() which is much simpler.
 *
 * For the benefit of future generations (since blst has no documentation to speak of), there are
 * two ways to pass the arrays of scalars and points into blst_p1s_mult_pippenger().
 *
 * 1. Pass `points` as an array of pointers to the points, and pass `scalars` as an array of
 *    pointers to the scalars, each of length `len`.
 * 2. Pass an array where the first element is a pointer to the contiguous array of points and the
 *    second is null, and similarly for scalars.
 *
 * We do the second of these to save memory here.
 */
static C_KZG_RET g1_lincomb_fast(g1_t *out, const g1_t *p, const fr_t *coeffs, size_t len) {
    C_KZG_RET ret;
    void *scratch = NULL;
    blst_p1 *p_filtered = NULL;
    blst_p1_affine *p_affine = NULL;
    blst_scalar *scalars = NULL;

    /* Tunable parameter: must be at least 2 since blst fails for 0 or 1 */
    const size_t min_length_threshold = 8;

    /* Use naive method if it's less than the threshold */
    if (len < min_length_threshold) {
        g1_lincomb_naive(out, p, coeffs, len);
        ret = C_KZG_OK;
        goto out;
    }

    /* Allocate space for arrays */
    ret = c_kzg_calloc((void **)&p_filtered, len, sizeof(blst_p1));
    if (ret != C_KZG_OK) goto out;
    ret = c_kzg_calloc((void **)&p_affine, len, sizeof(blst_p1_affine));
    if (ret != C_KZG_OK) goto out;
    ret = c_kzg_calloc((void **)&scalars, len, sizeof(blst_scalar));
    if (ret != C_KZG_OK) goto out;

    /* Allocate space for Pippenger scratch */
    size_t scratch_size = blst_p1s_mult_pippenger_scratch_sizeof(len);
    ret = c_kzg_malloc(&scratch, scratch_size);
    if (ret != C_KZG_OK) goto out;

    /* Transform the field elements to 256-bit scalars */
    for (size_t i = 0; i < len; i++) {
        blst_scalar_from_fr(&scalars[i], &coeffs[i]);
    }

    /* Filter out zero points: make a new list p_filtered that contains only non-zero points */
    size_t new_len = 0;
    for (size_t i = 0; i < len; i++) {
        if (!blst_p1_is_inf(&p[i])) {
            /* Copy valid points to the new position */
            p_filtered[new_len] = p[i];
            scalars[new_len] = scalars[i];
            new_len++;
        }
    }

    /* Check if the new length is fine */
    if (new_len < min_length_threshold) {
        /* We must use the original inputs */
        g1_lincomb_naive(out, p, coeffs, len);
        ret = C_KZG_OK;
        goto out;
    }

    /* Transform the points to affine representation */
    const blst_p1 *p_arg[2] = {p_filtered, NULL};
    blst_p1s_to_affine(p_affine, p_arg, new_len);

    /* Call the Pippenger implementation */
    const byte *scalars_arg[2] = {(byte *)scalars, NULL};
    const blst_p1_affine *points_arg[2] = {p_affine, NULL};
    blst_p1s_mult_pippenger(out, points_arg, new_len, scalars_arg, BITS_PER_FIELD_ELEMENT, scratch);
    ret = C_KZG_OK;

out:
    c_kzg_free(scratch);
    c_kzg_free(p_filtered);
    c_kzg_free(p_affine);
    c_kzg_free(scalars);
    return ret;
}

/**
 * Compute and return [ x^0, x^1, ..., x^{n-1} ].
 *
 * @param[out] out The array to store the powers
 * @param[in]  x   The field element to raise to powers
 * @param[in]  n   The number of powers to compute
 *
 * @remark `out` is left untouched if `n == 0`.
 */
static void compute_powers(fr_t *out, const fr_t *x, uint64_t n) {
    fr_t current_power = FR_ONE;
    for (uint64_t i = 0; i < n; i++) {
        out[i] = current_power;
        blst_fr_mul(&current_power, &current_power, x);
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Polynomials Functions
////////////////////////////////////////////////////////////////////////////////////////////////////

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
         * If the point to evaluate at is one of the evaluation points by which the polynomial is
         * given, we can just return the result directly.  Note that special-casing this is
         * necessary, as the formula below would divide by zero otherwise.
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

////////////////////////////////////////////////////////////////////////////////////////////////////
// KZG Functions
////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Compute a KZG commitment from a polynomial.
 *
 * @param[out] out The resulting commitment
 * @param[in]  p   The polynomial to commit to
 * @param[in]  s   The trusted setup
 */
static C_KZG_RET poly_to_kzg_commitment(g1_t *out, const Polynomial *p, const KZGSettings *s) {
    return g1_lincomb_fast(
        out, s->g1_values_lagrange_brp, (const fr_t *)(&p->evals), FIELD_ELEMENTS_PER_BLOB
    );
}

/**
 * Convert a blob to a KZG commitment.
 *
 * @param[out] out  The resulting commitment
 * @param[in]  blob The blob representing the polynomial to be committed to
 * @param[in]  s    The trusted setup
 */
C_KZG_RET blob_to_kzg_commitment(KZGCommitment *out, const Blob *blob, const KZGSettings *s) {
    C_KZG_RET ret;
    Polynomial p;
    g1_t commitment;

    ret = blob_to_polynomial(&p, blob);
    if (ret != C_KZG_OK) return ret;
    ret = poly_to_kzg_commitment(&commitment, &p, s);
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
    return verify_kzg_proof_impl(ok, &commitment_g1, &z_fr, &y_fr, &proof_g1, s);
}

/**
 * Helper function: Verify KZG proof claiming that `p(z) == y`.
 *
 * Given a `commitment` to a polynomial, a `proof` for `z`, and the claimed value `y` at `z`, verify
 * the claim.
 *
 * @param[out]  ok          True if the proof is valid, otherwise false
 * @param[in]   commitment  The commitment to a polynomial
 * @param[in]   z           The point at which the proof is to be opened
 * @param[in]   y           The claimed value of the polynomial at `z`
 * @param[in]   proof       A proof of the value of the polynomial at `z`
 * @param[in]   s           The trusted setup
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
    g2_sub(&X_minus_z, &s->g2_values_monomial[1], &x_g2);

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
 * @param[out] y_out     The evaluation of the polynomial at the evaluation point z
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
 * Helper function for compute_kzg_proof() and compute_blob_kzg_proof().
 *
 * @param[out] proof_out  The combined proof as a single G1 element
 * @param[out] y_out      The evaluation of the polynomial at the evaluation point z
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
        &out_g1, s->g1_values_lagrange_brp, (const fr_t *)(&q.evals), FIELD_ELEMENTS_PER_BLOB
    );
    if (ret != C_KZG_OK) goto out;

    bytes_from_g1(proof_out, &out_g1);

out:
    c_kzg_free(inverses_in);
    c_kzg_free(inverses);
    return ret;
}

/**
 * Given a blob and a commitment, return the KZG proof that is used to verify it against the
 * commitment. This function does not verify that the commitment is correct with respect to the
 * blob.
 *
 * @param[out] out              The resulting proof
 * @param[in]  blob             A blob
 * @param[in]  commitment_bytes Commitment to verify
 * @param[in]  s                The trusted setup
 */
C_KZG_RET compute_blob_kzg_proof(
    KZGProof *out, const Blob *blob, const Bytes48 *commitment_bytes, const KZGSettings *s
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
    ret = compute_kzg_proof_impl(out, &y, &polynomial, &evaluation_challenge_fr, s);
    if (ret != C_KZG_OK) goto out;

out:
    return ret;
}

/**
 * Given a blob and its proof, verify that it corresponds to the provided commitment.
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
    ret = evaluate_polynomial_in_evaluation_form(&y_fr, &polynomial, &evaluation_challenge_fr, s);
    if (ret != C_KZG_OK) return ret;

    /* Call helper to do pairings check */
    return verify_kzg_proof_impl(ok, &commitment_g1, &evaluation_challenge_fr, &y_fr, &proof_g1, s);
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
static C_KZG_RET compute_r_powers_for_verify_kzg_proof_batch(
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

    size_t input_size = DOMAIN_STR_LENGTH + sizeof(uint64_t) + sizeof(uint64_t) +
                        (n * (BYTES_PER_COMMITMENT + 2 * BYTES_PER_FIELD_ELEMENT + BYTES_PER_PROOF)
                        );
    ret = c_kzg_malloc((void **)&bytes, input_size);
    if (ret != C_KZG_OK) goto out;

    /* Pointer tracking `bytes` for writing on top of it */
    uint8_t *offset = bytes;

    /* Copy domain separator */
    memcpy(offset, RANDOM_CHALLENGE_DOMAIN_VERIFY_BLOB_KZG_PROOF_BATCH, DOMAIN_STR_LENGTH);
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
 * Helper function for verify_blob_kzg_proof_batch(): actually perform the verification.
 *
 * @param[out] ok             True if the proofs are valid, otherwise false
 * @param[in]  commitments_g1 Array of commitments to verify
 * @param[in]  zs_fr          Array of evaluation points for the KZG proofs
 * @param[in]  ys_fr          Array of evaluation results for the KZG proofs
 * @param[in]  proofs_g1      Array of proofs used for verification
 * @param[in]  n              The number of blobs/commitments/proofs
 * @param[in]  s              The trusted setup
 *
 * @remark This function only works for `n > 0`.
 * @remark This function assumes that `n` is trusted and that all input arrays contain `n` elements.
 * `n` should be the actual size of the arrays and not read off a length field in the protocol.
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
    ret = compute_r_powers_for_verify_kzg_proof_batch(
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
    *ok = pairings_verify(&proof_lincomb, &s->g2_values_monomial[1], &rhs_g1, blst_p2_generator());

out:
    c_kzg_free(r_powers);
    c_kzg_free(C_minus_y);
    c_kzg_free(r_times_z);
    return ret;
}

/**
 * Given a list of blobs and blob KZG proofs, verify that they correspond to the provided
 * commitments.
 *
 * @param[out] ok                True if the proofs are valid, otherwise false
 * @param[in]  blobs             Array of blobs to verify
 * @param[in]  commitments_bytes Array of commitments to verify
 * @param[in]  proofs_bytes      Array of proofs used for verification
 * @param[in]  n                 The number of blobs/commitments/proofs
 * @param[in]  s                 The trusted setup
 *
 * @remark This function accepts if called with `n==0`.
 * @remark This function assumes that `n` is trusted and that all input arrays contain `n` elements.
 * `n` should be the actual size of the arrays and not read off a length field in the protocol.
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
        return verify_blob_kzg_proof(ok, &blobs[0], &commitments_bytes[0], &proofs_bytes[0], s);
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
        ret = bytes_to_kzg_commitment(&commitments_g1[i], &commitments_bytes[i]);
        if (ret != C_KZG_OK) goto out;

        /* Convert each blob from bytes to a poly */
        ret = blob_to_polynomial(&polynomial, &blobs[i]);
        if (ret != C_KZG_OK) goto out;

        compute_challenge(&evaluation_challenges_fr[i], &blobs[i], &commitments_g1[i]);

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

////////////////////////////////////////////////////////////////////////////////////////////////////
// FFT for G1 points
////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Utility function to test whether the argument is a power of two.
 *
 * @param[in] n The number to test
 *
 * @return True if `n` is zero or a power of two, otherwise false.
 *
 * @remark This method returns true for is_power_of_two(0) which is a bit weird, but not an issue in
 * the contexts in which we use it.
 *
 */
static bool is_power_of_two(uint64_t n) {
    return (n & (n - 1)) == 0;
}

/**
 * Fast Fourier Transform.
 *
 * Recursively divide and conquer.
 *
 * @param[out] out          The results (length `n`)
 * @param[in]  in           The input data (length `n * stride`)
 * @param[in]  stride       The input data stride
 * @param[in]  roots        Roots of unity (length `n * roots_stride`)
 * @param[in]  roots_stride The stride interval among the roots of unity
 * @param[in]  n            Length of the FFT, must be a power of two
 */
static void fft_g1_fast(
    g1_t *out, const g1_t *in, uint64_t stride, const fr_t *roots, uint64_t roots_stride, uint64_t n
) {
    g1_t y_times_root;
    uint64_t half = n / 2;
    if (half > 0) { /* Tunable parameter */
        fft_g1_fast(out, in, stride * 2, roots, roots_stride * 2, half);
        fft_g1_fast(out + half, in + stride, stride * 2, roots, roots_stride * 2, half);
        for (uint64_t i = 0; i < half; i++) {
            /* If the point is infinity, we can skip the calculation */
            if (blst_p1_is_inf(&out[i + half])) {
                out[i + half] = out[i];
            } else {
                /* If the scalar is one, we can skip the multiplication */
                if (fr_is_one(&roots[i * roots_stride])) {
                    y_times_root = out[i + half];
                } else {
                    g1_mul(&y_times_root, &out[i + half], &roots[i * roots_stride]);
                }
                g1_sub(&out[i + half], &out[i], &y_times_root);
                blst_p1_add_or_double(&out[i], &out[i], &y_times_root);
            }
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
 * @remark Use ifft_g1() for inverse transformation.
 */
C_KZG_RET fft_g1(g1_t *out, const g1_t *in, size_t n, const KZGSettings *s) {
    /* Ensure the length is valid */
    if (n > s->max_width || !is_power_of_two(n)) {
        return C_KZG_BADARGS;
    }

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
 * @remark Use fft_g1() for forward transformation.
 */
C_KZG_RET ifft_g1(g1_t *out, const g1_t *in, size_t n, const KZGSettings *s) {
    /* Ensure the length is valid */
    if (n > s->max_width || !is_power_of_two(n)) {
        return C_KZG_BADARGS;
    }

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

////////////////////////////////////////////////////////////////////////////////////////////////////
// Trusted Setup Functions
////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Reverse the bit order in a 32-bit integer.
 *
 * @param[in]   n   The integer to be reversed
 *
 * @return An integer with the bits of `n` reversed.
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
 * @param[in] n The power of two
 *
 * @return The log base two of n.
 *
 * @remark In other words, the bit index of the one bit.
 * @remark Works only for n a power of two, and only for n up to 2^31.
 * @remark Not the fastest implementation, but it doesn't need to be fast.
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
 * @param[in]   n       To reverse `b` bits, set `n = 2 ^ b`
 * @param[in]   value   The bits to be reversed
 *
 * @return The reversal of the lowest log_2(n) bits of the input value.
 *
 * @remark n must be a power of two.
 */
static uint32_t reverse_bits_limited(uint32_t n, uint32_t value) {
    size_t unused_bit_len = 32 - log2_pow2(n);
    return reverse_bits(value) >> unused_bit_len;
}

/**
 * Reorder an array in reverse bit order of its indices.
 *
 * @param[in,out] values The array, which is re-ordered in-place
 * @param[in]     size   The size in bytes of an element of the array
 * @param[in]     n      The length of the array, must be a power of two
 *                       strictly greater than 1 and less than 2^32.
 *
 * @remark Operates in-place on the array.
 * @remark Can handle arrays of any type: provide the element size in `size`.
 * @remark This means that `input[n] == output[n']`, where input and output denote the input and
 * output array and n' is obtained from n by bit-reversing n. As opposed to reverse_bits, this
 * bit-reversal operates on log2(n)-bit numbers.
 */
static C_KZG_RET bit_reversal_permutation(void *values, size_t size, uint64_t n) {
    C_KZG_RET ret;
    byte *tmp = NULL;
    byte *v = values;

    /* Some sanity checks */
    if (n < 2 || n >= UINT32_MAX || !is_power_of_two(n)) {
        ret = C_KZG_BADARGS;
        goto out;
    }

    /* Scratch space for swapping an entry of the values array */
    ret = c_kzg_malloc((void **)&tmp, size);
    if (ret != C_KZG_OK) goto out;

    /* Reorder elements */
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

out:
    c_kzg_free(tmp);
    return ret;
}

/**
 * Generate powers of a root of unity in the field.
 *
 * @param[out] out   The roots of unity (length `width + 1`)
 * @param[in]  root  A root of unity
 * @param[in]  width One less than the size of `out`
 *
 * @remark `root` must be such that `root ^ width` is equal to one, but no smaller power of `root`
 * is equal to one.
 */
static C_KZG_RET expand_root_of_unity(fr_t *out, const fr_t *root, uint64_t width) {
    uint64_t i;

    /* We assume it's at least two */
    if (width < 2) {
        return C_KZG_BADARGS;
    }

    /* We know what these will be */
    out[0] = FR_ONE;
    out[1] = *root;

    /* Compute powers of root */
    for (i = 2; i <= width; i++) {
        blst_fr_mul(&out[i], &out[i - 1], root);
        if (fr_is_one(&out[i])) break;
    }

    /* We expect the last entry to be one */
    if (i != width || !fr_is_one(&out[width])) {
        return C_KZG_BADARGS;
    }

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

    /* Ensure this element will exist */
    if (max_scale >= NUM_ELEMENTS(SCALE2_ROOT_OF_UNITY)) {
        return C_KZG_BADARGS;
    }

    /* Get the root of unity */
    blst_fr_from_uint64(&root_of_unity, SCALE2_ROOT_OF_UNITY[max_scale]);

    /* Populate the roots of unity */
    ret = expand_root_of_unity(s->expanded_roots_of_unity, &root_of_unity, s->max_width);
    if (ret != C_KZG_OK) goto out;

    /* Copy all but the last root to the roots of unity */
    memcpy(s->roots_of_unity, s->expanded_roots_of_unity, sizeof(fr_t) * s->max_width);

    /* Permute the roots of unity */
    ret = bit_reversal_permutation(s->roots_of_unity, sizeof(fr_t), s->max_width);
    if (ret != C_KZG_OK) goto out;

    /* Populate reverse roots of unity */
    for (uint64_t i = 0; i <= s->max_width; i++) {
        s->reverse_roots_of_unity[i] = s->expanded_roots_of_unity[s->max_width - i];
    }

out:
    return ret;
}

/**
 * Free a trusted setup (KZGSettings).
 *
 * @param[in] s The trusted setup to free
 *
 * @remark This does nothing if `s` is NULL.
 */
void free_trusted_setup(KZGSettings *s) {
    if (s == NULL) return;
    s->max_width = 0;
    c_kzg_free(s->roots_of_unity);
    c_kzg_free(s->expanded_roots_of_unity);
    c_kzg_free(s->reverse_roots_of_unity);
    c_kzg_free(s->g1_values_monomial);
    c_kzg_free(s->g1_values_lagrange_brp);
    c_kzg_free(s->g2_values_monomial);

    /*
     * If for whatever reason we accidentally call free_trusted_setup() on an uninitialized
     * structure, we don't want to deference these 2d arrays.  Without these NULL checks, it's
     * possible for there to be a segmentation fault via null pointer dereference.
     */
    if (s->x_ext_fft_columns != NULL) {
        for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
            c_kzg_free(s->x_ext_fft_columns[i]);
        }
    }
    if (s->tables != NULL) {
        for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
            c_kzg_free(s->tables[i]);
        }
    }
    c_kzg_free(s->x_ext_fft_columns);
    c_kzg_free(s->tables);
    s->wbits = 0;
    s->scratch_size = 0;
}

/**
 * The first part of the Toeplitz matrix multiplication algorithm: the Fourier transform of the
 * vector x extended.
 *
 * @param[out]  out The FFT of the extension of x, size n * 2
 * @param[in]   x   The input vector, size n
 * @param[in]   n   The length of the input vector x
 * @param[in]   s   The trusted setup
 */
static C_KZG_RET toeplitz_part_1(g1_t *out, const g1_t *x, size_t n, const KZGSettings *s) {
    C_KZG_RET ret;
    size_t n2 = n * 2;
    g1_t *x_ext;

    /* Create extended array of points */
    ret = new_g1_array(&x_ext, n2);
    if (ret != C_KZG_OK) goto out;

    /* Copy x & extend with zero */
    for (size_t i = 0; i < n; i++) {
        x_ext[i] = x[i];
    }
    for (size_t i = n; i < n2; i++) {
        x_ext[i] = G1_IDENTITY;
    }

    /* Peform forward transformation */
    ret = fft_g1(out, x_ext, n2, s);
    if (ret != C_KZG_OK) goto out;

out:
    c_kzg_free(x_ext);
    return ret;
}

/**
 * Initialize fields for FK20 multi-proof computations.
 *
 * @param[out]  s   Pointer to KZGSettings to initialize
 */
static C_KZG_RET init_fk20_multi_settings(KZGSettings *s) {
    C_KZG_RET ret;
    uint64_t n, k, k2;
    g1_t *x = NULL;
    g1_t *points = NULL;
    blst_p1_affine *p_affine = NULL;
    bool precompute = s->wbits != 0;

    n = s->max_width / 2;
    k = n / FIELD_ELEMENTS_PER_CELL;
    k2 = 2 * k;

    if (FIELD_ELEMENTS_PER_CELL >= NUM_G2_POINTS) {
        ret = C_KZG_BADARGS;
        goto out;
    }

    /* Allocate space for arrays */
    ret = new_g1_array(&x, k);
    if (ret != C_KZG_OK) goto out;
    ret = new_g1_array(&points, k2);
    if (ret != C_KZG_OK) goto out;

    /* Allocate space for array of pointers, this is a 2D array */
    ret = c_kzg_calloc((void **)&s->x_ext_fft_columns, k2, sizeof(void *));
    if (ret != C_KZG_OK) goto out;
    for (size_t i = 0; i < k2; i++) {
        ret = new_g1_array(&s->x_ext_fft_columns[i], FIELD_ELEMENTS_PER_CELL);
        if (ret != C_KZG_OK) goto out;
    }

    for (size_t offset = 0; offset < FIELD_ELEMENTS_PER_CELL; offset++) {
        /* Compute x, sections of the g1 values */
        size_t start = n - FIELD_ELEMENTS_PER_CELL - 1 - offset;
        for (size_t i = 0; i < k - 1; i++) {
            size_t j = start - i * FIELD_ELEMENTS_PER_CELL;
            x[i] = s->g1_values_monomial[j];
        }
        x[k - 1] = G1_IDENTITY;

        /* Compute points, the fft of an extended x */
        ret = toeplitz_part_1(points, x, k, s);
        if (ret != C_KZG_OK) goto out;

        /* Reorganize from rows into columns */
        for (size_t row = 0; row < k2; row++) {
            s->x_ext_fft_columns[row][offset] = points[row];
        }
    }

    if (precompute) {
        /* Allocate space for precomputed tables */
        ret = c_kzg_calloc((void **)&s->tables, k2, sizeof(void *));
        if (ret != C_KZG_OK) goto out;

        /* Allocate space for points in affine representation */
        ret = c_kzg_calloc((void **)&p_affine, FIELD_ELEMENTS_PER_CELL, sizeof(blst_p1_affine));
        if (ret != C_KZG_OK) goto out;

        /* Calculate the size of each table, this can be re-used */
        size_t table_size = blst_p1s_mult_wbits_precompute_sizeof(
            s->wbits, FIELD_ELEMENTS_PER_CELL
        );

        for (size_t i = 0; i < k2; i++) {
            /* Transform the points to affine representation */
            const blst_p1 *p_arg[2] = {s->x_ext_fft_columns[i], NULL};
            blst_p1s_to_affine(p_affine, p_arg, FIELD_ELEMENTS_PER_CELL);
            const blst_p1_affine *points_arg[2] = {p_affine, NULL};

            /* Allocate space for the table */
            ret = c_kzg_malloc((void **)&s->tables[i], table_size);
            if (ret != C_KZG_OK) goto out;

            /* Compute table for fixed-base MSM */
            blst_p1s_mult_wbits_precompute(
                s->tables[i], s->wbits, points_arg, FIELD_ELEMENTS_PER_CELL
            );
        }

        /* Calculate the size of the scratch */
        s->scratch_size = blst_p1s_mult_wbits_scratch_sizeof(FIELD_ELEMENTS_PER_CELL);
    }

out:
    c_kzg_free(x);
    c_kzg_free(points);
    c_kzg_free(p_affine);
    return ret;
}

/**
 * Basic sanity check that the trusted setup was loaded in Lagrange form.
 *
 * @param[in] s  Pointer to the stored trusted setup data
 * @param[in] n1 Number of `g1` points in trusted_setup
 * @param[in] n2 Number of `g2` points in trusted_setup
 */
static C_KZG_RET is_trusted_setup_in_lagrange_form(const KZGSettings *s, size_t n1, size_t n2) {
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
        &s->g1_values_lagrange_brp[1],
        &s->g2_values_monomial[0],
        &s->g1_values_lagrange_brp[0],
        &s->g2_values_monomial[1]
    );
    return is_monomial_form ? C_KZG_BADARGS : C_KZG_OK;
}

/**
 * Load trusted setup into a KZGSettings.
 *
 * @param[out]  out                     Pointer to the stored trusted setup
 * @param[in]   g1_monomial_bytes       Array of G1 points in monomial form
 * @param[in]   num_g1_monomial_bytes   Number of g1 monomial bytes
 * @param[in]   g1_lagrange_bytes       Array of G1 points in Lagrange form
 * @param[in]   num_g1_lagrange_bytes   Number of g1 Lagrange bytes
 * @param[in]   g2_monomial_bytes       Array of G2 points in monomial form
 * @param[in]   num_g2_monomial_bytes   Number of g2 monomial bytes
 * @param[in]   precompute              Configurable value between 0-15
 *
 * @remark Free afterwards use with free_trusted_setup().
 */
C_KZG_RET load_trusted_setup(
    KZGSettings *out,
    const uint8_t *g1_monomial_bytes,
    size_t num_g1_monomial_bytes,
    const uint8_t *g1_lagrange_bytes,
    size_t num_g1_lagrange_bytes,
    const uint8_t *g2_monomial_bytes,
    size_t num_g2_monomial_bytes,
    size_t precompute
) {
    C_KZG_RET ret;

    out->max_width = 0;
    out->roots_of_unity = NULL;
    out->expanded_roots_of_unity = NULL;
    out->reverse_roots_of_unity = NULL;
    out->g1_values_monomial = NULL;
    out->g1_values_lagrange_brp = NULL;
    out->g2_values_monomial = NULL;
    out->x_ext_fft_columns = NULL;
    out->tables = NULL;

    /* It seems that blst limits the input to 15 */
    if (precompute > 15) {
        ret = C_KZG_BADARGS;
        goto out_error;
    }

    /*
     * This is the window size for the windowed multiplication in proof generation. The larger wbits
     * is, the faster the MSM will be, but the size of the precomputed table will grow
     * exponentially. With 8 bits, the tables are 96 MiB; with 9 bits, the tables are 192 MiB and so
     * forth. From our testing, there are diminishing returns after 8 bits.
     */
    out->wbits = precompute;

    /* Sanity check in case this is called directly */
    if (num_g1_monomial_bytes != NUM_G1_POINTS * BYTES_PER_G1 ||
        num_g1_lagrange_bytes != NUM_G1_POINTS * BYTES_PER_G1 ||
        num_g2_monomial_bytes != NUM_G2_POINTS * BYTES_PER_G2) {
        ret = C_KZG_BADARGS;
        goto out_error;
    }

    /* 1<<max_scale is the smallest power of 2 >= n1 */
    uint32_t max_scale = 0;
    while ((1ULL << max_scale) < NUM_G1_POINTS)
        max_scale++;

    /* Set the max_width */
    out->max_width = 1ULL << max_scale;

    /* For DAS reconstruction */
    out->max_width *= 2;

    /* Allocate all of our arrays */
    ret = new_fr_array(&out->roots_of_unity, out->max_width);
    if (ret != C_KZG_OK) goto out_error;
    ret = new_fr_array(&out->expanded_roots_of_unity, out->max_width + 1);
    if (ret != C_KZG_OK) goto out_error;
    ret = new_fr_array(&out->reverse_roots_of_unity, out->max_width + 1);
    if (ret != C_KZG_OK) goto out_error;
    ret = new_g1_array(&out->g1_values_monomial, NUM_G1_POINTS);
    if (ret != C_KZG_OK) goto out_error;
    ret = new_g1_array(&out->g1_values_lagrange_brp, NUM_G1_POINTS);
    if (ret != C_KZG_OK) goto out_error;
    ret = new_g2_array(&out->g2_values_monomial, NUM_G2_POINTS);
    if (ret != C_KZG_OK) goto out_error;

    /* Convert all g1 monomial bytes to g1 points */
    for (uint64_t i = 0; i < NUM_G1_POINTS; i++) {
        blst_p1_affine g1_affine;
        BLST_ERROR err = blst_p1_uncompress(&g1_affine, &g1_monomial_bytes[BYTES_PER_G1 * i]);
        if (err != BLST_SUCCESS) {
            ret = C_KZG_BADARGS;
            goto out_error;
        }
        blst_p1_from_affine(&out->g1_values_monomial[i], &g1_affine);
    }

    /* Convert all g1 Lagrange bytes to g1 points */
    for (uint64_t i = 0; i < NUM_G1_POINTS; i++) {
        blst_p1_affine g1_affine;
        BLST_ERROR err = blst_p1_uncompress(&g1_affine, &g1_lagrange_bytes[BYTES_PER_G1 * i]);
        if (err != BLST_SUCCESS) {
            ret = C_KZG_BADARGS;
            goto out_error;
        }
        blst_p1_from_affine(&out->g1_values_lagrange_brp[i], &g1_affine);
    }

    /* Convert all g2 bytes to g2 points */
    for (uint64_t i = 0; i < NUM_G2_POINTS; i++) {
        blst_p2_affine g2_affine;
        BLST_ERROR err = blst_p2_uncompress(&g2_affine, &g2_monomial_bytes[BYTES_PER_G2 * i]);
        if (err != BLST_SUCCESS) {
            ret = C_KZG_BADARGS;
            goto out_error;
        }
        blst_p2_from_affine(&out->g2_values_monomial[i], &g2_affine);
    }

    /* Make sure the trusted setup was loaded in Lagrange form */
    ret = is_trusted_setup_in_lagrange_form(out, NUM_G1_POINTS, NUM_G2_POINTS);
    if (ret != C_KZG_OK) goto out_error;

    /* Compute roots of unity and permute the G1 trusted setup */
    ret = compute_roots_of_unity(out);
    if (ret != C_KZG_OK) goto out_error;

    /* Bit reverse the Lagrange form points */
    ret = bit_reversal_permutation(out->g1_values_lagrange_brp, sizeof(g1_t), NUM_G1_POINTS);
    if (ret != C_KZG_OK) goto out_error;

    /* Setup for FK20 proof computation */
    ret = init_fk20_multi_settings(out);
    if (ret != C_KZG_OK) goto out_error;

    goto out_success;

out_error:
    /*
     * Note: this only frees the fields in the KZGSettings structure. It does not free the
     * KZGSettings structure memory. If necessary, that must be done by the caller.
     */
    free_trusted_setup(out);
out_success:
    return ret;
}

/**
 * Load trusted setup from a file.
 *
 * @param[out]  out         Pointer to the loaded trusted setup data
 * @param[in]   in          File handle for input
 * @param[in]   precompute  Configurable value between 0-15
 *
 * @remark See also load_trusted_setup().
 * @remark The input file will not be closed.
 * @remark The file format is `n1 n2 g1_1 g1_2 ... g1_n1 g2_1 ... g2_n2` where the first two numbers
 * are in decimal and the remainder are hexstrings and any whitespace can be used as separators.
 */
C_KZG_RET load_trusted_setup_file(KZGSettings *out, FILE *in, size_t precompute) {
    C_KZG_RET ret;
    int num_matches;
    uint64_t i;
    uint8_t *g1_monomial_bytes = NULL;
    uint8_t *g1_lagrange_bytes = NULL;
    uint8_t *g2_monomial_bytes = NULL;

    /* Allocate space for points */
    ret = c_kzg_calloc((void **)&g1_monomial_bytes, NUM_G1_POINTS, BYTES_PER_G1);
    if (ret != C_KZG_OK) goto out;
    ret = c_kzg_calloc((void **)&g1_lagrange_bytes, NUM_G1_POINTS, BYTES_PER_G1);
    if (ret != C_KZG_OK) goto out;
    ret = c_kzg_calloc((void **)&g2_monomial_bytes, NUM_G2_POINTS, BYTES_PER_G2);
    if (ret != C_KZG_OK) goto out;

    /* Read the number of g1 points */
    num_matches = fscanf(in, "%" SCNu64, &i);
    if (num_matches != 1 || i != NUM_G1_POINTS) {
        ret = C_KZG_BADARGS;
        goto out;
    }

    /* Read the number of g2 points */
    num_matches = fscanf(in, "%" SCNu64, &i);
    if (num_matches != 1 || i != NUM_G2_POINTS) {
        ret = C_KZG_BADARGS;
        goto out;
    }

    /* Read all of the g1 points in Lagrange form, byte by byte */
    for (i = 0; i < NUM_G1_POINTS * BYTES_PER_G1; i++) {
        num_matches = fscanf(in, "%2hhx", &g1_lagrange_bytes[i]);
        if (num_matches != 1) {
            ret = C_KZG_BADARGS;
            goto out;
        }
    }

    /* Read all of the g2 points in monomial form, byte by byte */
    for (i = 0; i < NUM_G2_POINTS * BYTES_PER_G2; i++) {
        num_matches = fscanf(in, "%2hhx", &g2_monomial_bytes[i]);
        if (num_matches != 1) {
            ret = C_KZG_BADARGS;
            goto out;
        }
    }

    /* Read all of the g1 points in monomial form, byte by byte */
    /* Note: this is last because it is an extension for EIP-7594 */
    for (i = 0; i < NUM_G1_POINTS * BYTES_PER_G1; i++) {
        num_matches = fscanf(in, "%2hhx", &g1_monomial_bytes[i]);
        if (num_matches != 1) {
            ret = C_KZG_BADARGS;
            goto out;
        }
    }

    ret = load_trusted_setup(
        out,
        g1_monomial_bytes,
        NUM_G1_POINTS * BYTES_PER_G1,
        g1_lagrange_bytes,
        NUM_G1_POINTS * BYTES_PER_G1,
        g2_monomial_bytes,
        NUM_G2_POINTS * BYTES_PER_G2,
        precompute
    );

out:
    c_kzg_free(g1_monomial_bytes);
    c_kzg_free(g1_lagrange_bytes);
    c_kzg_free(g2_monomial_bytes);
    return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Fast Fourier Transform
////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Fast Fourier Transform.
 *
 * Recursively divide and conquer.
 *
 * @param[out]  out             The results (length `n`)
 * @param[in]   in              The input data (length `n * stride`)
 * @param[in]   stride          The input data stride
 * @param[in]   roots           Roots of unity (length `n * roots_stride`)
 * @param[in]   roots_stride    The stride interval among the roots of unity
 * @param[in]   n               Length of the FFT, must be a power of two
 */
static void fft_fr_fast(
    fr_t *out, const fr_t *in, size_t stride, const fr_t *roots, size_t roots_stride, size_t n
) {
    size_t half = n / 2;
    if (half > 0) {
        fr_t y_times_root;
        fft_fr_fast(out, in, stride * 2, roots, roots_stride * 2, half);
        fft_fr_fast(out + half, in + stride, stride * 2, roots, roots_stride * 2, half);
        for (size_t i = 0; i < half; i++) {
            blst_fr_mul(&y_times_root, &out[i + half], &roots[i * roots_stride]);
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
 * @param[out]  out The results (array of length n)
 * @param[in]   in  The input data (array of length n)
 * @param[in]   n   Length of the arrays
 * @param[in]   s   The trusted setup
 *
 * @remark The array lengths must be a power of two.
 * @remark Use ifft_fr() for inverse transformation.
 */
static C_KZG_RET fft_fr(fr_t *out, const fr_t *in, size_t n, const KZGSettings *s) {
    /* Ensure the length is valid */
    if (n > s->max_width || !is_power_of_two(n)) {
        return C_KZG_BADARGS;
    }

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
 * @remark Use fft_fr() for forward transformation.
 */
static C_KZG_RET ifft_fr(fr_t *out, const fr_t *in, size_t n, const KZGSettings *s) {
    /* Ensure the length is valid */
    if (n > s->max_width || !is_power_of_two(n)) {
        return C_KZG_BADARGS;
    }

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

////////////////////////////////////////////////////////////////////////////////////////////////////
// Zero poly
////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Calculates the minimal polynomial that evaluates to zero for each root.
 *
 * Uses straightforward long multiplication to calculate the product of `(x - r_i)` where `r_i` is
 * the i'th root. This results in a poly of degree roots_len.
 *
 * @param[in,out]   poly         The zero polynomial for roots
 * @param[in,out]   poly_len     The length of poly
 * @param[in]       roots        The array of roots
 * @param[in]       roots_len    The number of roots
 * @param[in]       s            The trusted setup
 *
 * @remark These do not have to be roots of unity. They are roots of a polynomial.
 * @remark `poly_len` must be at least `roots_len + 1` in length.
 */
static C_KZG_RET compute_vanishing_polynomial_from_roots(
    fr_t *poly, size_t *poly_len, const fr_t *roots, size_t roots_len
) {
    fr_t neg_root;

    if (roots_len == 0) {
        return C_KZG_BADARGS;
    }

    /* Initialize with -root[0] */
    blst_fr_cneg(&poly[0], &roots[0], true);

    for (size_t i = 1; i < roots_len; i++) {
        blst_fr_cneg(&neg_root, &roots[i], true);

        poly[i] = neg_root;
        blst_fr_add(&poly[i], &poly[i], &poly[i - 1]);

        for (size_t j = i - 1; j > 0; j--) {
            blst_fr_mul(&poly[j], &poly[j], &neg_root);
            blst_fr_add(&poly[j], &poly[j], &poly[j - 1]);
        }
        blst_fr_mul(&poly[0], &poly[0], &neg_root);
    }

    poly[roots_len] = FR_ONE;
    *poly_len = roots_len + 1;

    return C_KZG_OK;
}

/**
 * Computes the minimal polynomial that evaluates to zero at equally spaced chosen roots of unity in
 * the domain of size `FIELD_ELEMENTS_PER_BLOB`.
 *
 * The roots of unity are chosen based on the missing cell indices. If the i'th cell is missing,
 * then the i'th root of unity from `expanded_roots_of_unity` will be zero on the polynomial
 * computed, along with every `CELLS_PER_EXT_BLOB` spaced root of unity in the domain.
 *
 * @param[in,out]   vanishing_poly          The vanishing polynomial
 * @param[in]       missing_cell_indices    The array of missing cell indices
 * @param[in]       len_missing_cells       The number of missing cell indices
 * @param[in]       s                       The trusted setup
 *
 * @remark When all of the cells are missing, this algorithm has an edge case. We return
 * C_KZG_BADARGS in that case.
 * @remark When none of the cells are missing, recovery is trivial. We expect the caller to handle
 * this case, and return C_KZG_BADARGS if not.
 * @remark `missing_cell_indices` are assumed to be less than `CELLS_PER_EXT_BLOB`.
 */
static C_KZG_RET vanishing_polynomial_for_missing_cells(
    fr_t *vanishing_poly,
    const uint64_t *missing_cell_indices,
    size_t len_missing_cells,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    fr_t *roots = NULL;
    fr_t *short_vanishing_poly = NULL;
    size_t short_vanishing_poly_len = 0;

    /* Return early if none or all of the cells are missing */
    if (len_missing_cells == 0 || len_missing_cells == CELLS_PER_EXT_BLOB) {
        ret = C_KZG_BADARGS;
        goto out;
    }

    /* Allocate arrays */
    ret = new_fr_array(&roots, len_missing_cells);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&short_vanishing_poly, (len_missing_cells + 1));
    if (ret != C_KZG_OK) goto out;

    /* Check if max_width is divisible by CELLS_PER_EXT_BLOB */
    assert(s->max_width % CELLS_PER_EXT_BLOB == 0);

    /*
     * For each missing cell index, choose the corresponding root of unity from the subgroup of
     * size `CELLS_PER_EXT_BLOB`.
     *
     * In other words, if the missing index is `i`, then we add \omega^i to the roots array, where
     * \omega is a primitive `CELLS_PER_EXT_BLOB` root of unity.
     */
    size_t stride = s->max_width / CELLS_PER_EXT_BLOB;
    for (size_t i = 0; i < len_missing_cells; i++) {
        roots[i] = s->expanded_roots_of_unity[missing_cell_indices[i] * stride];
    }

    /* Compute the polynomial that evaluates to zero on the roots */
    ret = compute_vanishing_polynomial_from_roots(
        short_vanishing_poly, &short_vanishing_poly_len, roots, len_missing_cells
    );
    if (ret != C_KZG_OK) goto out;

    /*
     * For each root \omega^i in `short_vanishing_poly`, we compute a polynomial that has roots at
     *
     *  H = {
     *      \omega^i * \gamma^0,
     *      \omega^i * \gamma^1,
     *      ...,
     *      \omega^i * \gamma^{FIELD_ELEMENTS_PER_CELL-1}
     *  }
     *
     * where \gamma is a primitive `FIELD_ELEMENTS_PER_EXT_BLOB`-th root of unity.
     *
     * This is done by shifting the degree of all coefficients in `short_vanishing_poly` up by
     * `FIELD_ELEMENTS_PER_CELL` amount.
     */
    for (size_t i = 0; i < short_vanishing_poly_len; i++) {
        vanishing_poly[i * FIELD_ELEMENTS_PER_CELL] = short_vanishing_poly[i];
    }

out:
    c_kzg_free(roots);
    c_kzg_free(short_vanishing_poly);
    return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Cell Recovery
////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * The coset shift factor for the cell recovery code.
 *
 *   fr_t a;
 *   fr_from_uint64(&a, 7);
 *   for (size_t i = 0; i < 4; i++)
 *       printf("%#018llxL,\n", a.l[i]);
 */
static const fr_t RECOVERY_SHIFT_FACTOR = {
    0x0000000efffffff1L,
    0x17e363d300189c0fL,
    0xff9c57876f8457b0L,
    0x351332208fc5a8c4L,
};

/**
 * The inverse of RECOVERY_SHIFT_FACTOR.
 *
 *   fr_t a;
 *   fr_from_uint64(&a, 7);
 *   fr_div(&a, &FR_ONE, &a);
 *   for (size_t i = 0; i < 4; i++)
 *       printf("%#018llxL,\n", a.l[i]);
 */
static const fr_t INV_RECOVERY_SHIFT_FACTOR = {
    0xdb6db6dadb6db6dcL,
    0xe6b5824adb6cc6daL,
    0xf8b356e005810db9L,
    0x66d0f1e660ec4796L,
};

/**
 * Shift a polynomial in place.
 *
 * Multiplies each coefficient by `shift_factor ^ i`. Equivalent to creating a polynomial that
 * evaluates at `x * shift_factor` rather than `x`.
 *
 * @param[in,out]   p            The polynomial coefficients to be scaled
 * @param[in]       len          Length of the polynomial coefficients
 * @param[in]       shift_factor Shift factor
 */
static void shift_poly(fr_t *p, size_t len, const fr_t *shift_factor) {
    fr_t factor_power = FR_ONE;
    for (size_t i = 1; i < len; i++) {
        blst_fr_mul(&factor_power, &factor_power, shift_factor);
        blst_fr_mul(&p[i], &p[i], &factor_power);
    }
}

/**
 * Do an FFT over a coset of the roots of unity.
 *
 * @param[out]  out The results (array of length n)
 * @param[in]   in  The input data (array of length n)
 * @param[in]   n   Length of the arrays
 * @param[in]   s   The trusted setup
 *
 * @remark The coset shift factor is RECOVERY_SHIFT_FACTOR.
 */
static C_KZG_RET coset_fft_fr(fr_t *out, const fr_t *in, size_t n, const KZGSettings *s) {
    C_KZG_RET ret;
    fr_t *in_shifted = NULL;

    /* Create some room to shift the polynomial */
    ret = new_fr_array(&in_shifted, n);
    if (ret != C_KZG_OK) goto out;

    /* Shift the poly */
    memcpy(in_shifted, in, n * sizeof(fr_t));
    shift_poly(in_shifted, n, &RECOVERY_SHIFT_FACTOR);

    ret = fft_fr(out, in_shifted, n, s);
    if (ret != C_KZG_OK) goto out;

out:
    c_kzg_free(in_shifted);
    return ret;
}

/**
 * Do an inverse FFT over a coset of the roots of unity.
 *
 * @param[out]  out The results (array of length n)
 * @param[in]   in  The input data (array of length n)
 * @param[in]   n   Length of the arrays
 * @param[in]   s   The trusted setup
 *
 * @remark The coset shift factor is RECOVERY_SHIFT_FACTOR. In this function we use its inverse to
 * implement the IFFT.
 */
static C_KZG_RET coset_ifft_fr(fr_t *out, const fr_t *in, size_t n, const KZGSettings *s) {
    C_KZG_RET ret;

    ret = ifft_fr(out, in, n, s);
    if (ret != C_KZG_OK) goto out;

    shift_poly(out, n, &INV_RECOVERY_SHIFT_FACTOR);

out:
    return ret;
}

/**
 * Helper function to check if a uint64 value is in an array.
 *
 * @param[in]   arr         The array
 * @param[in]   arr_size    The size of the array
 * @param[in]   value       The value we want to search
 *
 * @return True if the value is in the array, otherwise false.
 */
static bool is_in_array(const uint64_t *arr, size_t arr_size, uint64_t value) {
    for (size_t i = 0; i < arr_size; i++) {
        if (arr[i] == value) {
            return true;
        }
    }
    return false;
}

/**
 * Given a dataset with up to half the entries missing, return the reconstructed original. Assumes
 * that the inverse FFT of the original data has the upper half of its values equal to zero.
 *
 * @param[out]  reconstructed_data_out   Preallocated array for recovered cells
 * @param[in]   cell_indices             The cell indices you have
 * @param[in]   num_cells                The number of cells that you have
 * @param[in]   cells                    The cells that you have
 * @param[in]   s                        The trusted setup
 *
 * @remark `recovered` and `cells` can point to the same memory.
 * @remark The array of cells must be 2n length and in the correct order.
 * @remark Missing cells should be equal to FR_NULL.
 */
static C_KZG_RET recover_cells_impl(
    fr_t *reconstructed_data_out,
    const uint64_t *cell_indices,
    size_t num_cells,
    fr_t *cells,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    uint64_t *missing_cell_indices = NULL;
    fr_t *vanishing_poly_eval = NULL;
    fr_t *vanishing_poly_coeff = NULL;
    fr_t *extended_evaluation_times_zero = NULL;
    fr_t *extended_evaluation_times_zero_coeffs = NULL;
    fr_t *extended_evaluations_over_coset = NULL;
    fr_t *vanishing_poly_over_coset = NULL;
    fr_t *reconstructed_poly_coeff = NULL;
    fr_t *cells_brp = NULL;

    /* Allocate space for arrays */
    ret = c_kzg_calloc((void **)&missing_cell_indices, s->max_width, sizeof(uint64_t));
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&vanishing_poly_eval, s->max_width);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&vanishing_poly_coeff, s->max_width);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&extended_evaluation_times_zero, s->max_width);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&extended_evaluation_times_zero_coeffs, s->max_width);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&extended_evaluations_over_coset, s->max_width);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&vanishing_poly_over_coset, s->max_width);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&reconstructed_poly_coeff, s->max_width);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&cells_brp, s->max_width);
    if (ret != C_KZG_OK) goto out;

    /* Bit-reverse the data points, stored in new array */
    memcpy(cells_brp, cells, s->max_width * sizeof(fr_t));
    ret = bit_reversal_permutation(cells_brp, sizeof(fr_t), s->max_width);
    if (ret != C_KZG_OK) goto out;

    /* Identify missing cells */
    size_t len_missing = 0;
    for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
        /* Iterate over each cell index and check if we have received it */
        if (!is_in_array(cell_indices, num_cells, i)) {
            /*
             * If the cell is missing, bit reverse the index and add it to the
             * missing array.
             */
            uint32_t brp_i = reverse_bits_limited(CELLS_PER_EXT_BLOB, i);
            missing_cell_indices[len_missing++] = brp_i;
        }
    }

    /* Check that we have enough cells */
    assert(len_missing <= CELLS_PER_EXT_BLOB / 2);

    /* Compute Z(x) in monomial form */
    ret = vanishing_polynomial_for_missing_cells(
        vanishing_poly_coeff, missing_cell_indices, len_missing, s
    );
    if (ret != C_KZG_OK) goto out;

    /* Convert Z(x) to evaluation form */
    ret = fft_fr(vanishing_poly_eval, vanishing_poly_coeff, s->max_width, s);
    if (ret != C_KZG_OK) goto out;

    /* Compute (E*Z)(x) = E(x) * Z(x) in evaluation form over the FFT domain */
    for (size_t i = 0; i < s->max_width; i++) {
        if (fr_is_null(&cells_brp[i])) {
            extended_evaluation_times_zero[i] = FR_ZERO;
        } else {
            blst_fr_mul(&extended_evaluation_times_zero[i], &cells_brp[i], &vanishing_poly_eval[i]);
        }
    }

    /* Convert (E*Z)(x) to monomial form  */
    ret = ifft_fr(
        extended_evaluation_times_zero_coeffs, extended_evaluation_times_zero, s->max_width, s
    );
    if (ret != C_KZG_OK) goto out;

    /*
     * Polynomial division by convolution: Q3 = Q1 / Q2 where
     *   Q1 = (D * Z_r,I)(k * x)
     *   Q2 = Z_r,I(k * x)
     *   Q3 = D(k * x)
     */
    ret = coset_fft_fr(
        extended_evaluations_over_coset, extended_evaluation_times_zero_coeffs, s->max_width, s
    );
    if (ret != C_KZG_OK) goto out;

    ret = coset_fft_fr(vanishing_poly_over_coset, vanishing_poly_coeff, s->max_width, s);
    if (ret != C_KZG_OK) goto out;

    /* The result of the division is Q3 */
    for (size_t i = 0; i < s->max_width; i++) {
        fr_div(
            &extended_evaluations_over_coset[i],
            &extended_evaluations_over_coset[i],
            &vanishing_poly_over_coset[i]
        );
    }

    /*
     * Note: After the above polynomial division, extended_evaluations_over_coset is the same
     * polynomial as reconstructed_poly_over_coset in the spec.
     */

    /* Convert the evaluations back to coefficents */
    ret = coset_ifft_fr(reconstructed_poly_coeff, extended_evaluations_over_coset, s->max_width, s);
    if (ret != C_KZG_OK) goto out;

    /*
     * After unscaling the reconstructed polynomial, we have D(x) which evaluates to our original
     * data at the roots of unity. Next, we evaluate the polynomial to get the original data.
     */
    ret = fft_fr(reconstructed_data_out, reconstructed_poly_coeff, s->max_width, s);
    if (ret != C_KZG_OK) goto out;

    /* Bit-reverse the recovered data points */
    ret = bit_reversal_permutation(reconstructed_data_out, sizeof(fr_t), s->max_width);
    if (ret != C_KZG_OK) goto out;

out:
    c_kzg_free(missing_cell_indices);
    c_kzg_free(vanishing_poly_eval);
    c_kzg_free(extended_evaluation_times_zero);
    c_kzg_free(extended_evaluation_times_zero_coeffs);
    c_kzg_free(extended_evaluations_over_coset);
    c_kzg_free(vanishing_poly_over_coset);
    c_kzg_free(reconstructed_poly_coeff);
    c_kzg_free(vanishing_poly_coeff);
    c_kzg_free(cells_brp);
    return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Polynomial Conversion Functions
////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Bit reverses and converts a polynomial in lagrange form to monomial form.
 *
 * @param[out]  monomial    The result, an array of `len` fields
 * @param[in]   lagrange    The input poly, an array of `len` fields
 * @param[in]   len         The length of both polynomials
 * @param[in]   s           The trusted setup
 *
 * @remark This method converts a lagrange-form polynomial to a monomial-form polynomial, by inverse
 * FFTing the bit-reverse-permuted lagrange polynomial.
 */
static C_KZG_RET poly_lagrange_to_monomial(
    fr_t *monomial_out, const fr_t *lagrange, size_t len, const KZGSettings *s
) {
    C_KZG_RET ret;
    fr_t *lagrange_brp = NULL;

    /* Allocate space for the intermediate BRP poly */
    ret = new_fr_array(&lagrange_brp, len);
    if (ret != C_KZG_OK) goto out;

    /* Copy the values and perform a bit reverse permutation */
    memcpy(lagrange_brp, lagrange, sizeof(fr_t) * len);
    ret = bit_reversal_permutation(lagrange_brp, sizeof(fr_t), len);
    if (ret != C_KZG_OK) goto out;

    /* Perform an inverse FFT on the BRP'd polynomial */
    ret = ifft_fr(monomial_out, lagrange_brp, len, s);
    if (ret != C_KZG_OK) goto out;

out:
    c_kzg_free(lagrange_brp);
    return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Cell Proofs
////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Reorder and extend polynomial coefficients for the toeplitz method, strided version.
 *
 * @param[out]  out     The reordered polynomial, size `n * 2 / stride`
 * @param[in]   in      The input polynomial, size `n`
 * @param[in]   n       The size of the input polynomial
 * @param[in]   offset  The offset
 * @param[in]   stride  The stride
 */
static C_KZG_RET toeplitz_coeffs_stride(
    fr_t *out, const fr_t *in, size_t n, uint64_t offset, uint64_t stride
) {
    uint64_t k, k2;

    if (stride == 0) return C_KZG_BADARGS;

    k = n / stride;
    k2 = k * 2;

    out[0] = in[n - 1 - offset];
    for (uint64_t i = 1; i <= k + 1 && i < k2; i++) {
        out[i] = FR_ZERO;
    }
    for (uint64_t i = k + 2, j = 2 * stride - offset - 1; i < k2; i++, j += stride) {
        out[i] = in[j];
    }

    return C_KZG_OK;
}

/**
 * Compute FK20 cell-proofs for a polynomial.
 *
 * @param[out]  out An array of CELLS_PER_EXT_BLOB proofs
 * @param[in]   p   The polynomial, an array of coefficients
 * @param[in]   n   The length of the polynomial
 * @param[in]   s   The trusted setup
 *
 * @remark The polynomial should have FIELD_ELEMENTS_PER_BLOB coefficients. Only the lower half of
 * the extended polynomial is supplied because the upper half is assumed to be zero.
 */
static C_KZG_RET compute_fk20_proofs(g1_t *out, const fr_t *p, size_t n, const KZGSettings *s) {
    C_KZG_RET ret;
    uint64_t k, k2;

    blst_scalar *scalars = NULL;
    fr_t **coeffs = NULL;
    fr_t *toeplitz_coeffs = NULL;
    fr_t *toeplitz_coeffs_fft = NULL;
    g1_t *h = NULL;
    g1_t *h_ext_fft = NULL;
    void *scratch = NULL;
    bool precompute = s->wbits != 0;

    /* Initialize length variables */
    k = n / FIELD_ELEMENTS_PER_CELL;
    k2 = k * 2;

    /* Do allocations */
    ret = new_fr_array(&toeplitz_coeffs, k2);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&toeplitz_coeffs_fft, k2);
    if (ret != C_KZG_OK) goto out;
    ret = new_g1_array(&h_ext_fft, k2);
    if (ret != C_KZG_OK) goto out;
    ret = new_g1_array(&h, k2);
    if (ret != C_KZG_OK) goto out;

    if (precompute) {
        /* Allocations for fixed-base MSM */
        ret = c_kzg_malloc(&scratch, s->scratch_size);
        if (ret != C_KZG_OK) goto out;
        ret = c_kzg_calloc((void **)&scalars, FIELD_ELEMENTS_PER_CELL, sizeof(blst_scalar));
        if (ret != C_KZG_OK) goto out;
    }

    /* Allocate 2d array for coefficients by column */
    ret = c_kzg_calloc((void **)&coeffs, k2, sizeof(void *));
    if (ret != C_KZG_OK) goto out;
    for (uint64_t i = 0; i < k2; i++) {
        ret = new_fr_array(&coeffs[i], k);
        if (ret != C_KZG_OK) goto out;
    }

    /* Initialize values to zero */
    for (uint64_t i = 0; i < k2; i++) {
        h_ext_fft[i] = G1_IDENTITY;
    }

    /* Compute toeplitz coefficients and organize by column */
    for (uint64_t i = 0; i < FIELD_ELEMENTS_PER_CELL; i++) {
        ret = toeplitz_coeffs_stride(toeplitz_coeffs, p, n, i, FIELD_ELEMENTS_PER_CELL);
        if (ret != C_KZG_OK) goto out;
        ret = fft_fr(toeplitz_coeffs_fft, toeplitz_coeffs, k2, s);
        if (ret != C_KZG_OK) goto out;
        for (uint64_t j = 0; j < k2; j++) {
            coeffs[j][i] = toeplitz_coeffs_fft[j];
        }
    }

    /* Compute h_ext_fft via MSM */
    for (uint64_t i = 0; i < k2; i++) {
        if (precompute) {
            /* Transform the field elements to 255-bit scalars */
            for (uint64_t j = 0; j < FIELD_ELEMENTS_PER_CELL; j++) {
                blst_scalar_from_fr(&scalars[j], &coeffs[i][j]);
            }
            const byte *scalars_arg[2] = {(byte *)scalars, NULL};

            /* A fixed-base MSM with precomputation */
            blst_p1s_mult_wbits(
                &h_ext_fft[i],
                s->tables[i],
                s->wbits,
                FIELD_ELEMENTS_PER_CELL,
                scalars_arg,
                BITS_PER_FIELD_ELEMENT,
                scratch
            );
        } else {
            /* A pretty fast MSM without precomputation */
            ret = g1_lincomb_fast(
                &h_ext_fft[i], s->x_ext_fft_columns[i], coeffs[i], FIELD_ELEMENTS_PER_CELL
            );
            if (ret != C_KZG_OK) goto out;
        }
    }

    ret = ifft_g1(h, h_ext_fft, k2, s);
    if (ret != C_KZG_OK) goto out;

    /* Zero the second half of h */
    for (uint64_t i = k; i < k2; i++) {
        h[i] = G1_IDENTITY;
    }

    ret = fft_g1(out, h, k2, s);
    if (ret != C_KZG_OK) goto out;

out:
    c_kzg_free(scalars);
    if (coeffs != NULL) {
        for (uint64_t i = 0; i < k2; i++) {
            c_kzg_free(coeffs[i]);
        }
        c_kzg_free(coeffs);
    }
    c_kzg_free(toeplitz_coeffs);
    c_kzg_free(toeplitz_coeffs_fft);
    c_kzg_free(h);
    c_kzg_free(h_ext_fft);
    c_kzg_free(scratch);
    return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Helper Functions for Batch Cell Verification
////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Compute random linear combination challenge scalars for verify_cell_kzg_proof_batch. In this, we
 * must hash EVERYTHING that the prover can control.
 *
 * @param[out]  r_powers_out        The output challenges
 * @param[in]   commitments_bytes   The input commitments
 * @param[in]   num_commitments     The number of commitments
 * @param[in]   commitment_indices  The cell commitment indices
 * @param[in]   cell_indices        The cell indices
 * @param[in]   cells               The cell
 * @param[in]   proofs_bytes        The cell proof
 * @param[in]   num_cells           The number of cells
 */
static C_KZG_RET compute_r_powers_for_verify_cell_kzg_proof_batch(
    fr_t *r_powers_out,
    const Bytes48 *commitments_bytes,
    size_t num_commitments,
    const uint64_t *commitment_indices,
    const uint64_t *cell_indices,
    const Cell *cells,
    const Bytes48 *proofs_bytes,
    size_t num_cells
) {
    C_KZG_RET ret;
    uint8_t *bytes = NULL;
    Bytes32 r_bytes;
    fr_t r;

    /* Calculate the size of the data we're going to hash */
    size_t input_size = DOMAIN_STR_LENGTH                          /* The domain separator */
                        + sizeof(uint64_t)                         /* FIELD_ELEMENTS_PER_CELL */
                        + sizeof(uint64_t)                         /* num_commitments */
                        + sizeof(uint64_t)                         /* num_cells */
                        + (num_commitments * BYTES_PER_COMMITMENT) /* comms */
                        + (num_cells * sizeof(uint64_t))           /* commitment_indices */
                        + (num_cells * sizeof(uint64_t))           /* cell_indices */
                        + (num_cells * BYTES_PER_CELL)             /* cells */
                        + (num_cells * BYTES_PER_PROOF);           /* proofs_bytes */

    /* Allocate space to copy this data into */
    ret = c_kzg_malloc((void **)&bytes, input_size);
    if (ret != C_KZG_OK) goto out;

    /* Pointer tracking `bytes` for writing on top of it */
    uint8_t *offset = bytes;

    /* Copy domain separator */
    memcpy(offset, RANDOM_CHALLENGE_DOMAIN_VERIFY_CELL_KZG_PROOF_BATCH, DOMAIN_STR_LENGTH);
    offset += DOMAIN_STR_LENGTH;

    /* Copy field elements per cell */
    bytes_from_uint64(offset, FIELD_ELEMENTS_PER_CELL);
    offset += sizeof(uint64_t);

    /* Copy number of commitments */
    bytes_from_uint64(offset, num_commitments);
    offset += sizeof(uint64_t);

    /* Copy number of cells */
    bytes_from_uint64(offset, num_cells);
    offset += sizeof(uint64_t);

    for (size_t i = 0; i < num_commitments; i++) {
        /* Copy commitment */
        memcpy(offset, &commitments_bytes[i], BYTES_PER_COMMITMENT);
        offset += BYTES_PER_COMMITMENT;
    }

    for (size_t i = 0; i < num_cells; i++) {
        /* Copy row id */
        bytes_from_uint64(offset, commitment_indices[i]);
        offset += sizeof(uint64_t);

        /* Copy column id */
        bytes_from_uint64(offset, cell_indices[i]);
        offset += sizeof(uint64_t);

        /* Copy cell */
        memcpy(offset, &cells[i], BYTES_PER_CELL);
        offset += BYTES_PER_CELL;

        /* Copy proof */
        memcpy(offset, &proofs_bytes[i], BYTES_PER_PROOF);
        offset += BYTES_PER_PROOF;
    }

    /* Now let's create the challenge! */
    blst_sha256(r_bytes.bytes, bytes, input_size);
    hash_to_bls_field(&r, &r_bytes);

    /* Raise power of r for each cell */
    compute_powers(r_powers_out, &r, num_cells);

    /* Make sure we wrote the entire buffer */
    assert(offset == bytes + input_size);

out:
    c_kzg_free(bytes);
    return ret;
}

/**
 * Helper function to compare two commitments.
 *
 * @param[in]   a   The first commitment
 * @param[in]   b   The second commitment
 *
 * @return True if the commitments are the same, otherwise false.
 */
static bool commitments_equal(const Bytes48 *a, const Bytes48 *b) {
    return memcmp(a->bytes, b->bytes, BYTES_PER_COMMITMENT) == 0;
}

/**
 * Helper function to copy one commitment's bytes to another.
 *
 * @param[in]   dst   The destination commitment
 * @param[in]   src   The source commitment
 */
static void commitments_copy(Bytes48 *dst, const Bytes48 *src) {
    memcpy(dst->bytes, src->bytes, BYTES_PER_COMMITMENT);
}

/**
 * Convert a list of commitments with potential duplicates to a list of unique commitments. Also
 * returns a list of indices which point to those new unique commitments.
 *
 * @param[in,out]   commitments_out Updated to only contain unique commitments
 * @param[out]      indices_out     Used as map between old/new commitments
 * @param[in,out]   count_out       Number of commitments before and after
 *
 * @remark The input arrays are re-used.
 * @remark The number of commitments/indices must be the same.
 * @remark The length of `indices_out` is unchanged.
 * @remark `count_out` is updated to be the number of unique commitments.
 */
static void deduplicate_commitments(
    Bytes48 *commitments_out, uint64_t *indices_out, size_t *count_out
) {
    /* Bail early if there are no commitments */
    if (*count_out == 0) return;

    /* The first commitment is always new */
    indices_out[0] = 0;
    size_t new_count = 1;

    /* Create list of unique commitments & indices to them */
    for (size_t i = 1; i < *count_out; i++) {
        bool exist = false;
        for (size_t j = 0; j < new_count; j++) {
            if (commitments_equal(&commitments_out[i], &commitments_out[j])) {
                /* This commitment already exists */
                indices_out[i] = j;
                exist = true;
                break;
            }
        }
        if (!exist) {
            /* This is a new commitment */
            commitments_copy(&commitments_out[new_count], &commitments_out[i]);
            indices_out[i] = new_count;
            new_count++;
        }
    }

    /* Update the count */
    *count_out = new_count;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Functions for EIP-7594
////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Given a blob, get all of its cells and proofs.
 *
 * @param[out]  cells   An array of CELLS_PER_EXT_BLOB cells
 * @param[out]  proofs  An array of CELLS_PER_EXT_BLOB proofs
 * @param[in]   blob    The blob to get cells/proofs for
 * @param[in]   s       The trusted setup
 *
 * @remark Up to half of these cells may be lost.
 * @remark Use recover_cells_and_kzg_proofs for recovery.
 * @remark If cells is NULL, they won't be computed.
 * @remark If proofs is NULL, they won't be computed.
 * @remark Will return an error if both cells & proofs are NULL.
 */
C_KZG_RET compute_cells_and_kzg_proofs(
    Cell *cells, KZGProof *proofs, const Blob *blob, const KZGSettings *s
) {
    C_KZG_RET ret;
    fr_t *poly_monomial = NULL;
    fr_t *poly_lagrange = NULL;
    fr_t *data_fr = NULL;
    g1_t *proofs_g1 = NULL;

    /* If both of these are null, something is wrong */
    if (cells == NULL && proofs == NULL) {
        return C_KZG_BADARGS;
    }

    /* Allocate space fr-form arrays */
    ret = new_fr_array(&poly_monomial, FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&poly_lagrange, FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;

    /*
     * Convert the blob to a polynomial in lagrange form. Note that only the first 4096 fields of
     * the polynomial will be set. The upper 4096 fields will remain zero. This is required because
     * the polynomial will be evaluated with 8192 roots of unity.
     */
    ret = blob_to_polynomial((Polynomial *)poly_lagrange, blob);
    if (ret != C_KZG_OK) goto out;

    /* We need the polynomial to be in monomial form */
    ret = poly_lagrange_to_monomial(poly_monomial, poly_lagrange, FIELD_ELEMENTS_PER_BLOB, s);
    if (ret != C_KZG_OK) goto out;

    if (cells != NULL) {
        /* Allocate space for our data points */
        ret = new_fr_array(&data_fr, FIELD_ELEMENTS_PER_EXT_BLOB);
        if (ret != C_KZG_OK) goto out;

        /* Get the data points via forward transformation */
        ret = fft_fr(data_fr, poly_monomial, FIELD_ELEMENTS_PER_EXT_BLOB, s);
        if (ret != C_KZG_OK) goto out;

        /* Bit-reverse the data points */
        ret = bit_reversal_permutation(data_fr, sizeof(fr_t), FIELD_ELEMENTS_PER_EXT_BLOB);
        if (ret != C_KZG_OK) goto out;

        /* Convert all of the cells to byte-form */
        for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
            for (size_t j = 0; j < FIELD_ELEMENTS_PER_CELL; j++) {
                size_t index = i * FIELD_ELEMENTS_PER_CELL + j;
                size_t offset = j * BYTES_PER_FIELD_ELEMENT;
                bytes_from_bls_field((Bytes32 *)&cells[i].bytes[offset], &data_fr[index]);
            }
        }
    }

    if (proofs != NULL) {
        /* Allocate space for our proofs in g1-form */
        ret = new_g1_array(&proofs_g1, CELLS_PER_EXT_BLOB);
        if (ret != C_KZG_OK) goto out;

        /* Compute the proofs, provide only the first half */
        ret = compute_fk20_proofs(proofs_g1, poly_monomial, FIELD_ELEMENTS_PER_BLOB, s);
        if (ret != C_KZG_OK) goto out;

        /* Bit-reverse the proofs */
        ret = bit_reversal_permutation(proofs_g1, sizeof(g1_t), CELLS_PER_EXT_BLOB);
        if (ret != C_KZG_OK) goto out;

        /* Convert all of the proofs to byte-form */
        for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
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
 * Given some cells for a blob, recover all cells/proofs.
 *
 * @param[out]  recovered_cells     An array of CELLS_PER_EXT_BLOB cells
 * @param[out]  recovered_proofs    An array of CELLS_PER_EXT_BLOB proofs
 * @param[in]   cell_indices        The cell indices for the cells
 * @param[in]   cells               The cells to check
 * @param[in]   num_cells           The number of cells provided
 * @param[in]   s                   The trusted setup
 *
 * @remark Recovery is faster if there are fewer missing cells.
 * @remark If recovered_proofs is NULL, they will not be recomputed.
 */
C_KZG_RET recover_cells_and_kzg_proofs(
    Cell *recovered_cells,
    KZGProof *recovered_proofs,
    const uint64_t *cell_indices,
    const Cell *cells,
    size_t num_cells,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    fr_t *recovered_cells_fr = NULL;
    g1_t *recovered_proofs_g1 = NULL;
    Blob *blob = NULL;

    /* Ensure only one blob's worth of cells was provided */
    if (num_cells > CELLS_PER_EXT_BLOB) {
        ret = C_KZG_BADARGS;
        goto out;
    }

    /* Check if it's possible to recover */
    if (num_cells < CELLS_PER_EXT_BLOB / 2) {
        ret = C_KZG_BADARGS;
        goto out;
    }

    /* Check that cell indices are valid */
    for (size_t i = 0; i < num_cells; i++) {
        if (cell_indices[i] >= CELLS_PER_EXT_BLOB) {
            ret = C_KZG_BADARGS;
            goto out;
        }
    }

    /* Do allocations */
    ret = new_fr_array(&recovered_cells_fr, s->max_width);
    if (ret != C_KZG_OK) goto out;
    ret = new_g1_array(&recovered_proofs_g1, CELLS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = c_kzg_malloc((void **)&blob, BYTES_PER_BLOB);
    if (ret != C_KZG_OK) goto out;

    /* Initialize all cells as missing */
    for (size_t i = 0; i < s->max_width; i++) {
        recovered_cells_fr[i] = FR_NULL;
    }

    /* Update with existing cells */
    for (size_t i = 0; i < num_cells; i++) {
        size_t index = cell_indices[i] * FIELD_ELEMENTS_PER_CELL;
        for (size_t j = 0; j < FIELD_ELEMENTS_PER_CELL; j++) {
            fr_t *field = &recovered_cells_fr[index + j];

            /*
             * Check if the field has already been set. If it has, there was a duplicate cell index
             * and we can return an error. The compiler will optimize this and the overhead is
             * practically zero.
             */
            if (!fr_is_null(field)) {
                ret = C_KZG_BADARGS;
                goto out;
            }

            /* Convert the untrusted bytes to a field element */
            size_t offset = j * BYTES_PER_FIELD_ELEMENT;
            ret = bytes_to_bls_field(field, (Bytes32 *)&cells[i].bytes[offset]);
            if (ret != C_KZG_OK) goto out;
        }
    }

    if (num_cells == CELLS_PER_EXT_BLOB) {
        /* Nothing to recover, copy the cells */
        memcpy(recovered_cells, cells, CELLS_PER_EXT_BLOB * sizeof(Cell));
    } else {
        /* Perform cell recovery */
        ret = recover_cells_impl(
            recovered_cells_fr, cell_indices, num_cells, recovered_cells_fr, s
        );
        if (ret != C_KZG_OK) goto out;

        /* Convert the recovered data points to byte-form */
        for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
            for (size_t j = 0; j < FIELD_ELEMENTS_PER_CELL; j++) {
                size_t index = i * FIELD_ELEMENTS_PER_CELL + j;
                size_t offset = j * BYTES_PER_FIELD_ELEMENT;
                bytes_from_bls_field(
                    (Bytes32 *)&recovered_cells[i].bytes[offset], &recovered_cells_fr[index]
                );
            }
        }
    }

    if (recovered_proofs != NULL) {
        /*
         * Instead of converting the cells to a blob and back, we can just treat the cells as a
         * polynomial. We are done with the fr-form recovered cells and we can safely mutate the
         * array.
         */
        ret = poly_lagrange_to_monomial(
            recovered_cells_fr, recovered_cells_fr, FIELD_ELEMENTS_PER_EXT_BLOB, s
        );
        if (ret != C_KZG_OK) goto out;

        /* Compute the proofs, provide only the first half */
        ret = compute_fk20_proofs(
            recovered_proofs_g1, recovered_cells_fr, FIELD_ELEMENTS_PER_BLOB, s
        );
        if (ret != C_KZG_OK) goto out;

        /* Bit-reverse the proofs */
        ret = bit_reversal_permutation(recovered_proofs_g1, sizeof(g1_t), CELLS_PER_EXT_BLOB);
        if (ret != C_KZG_OK) goto out;

        /* Convert all of the proofs to byte-form */
        for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
            bytes_from_g1(&recovered_proofs[i], &recovered_proofs_g1[i]);
        }
    }

out:
    c_kzg_free(recovered_cells_fr);
    c_kzg_free(recovered_proofs_g1);
    c_kzg_free(blob);
    return ret;
}

/**
 * Given some cells, verify that their proofs are valid.
 *
 * @param[out]  ok                  True if the proofs are valid
 * @param[in]   commitments_bytes   The commitments for the cells
 * @param[in]   cell_indices        The cell indices for the cells
 * @param[in]   cells               The cells to check
 * @param[in]   proofs_bytes        The proofs for the cells
 * @param[in]   num_cells           The number of cells provided
 * @param[in]   s                   The trusted setup
 *
 * @remark cells[i] is associated with commitments_bytes[commitment_indices[i]].
 */
C_KZG_RET verify_cell_kzg_proof_batch(
    bool *ok,
    const Bytes48 *commitments_bytes,
    const uint64_t *cell_indices,
    const Cell *cells,
    const Bytes48 *proofs_bytes,
    size_t num_cells,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    g1_t evaluation;
    g1_t final_g1_sum;
    g1_t proof_lincomb;
    g1_t weighted_proof_lincomb;
    g2_t power_of_s = s->g2_values_monomial[FIELD_ELEMENTS_PER_CELL];
    size_t num_commitments;

    /* Arrays */
    Bytes48 *unique_commitments = NULL;
    uint64_t *commitment_indices = NULL;
    bool *is_cell_used = NULL;
    fr_t *aggregated_column_cells = NULL;
    fr_t *aggregated_interpolation_poly = NULL;
    fr_t *column_interpolation_poly = NULL;
    fr_t *commitment_weights = NULL;
    fr_t *r_powers = NULL;
    fr_t *weighted_powers_of_r = NULL;
    fr_t *weights = NULL;
    g1_t *commitments_g1 = NULL;
    g1_t *proofs_g1 = NULL;

    *ok = false;

    /* Exit early if we are given zero cells */
    if (num_cells == 0) {
        *ok = true;
        return C_KZG_OK;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Sanity checks
    ////////////////////////////////////////////////////////////////////////////////////////////////

    for (size_t i = 0; i < num_cells; i++) {
        /* Make sure column index is valid */
        if (cell_indices[i] >= CELLS_PER_EXT_BLOB) return C_KZG_BADARGS;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Deduplicate Commitments
    ////////////////////////////////////////////////////////////////////////////////////////////////

    ret = c_kzg_calloc((void **)&unique_commitments, num_cells, sizeof(Bytes48));
    if (ret != C_KZG_OK) goto out;
    ret = c_kzg_calloc((void **)&commitment_indices, num_cells, sizeof(uint64_t));
    if (ret != C_KZG_OK) goto out;

    /*
     * Convert the array of cell commitments to an array of unique commitments and an array of
     * indices to those unique commitments. We do this before the array allocations section below
     * because we need to know how many commitment weights there will be.
     */
    num_commitments = num_cells;
    memcpy(unique_commitments, commitments_bytes, num_cells * sizeof(Bytes48));
    deduplicate_commitments(unique_commitments, commitment_indices, &num_commitments);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Array allocations
    ////////////////////////////////////////////////////////////////////////////////////////////////

    ret = new_bool_array(&is_cell_used, FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&aggregated_column_cells, FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&aggregated_interpolation_poly, FIELD_ELEMENTS_PER_CELL);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&column_interpolation_poly, FIELD_ELEMENTS_PER_CELL);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&commitment_weights, num_commitments);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&r_powers, num_cells);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&weighted_powers_of_r, num_cells);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&weights, num_cells);
    if (ret != C_KZG_OK) goto out;
    ret = new_g1_array(&commitments_g1, num_commitments);
    if (ret != C_KZG_OK) goto out;
    ret = new_g1_array(&proofs_g1, num_cells);
    if (ret != C_KZG_OK) goto out;

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Compute random linear combination of the proofs
    ////////////////////////////////////////////////////////////////////////////////////////////////

    /*
     * Derive random factors for the linear combination. The exponents start with 0. That is, they
     * are r^0, r^1, r^2, r^3, and so on.
     */
    ret = compute_r_powers_for_verify_cell_kzg_proof_batch(
        r_powers,
        unique_commitments,
        num_commitments,
        commitment_indices,
        cell_indices,
        cells,
        proofs_bytes,
        num_cells
    );
    if (ret != C_KZG_OK) goto out;

    /* There should be a proof for each cell */
    for (size_t i = 0; i < num_cells; i++) {
        ret = bytes_to_kzg_proof(&proofs_g1[i], &proofs_bytes[i]);
        if (ret != C_KZG_OK) goto out;
    }

    /* Do the linear combination */
    ret = g1_lincomb_fast(&proof_lincomb, proofs_g1, r_powers, num_cells);
    if (ret != C_KZG_OK) goto out;

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Compute sum of the commitments
    ////////////////////////////////////////////////////////////////////////////////////////////////

    for (size_t i = 0; i < num_commitments; i++) {
        /* Convert & validate commitment */
        ret = bytes_to_kzg_commitment(&commitments_g1[i], &unique_commitments[i]);
        if (ret != C_KZG_OK) goto out;

        /* Initialize the weight to zero */
        commitment_weights[i] = FR_ZERO;
    }

    /* Update commitment weights */
    for (size_t i = 0; i < num_cells; i++) {
        blst_fr_add(
            &commitment_weights[commitment_indices[i]],
            &commitment_weights[commitment_indices[i]],
            &r_powers[i]
        );
    }

    /* Compute commitment sum */
    ret = g1_lincomb_fast(&final_g1_sum, commitments_g1, commitment_weights, num_commitments);
    if (ret != C_KZG_OK) goto out;

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Compute aggregated columns
    ////////////////////////////////////////////////////////////////////////////////////////////////

    /* Start with zeroed out columns */
    for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
        for (size_t j = 0; j < FIELD_ELEMENTS_PER_CELL; j++) {
            size_t index = i * FIELD_ELEMENTS_PER_CELL + j;
            aggregated_column_cells[index] = FR_ZERO;
        }
    }

    /* Scale each cell's data points */
    for (size_t i = 0; i < num_cells; i++) {
        for (size_t j = 0; j < FIELD_ELEMENTS_PER_CELL; j++) {
            fr_t field, scaled;
            size_t offset = j * BYTES_PER_FIELD_ELEMENT;
            ret = bytes_to_bls_field(&field, (Bytes32 *)&cells[i].bytes[offset]);
            if (ret != C_KZG_OK) goto out;
            blst_fr_mul(&scaled, &field, &r_powers[i]);
            size_t index = cell_indices[i] * FIELD_ELEMENTS_PER_CELL + j;
            blst_fr_add(&aggregated_column_cells[index], &aggregated_column_cells[index], &scaled);

            /* Mark the cell as being used */
            is_cell_used[index] = true;
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Compute sum of the interpolation polynomials
    ////////////////////////////////////////////////////////////////////////////////////////////////

    /* Start with a zeroed out poly */
    for (size_t i = 0; i < FIELD_ELEMENTS_PER_CELL; i++) {
        aggregated_interpolation_poly[i] = FR_ZERO;
    }

    /* Interpolate each column */
    for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
        /* Offset to the first cell for this column */
        size_t index = i * FIELD_ELEMENTS_PER_CELL;

        /* We only care about initialized cells */
        if (!is_cell_used[index]) continue;

        /* We don't need to copy this because it's not used again */
        ret = bit_reversal_permutation(
            &aggregated_column_cells[index], sizeof(fr_t), FIELD_ELEMENTS_PER_CELL
        );
        if (ret != C_KZG_OK) goto out;

        /*
         * Get interpolation polynomial for this column. To do so we first do an IDFT over the roots
         * of unity and then we scale by the coset factor.  We can't do an IDFT directly over the
         * coset because it's not a subgroup.
         */
        ret = ifft_fr(
            column_interpolation_poly, &aggregated_column_cells[index], FIELD_ELEMENTS_PER_CELL, s
        );
        if (ret != C_KZG_OK) goto out;

        /*
         * To unscale, divide by the coset. It's faster to multiply with the inverse. We can skip
         * the first iteration because its dividing by one.
         */
        uint32_t pos = reverse_bits_limited(CELLS_PER_EXT_BLOB, i);
        fr_t inv_coset_factor;
        blst_fr_eucl_inverse(&inv_coset_factor, &s->expanded_roots_of_unity[pos]);
        shift_poly(column_interpolation_poly, FIELD_ELEMENTS_PER_CELL, &inv_coset_factor);

        /* Update the aggregated poly */
        for (size_t k = 0; k < FIELD_ELEMENTS_PER_CELL; k++) {
            blst_fr_add(
                &aggregated_interpolation_poly[k],
                &aggregated_interpolation_poly[k],
                &column_interpolation_poly[k]
            );
        }
    }

    /* Commit to the final aggregated interpolation polynomial */
    ret = g1_lincomb_fast(
        &evaluation, s->g1_values_monomial, aggregated_interpolation_poly, FIELD_ELEMENTS_PER_CELL
    );
    if (ret != C_KZG_OK) goto out;

    blst_p1_cneg(&evaluation, true);
    blst_p1_add(&final_g1_sum, &final_g1_sum, &evaluation);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Compute sum of the proofs scaled by the coset factors
    ////////////////////////////////////////////////////////////////////////////////////////////////

    for (size_t i = 0; i < num_cells; i++) {
        uint32_t pos = reverse_bits_limited(CELLS_PER_EXT_BLOB, cell_indices[i]);
        fr_t coset_factor = s->expanded_roots_of_unity[pos];
        fr_pow(&weights[i], &coset_factor, FIELD_ELEMENTS_PER_CELL);
        blst_fr_mul(&weighted_powers_of_r[i], &r_powers[i], &weights[i]);
    }

    ret = g1_lincomb_fast(&weighted_proof_lincomb, proofs_g1, weighted_powers_of_r, num_cells);
    if (ret != C_KZG_OK) goto out;

    blst_p1_add(&final_g1_sum, &final_g1_sum, &weighted_proof_lincomb);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Do the final pairing check
    ////////////////////////////////////////////////////////////////////////////////////////////////

    *ok = pairings_verify(&final_g1_sum, blst_p2_generator(), &proof_lincomb, &power_of_s);

out:
    c_kzg_free(unique_commitments);
    c_kzg_free(commitment_indices);
    c_kzg_free(is_cell_used);
    c_kzg_free(aggregated_column_cells);
    c_kzg_free(aggregated_interpolation_poly);
    c_kzg_free(column_interpolation_poly);
    c_kzg_free(commitment_weights);
    c_kzg_free(r_powers);
    c_kzg_free(weighted_powers_of_r);
    c_kzg_free(weights);
    c_kzg_free(commitments_g1);
    c_kzg_free(proofs_g1);
    return ret;
}
