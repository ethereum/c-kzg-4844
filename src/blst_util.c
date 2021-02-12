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
 * @file blst_util.c
 *
 * Useful utilities for dealing with field points and group elements that are not directly exposed by the Blst library.
 */

#include "blst_util.h"
#include "debug_util.h"

/**
 * Check whether the operand is zero in the finite field.
 *
 * @param p The field element to be checked
 * @retval true The element is zero
 * @retval false The element is non-zero
 *
 * @todo See if there is a more efficient way to check for zero in the finite field.
 */
bool fr_is_zero(const blst_fr *p) {
    uint64_t a[4];
    blst_uint64_from_fr(a, p);
    return a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0;
}

/**
 * Check whether the operand is one in the finite field.
 *
 * @param p The field element to be checked
 * @retval true The element is one
 * @retval false The element is not one
 *
 * @todo See if there is a more efficient way to check for one in the finite field.
 */
bool fr_is_one(const blst_fr *p) {
    uint64_t a[4];
    blst_uint64_from_fr(a, p);
    return a[0] == 1 && a[1] == 0 && a[2] == 0 && a[3] == 0;
}

/**
 * Create a field element from a single 64-bit unsigned integer.
 *
 * @remark This can only generate a tiny fraction of possible field elements, and is mostly useful for testing.
 *
 * @param out The field element equivalent of @p n
 * @param n   The 64-bit integer to be converted
 */
void fr_from_uint64(blst_fr *out, uint64_t n) {
    uint64_t vals[] = {n, 0, 0, 0};
    blst_fr_from_uint64(out, vals);
}

/**
 * Test whether two field elements are equal.
 *
 * @param[in] aa The first element
 * @param[in] bb The second element
 * @retval true if @p aa and @p bb are equal
 * @retval false otherwise
 */
bool fr_equal(const blst_fr *aa, const blst_fr *bb) {
    uint64_t a[4], b[4];
    blst_uint64_from_fr(a, aa);
    blst_uint64_from_fr(b, bb);
    return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3];
}

/**
 * Negate a field element.
 *
 * @param[out] out The negation of @p in
 * @param[in]  in  The element to be negated
 */
void fr_negate(blst_fr *out, const blst_fr *in) {
    blst_fr_cneg(out, in, true);
}

/**
 * Exponentiation of a field element.
 *
 * Uses square and multiply for log(@p n) performance.
 *
 * @remark A 64-bit exponent is sufficient for our needs here.
 *
 * @param[out] out @p a raised to the power of @p n
 * @param[in]  a   The field element to be exponentiated
 * @param[in]  n   The exponent
 */
void fr_pow(blst_fr *out, const blst_fr *a, uint64_t n) {
    blst_fr tmp = *a;
    *out = fr_one;

    while (true) {
        if (n & 1) {
            blst_fr_mul(out, out, &tmp);
        }
        if ((n >>= 1) == 0) break;
        blst_fr_sqr(&tmp, &tmp);
    }
}

/**
 * Division of two field elements.
 *
 * @param[out] out @p a divided by @p b in the field
 * @param[in]  a   The dividend
 * @param[in]  b   The divisor
 */
void fr_div(blst_fr *out, const blst_fr *a, const blst_fr *b) {
    blst_fr_eucl_inverse(out, b);
    blst_fr_mul(out, out, a);
}

/**
 * Multiply a G1 group element by a field element.
 *
 * @param[out] out [@p b]@p a
 * @param[in]  a   The G1 group element
 * @param[in]  b   The multiplier
 */
void p1_mul(blst_p1 *out, const blst_p1 *a, const blst_fr *b) {
    blst_scalar s;
    blst_scalar_from_fr(&s, b);
    blst_p1_mult(out, a, s.b, 8 * sizeof(blst_scalar));
}

/**
 * Subtraction of G1 group elements.
 *
 * @param[out] out @p a - @p b
 * @param[in]  a   A G1 group element
 * @param[in]  b   The G1 group element to be subtracted
 */
void p1_sub(blst_p1 *out, const blst_p1 *a, const blst_p1 *b) {
    blst_p1 bneg = *b;
    blst_p1_cneg(&bneg, true);
    blst_p1_add_or_double(out, a, &bneg);
}

/**
 * Multiply a G2 group element by a field element.
 *
 * @param[out] out [@p b]@p a
 * @param[in]  a   The G2 group element
 * @param[in]  b   The multiplier
 */
void p2_mul(blst_p2 *out, const blst_p2 *a, const blst_fr *b) {
    blst_scalar s;
    blst_scalar_from_fr(&s, b);
    blst_p2_mult(out, a, s.b, 8 * sizeof(blst_scalar));
}

/**
 * Subtraction of G2 group elements.
 *
 * @param[out] out @p a - @p b
 * @param[in]  a   A G2 group element
 * @param[in]  b   The G2 group element to be subtracted
 */
void p2_sub(blst_p2 *out, const blst_p2 *a, const blst_p2 *b) {
    blst_p2 bneg = *b;
    blst_p2_cneg(&bneg, true);
    blst_p2_add_or_double(out, a, &bneg);
}

/**
 * Calculate a linear combination of G1 group elements.
 *
 * Calculates `[coeffs_0]p_0 + [coeffs_1]p_1 + ... + [coeffs_n]p_n` where `n` is `len - 1`.
 *
 * @param[out] out    The resulting sum-product
 * @param[in]  p      Array of G1 group elements, length @p len
 * @param[in]  coeffs Array of field elements, length @p len
 * @param[in]  len    The number of group/field elements
 *
 * @todo This could be substantially improved with an optimised multi-scalar multiplication. (1) Benchmark and see if
 * this is a bottleneck. (2) If so, look into optimised routines. [Notes from
 * Mamy](https://github.com/vacp2p/research/issues/7#issuecomment-690083000) on the topic.
 */
void linear_combination_g1(blst_p1 *out, const blst_p1 *p, const blst_fr *coeffs, const uint64_t len) {
    blst_p1 tmp;
    blst_p1_from_affine(out, &identity_g1_affine);
    for (uint64_t i = 0; i < len; i++) {
        p1_mul(&tmp, &p[i], &coeffs[i]);
        blst_p1_add_or_double(out, out, &tmp);
    }
}

/**
 * Perform pairings and test whether the outcomes are equal in G_T.
 *
 * Tests whether `e(a1, a2) == e(b1, b2)`
 *
 * @param[in] a1 A G1 group point for the first pairing
 * @param[in] a2 A G2 group point for the first pairing
 * @param[in] b1 A G1 group point for the second pairing
 * @param[in] b2 A G2 group point for the second pairing
 * @retval true  The pairings were equal
 * @retval false The pairings were not equal
 */
bool pairings_verify(const blst_p1 *a1, const blst_p2 *a2, const blst_p1 *b1, const blst_p2 *b2) {
    blst_fp12 loop0, loop1, gt_point;
    blst_p1_affine aa1, bb1;
    blst_p2_affine aa2, bb2;

    // As an optimisation, we want to invert one of the pairings,
    // so we negate one of the points.
    blst_p1 a1neg = *a1;
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
