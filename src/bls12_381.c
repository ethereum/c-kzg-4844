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
 * @file bls12_381.c
 *
 * Wrappers for cryptographic library functions, allowing different libraries to be supported.
 */

#include "bls12_381.h"

#ifdef BLST

#include <stdlib.h> // malloc(), free(), NULL

/**
 * Fast log base 2 of a byte.
 *
 * Corresponds to the index of the highest bit set in the byte. Adapted from
 * https://graphics.stanford.edu/~seander/bithacks.html#IntegerLog.
 *
 * @param[in] b A non-zero byte
 * @return The index of the highest set bit
 */
static int log_2_byte(byte b) {
    int r, shift;
    r = (b > 0xF) << 2;
    b >>= r;
    shift = (b > 0x3) << 1;
    b >>= (shift + 1);
    r |= shift | b;
    return r;
}

/**
 * Test whether the operand is zero in the finite field.
 *
 * @param p The field element to be checked
 * @retval true The element is zero
 * @retval false The element is non-zero
 *
 * @todo See if there is a more efficient way to check for zero in the finite field.
 */
bool fr_is_zero(const fr_t *p) {
    uint64_t a[4];
    blst_uint64_from_fr(a, p);
    return a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0;
}

/**
 * Test whether the operand is one in the finite field.
 *
 * @param p The field element to be checked
 * @retval true The element is one
 * @retval false The element is not one
 *
 * @todo See if there is a more efficient way to check for one in the finite field.
 */
bool fr_is_one(const fr_t *p) {
    uint64_t a[4];
    blst_uint64_from_fr(a, p);
    return a[0] == 1 && a[1] == 0 && a[2] == 0 && a[3] == 0;
}

/**
 * Test whether the operand is a specially defined NULL value.
 *
 * @param p The field element to be checked
 * @retval true The element is the NULL value
 * @retval false The element is not the NULL value
 */
bool fr_is_null(const fr_t *p) {
    uint64_t *null = (uint64_t *)&fr_null;
    uint64_t *a = (uint64_t *)p;
    return a[0] == null[0] && a[1] == null[1] && a[2] == null[2] && a[3] == null[3];
}

/**
 * Create a field element from a scalar, which is a little-endian sequence of bytes.
 *
 * @param[out] out The resulting field element
 * @param[in]  a   The scalar input, 32 bytes
 */
void fr_from_scalar(fr_t *out, const scalar_t *a) {
    blst_fr_from_scalar(out, a);
}

/**
 * Create a field element from an array of four 64-bit unsigned integers.
 *
 * @param out  The field element equivalent of @p vals
 * @param vals The array of 64-bit integers to be converted, little-endian ordering of the 64-bit words
 */
void fr_from_uint64s(fr_t *out, const uint64_t vals[4]) {
    blst_fr_from_uint64(out, vals);
}

/**
 * Create a field element from a single 64-bit unsigned integer.
 *
 * @remark This can only generate a tiny fraction of possible field elements, and is mostly useful for testing.
 *
 * @param out The field element equivalent of @p n
 * @param n   The 64-bit integer to be converted
 */
void fr_from_uint64(fr_t *out, uint64_t n) {
    uint64_t vals[] = {n, 0, 0, 0};
    fr_from_uint64s(out, vals);
}

/**
 * Convert a field element to an array of four 64-bit unsigned integers.
 *
 * @param out  Array for returned values, little-endian ordering of the 64-bit words
 * @param fr   The field element to be converted
 */
void fr_to_uint64s(uint64_t out[4], const fr_t *fr) {
    blst_uint64_from_fr(out, fr);
}

/**
 * Test whether two field elements are equal.
 *
 * @param[in] aa The first element
 * @param[in] bb The second element
 * @retval true if @p aa and @p bb are equal
 * @retval false otherwise
 */
bool fr_equal(const fr_t *aa, const fr_t *bb) {
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
void fr_negate(fr_t *out, const fr_t *in) {
    blst_fr_cneg(out, in, true);
}

/**
 * Add two field elements.
 *
 * @param[out] out @p a plus @p b in the field
 * @param[in]  a   Field element
 * @param[in]  b   Field element
 */
void fr_add(fr_t *out, const fr_t *a, const fr_t *b) {
    blst_fr_add(out, a, b);
}

/**
 * Subtract one field element from another.
 *
 * @param[out] out @p a minus @p b in the field
 * @param[in]  a   Field element
 * @param[in]  b   Field element
 */
void fr_sub(fr_t *out, const fr_t *a, const fr_t *b) {
    blst_fr_sub(out, a, b);
}

/**
 * Multiply two field elements.
 *
 * @param[out] out @p a multiplied by @p b in the field
 * @param[in]  a   Multiplicand
 * @param[in]  b   Multiplier
 */
void fr_mul(fr_t *out, const fr_t *a, const fr_t *b) {
    blst_fr_mul(out, a, b);
}

/**
 * Inverse of a field element.
 *
 * @param[out] out The inverse of @p a
 * @param[in]  a   A field element
 */
void fr_inv(fr_t *out, const fr_t *a) {
    blst_fr_eucl_inverse(out, a);
}

/**
 * Division of two field elements.
 *
 * @param[out] out @p a divided by @p b in the field
 * @param[in]  a   The dividend
 * @param[in]  b   The divisor
 */
void fr_div(fr_t *out, const fr_t *a, const fr_t *b) {
    blst_fr tmp;
    blst_fr_eucl_inverse(&tmp, b);
    blst_fr_mul(out, a, &tmp);
}

/**
 * Square a field element.
 *
 * @param[out] out @p a squared
 * @param[in]  a   A field element
 */
void fr_sqr(fr_t *out, const fr_t *a) {
    blst_fr_sqr(out, a);
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
void fr_pow(fr_t *out, const fr_t *a, uint64_t n) {
    fr_t tmp = *a;
    *out = fr_one;

    while (true) {
        if (n & 1) {
            fr_mul(out, out, &tmp);
        }
        if ((n >>= 1) == 0) break;
        fr_sqr(&tmp, &tmp);
    }
}

/**
 * Test G1 point for being infinity/the identity.
 *
 * @param[in] a A G1 point
 * @retval true if @p a is the identity point in G1
 * @retval false otherwise
 */
bool g1_is_inf(const g1_t *a) {
    return blst_p1_is_inf(a);
}

/**
 * Double a G1 point.
 *
 * @param[out] out @p a plus @p a in the group
 * @param[in]  a   G1 group point
 */
void g1_dbl(g1_t *out, const g1_t *a) {
    blst_p1_double(out, a);
}

/**
 * Add or double G1 points.
 *
 * This is safe if the two points are the same.
 *
 * @param[out] out @p a plus @p b in the group
 * @param[in]  a   G1 group point
 * @param[in]  b   G1 group point
 */
void g1_add_or_dbl(g1_t *out, const g1_t *a, const g1_t *b) {
    blst_p1_add_or_double(out, a, b);
}

/**
 * Test G1 points for equality.
 *
 * @param[in] a A G1 point
 * @param[in] b A G1 point
 * @retval true if @p a and @p b are the same point
 * @retval false otherwise
 */
bool g1_equal(const g1_t *a, const g1_t *b) {
    return blst_p1_is_equal(a, b);
}

/**
 * Multiply a G1 group element by a field element.
 *
 * This "undoes" the Blst constant-timedness. FFTs do a lot of multiplication by one, so constant time is rather slow.
 *
 * @param[out] out [@p b]@p a
 * @param[in]  a   The G1 group element
 * @param[in]  b   The multiplier
 */
void g1_mul(g1_t *out, const g1_t *a, const fr_t *b) {
    blst_scalar s;
    blst_scalar_from_fr(&s, b);

    // Count the number of bytes to be multiplied.
    int i = sizeof(blst_scalar);
    while (i && !s.b[i - 1]) --i;
    if (i == 0) {
        *out = g1_identity;
    } else if (i == 1 && s.b[0] == 1) {
        *out = *a;
    } else {
        // Count the number of bits to be multiplied.
        blst_p1_mult(out, a, s.b, 8 * i - 7 + log_2_byte(s.b[i - 1]));
    }
}

/**
 * Subtraction of G1 group elements.
 *
 * @param[out] out @p a - @p b
 * @param[in]  a   A G1 group element
 * @param[in]  b   The G1 group element to be subtracted
 */
void g1_sub(g1_t *out, const g1_t *a, const g1_t *b) {
    g1_t bneg = *b;
    blst_p1_cneg(&bneg, true);
    blst_p1_add_or_double(out, a, &bneg);
}

/**
 * Test G2 points for equality.
 *
 * @param[in] a A G2 point
 * @param[in] b A G2 point
 * @retval true if @p a and @p b are the same point
 * @retval false otherwise
 */
bool g2_equal(const g2_t *a, const g2_t *b) {
    return blst_p2_is_equal(a, b);
}

/**
 * Multiply a G2 group element by a field element.
 *
 * @param[out] out [@p b]@p a
 * @param[in]  a   The G2 group element
 * @param[in]  b   The multiplier
 */
void g2_mul(g2_t *out, const g2_t *a, const fr_t *b) {
    blst_scalar s;
    blst_scalar_from_fr(&s, b);
    blst_p2_mult(out, a, s.b, 8 * sizeof(blst_scalar));
}

/**
 * Add or double G2 points.
 *
 * This is safe if the two points are the same.
 *
 * @param[out] out @p a plus @p b in the group
 * @param[in]  a   G2 group point
 * @param[in]  b   G2 group point
 */
void g2_add_or_dbl(g2_t *out, const g2_t *a, const g2_t *b) {
    blst_p2_add_or_double(out, a, b);
}

/**
 * Subtraction of G2 group elements.
 *
 * @param[out] out @p a - @p b
 * @param[in]  a   A G2 group element
 * @param[in]  b   The G2 group element to be subtracted
 */
void g2_sub(g2_t *out, const g2_t *a, const g2_t *b) {
    g2_t bneg = *b;
    blst_p2_cneg(&bneg, true);
    blst_p2_add_or_double(out, a, &bneg);
}

/**
 * Double a G2 point.
 *
 * @param[out] out @p a plus @p a in the group
 * @param[in]  a   G2 group point
 */
void g2_dbl(g2_t *out, const g2_t *a) {
    blst_p2_double(out, a);
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
 * For the benefit of future generations (since Blst has no documentation to speak of),
 * there are two ways to pass the arrays of scalars and points into `blst_p1s_mult_pippenger()`.
 *
 * 1. Pass `points` as an array of pointers to the points, and pass `scalars` as an array of pointers to the scalars,
 * each of length @p len.
 * 2. Pass an array where the first element is a pointer to the contiguous array of points and the second is null, and
 * similarly for scalars.
 *
 * We do the second of these to save memory here.
 */
void g1_linear_combination(g1_t *out, const g1_t *p, const fr_t *coeffs, const uint64_t len) {

    if (len < 8) { // Tunable parameter: must be at least 2 since Blst fails for 0 or 1
        // Direct approach
        g1_t tmp;
        *out = g1_identity;
        for (uint64_t i = 0; i < len; i++) {
            g1_mul(&tmp, &p[i], &coeffs[i]);
            blst_p1_add_or_double(out, out, &tmp);
        }
    } else {
        // Blst's implementation of the Pippenger method
        void *scratch = malloc(blst_p1s_mult_pippenger_scratch_sizeof(len));
        blst_p1_affine *p_affine = malloc(len * sizeof(blst_p1_affine));
        blst_scalar *scalars = malloc(len * sizeof(blst_scalar));

        // Transform the points to affine representation
        const blst_p1 *p_arg[2] = {p, NULL};
        blst_p1s_to_affine(p_affine, p_arg, len);

        // Transform the field elements to 256-bit scalars
        for (int i = 0; i < len; i++) {
            blst_scalar_from_fr(&scalars[i], &coeffs[i]);
        }

        // Call the Pippenger implementation
        const byte *scalars_arg[2] = {(byte *)scalars, NULL};
        const blst_p1_affine *points_arg[2] = {p_affine, NULL};
        blst_p1s_mult_pippenger(out, points_arg, len, scalars_arg, 256, scratch);

        // Tidy up
        free(scratch);
        free(p_affine);
        free(scalars);
    }
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
 * @retval true  The pairings were equal
 * @retval false The pairings were not equal
 */
bool pairings_verify(const g1_t *a1, const g2_t *a2, const g1_t *b1, const g2_t *b2) {
    blst_fp12 loop0, loop1, gt_point;
    blst_p1_affine aa1, bb1;
    blst_p2_affine aa2, bb2;

    // As an optimisation, we want to invert one of the pairings,
    // so we negate one of the points.
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

#endif // BLST

#ifdef KZGTEST

#include "../inc/acutest.h"
#include "test_util.h"

// This is -1 (the second root of unity)
uint64_t m1[] = {0xffffffff00000000L, 0x53bda402fffe5bfeL, 0x3339d80809a1d805L, 0x73eda753299d7d48L};

void log_2_byte_works(void) {
    // TEST_CHECK(0 == log_2_byte(0x00));
    TEST_CHECK(0 == log_2_byte(0x01));
    TEST_CHECK(7 == log_2_byte(0x80));
    TEST_CHECK(7 == log_2_byte(0xff));
    TEST_CHECK(4 == log_2_byte(0x10));
}

void fr_is_zero_works(void) {
    fr_t zero;
    fr_from_uint64(&zero, 0);
    TEST_CHECK(fr_is_zero(&zero));
}

void fr_is_one_works(void) {
    TEST_CHECK(fr_is_one(&fr_one));
}

void fr_is_null_works(void) {
    TEST_CHECK(fr_is_null(&fr_null));
    TEST_CHECK(!fr_is_null(&fr_zero));
    TEST_CHECK(!fr_is_null(&fr_one));
}

void fr_from_uint64_works(void) {
    fr_t a;
    fr_from_uint64(&a, 1);
    TEST_CHECK(fr_is_one(&a));
}

void fr_equal_works(void) {
    // A couple of arbitrary roots of unity
    uint64_t aa[] = {0x0001000000000000L, 0xec03000276030000L, 0x8d51ccce760304d0L, 0x0000000000000000L};
    uint64_t bb[] = {0x8dd702cb688bc087L, 0xa032824078eaa4feL, 0xa733b23a98ca5b22L, 0x3f96405d25a31660L};
    fr_t a, b;
    fr_from_uint64s(&a, aa);
    fr_from_uint64s(&b, bb);
    TEST_CHECK(true == fr_equal(&a, &a));
    TEST_CHECK(false == fr_equal(&a, &b));
}

void fr_negate_works(void) {
    fr_t minus1, res;
    fr_from_uint64s(&minus1, m1);
    fr_negate(&res, &minus1);
    TEST_CHECK(fr_is_one(&res));
}

void fr_pow_works(void) {
    // a^pow
    uint64_t pow = 123456;
    fr_t a, expected, actual;
    fr_from_uint64(&a, 197);

    // Do it the slow way
    expected = fr_one;
    for (uint64_t i = 0; i < pow; i++) {
        fr_mul(&expected, &expected, &a);
    }

    // Do it the quick way
    fr_pow(&actual, &a, pow);

    TEST_CHECK(fr_equal(&expected, &actual));
}

void fr_div_works(void) {
    fr_t a, b, tmp, actual;

    fr_from_uint64(&a, 197);
    fr_from_uint64(&b, 123456);

    fr_div(&tmp, &a, &b);
    fr_mul(&actual, &tmp, &b);

    TEST_CHECK(fr_equal(&a, &actual));
}

// This is strictly undefined, but conventionally 0 is returned
void fr_div_by_zero(void) {
    fr_t a, b, tmp;

    fr_from_uint64(&a, 197);
    fr_from_uint64(&b, 0);

    fr_div(&tmp, &a, &b);

    TEST_CHECK(fr_is_zero(&tmp));
}

void fr_uint64s_roundtrip(void) {
    fr_t fr;
    uint64_t expected[4] = {1, 2, 3, 4};
    uint64_t actual[4];

    fr_from_uint64s(&fr, expected);
    fr_to_uint64s(actual, &fr);

    TEST_CHECK(expected[0] == actual[0]);
    TEST_CHECK(expected[1] == actual[1]);
    TEST_CHECK(expected[2] == actual[2]);
    TEST_CHECK(expected[3] == actual[3]);
}

void p1_mul_works(void) {
    fr_t minus1;
    g1_t res;

    // Multiply the generator by minus one (the second root of unity)
    fr_from_uint64s(&minus1, m1);
    g1_mul(&res, &g1_generator, &minus1);

    // We should end up with negative the generator
    TEST_CHECK(g1_equal(&res, &g1_negative_generator));
}

void p1_sub_works(void) {
    g1_t tmp, res;

    // 2 * g1_gen = g1_gen - g1_gen_neg
    g1_dbl(&tmp, &g1_generator);
    g1_sub(&res, &g1_generator, &g1_negative_generator);

    TEST_CHECK(g1_equal(&tmp, &res));
}

void p2_add_or_dbl_works(void) {
    g2_t expected, actual;

    g2_dbl(&expected, &g2_generator);
    g2_add_or_dbl(&actual, &g2_generator, &g2_generator);

    TEST_CHECK(g2_equal(&expected, &actual));
}

void p2_mul_works(void) {
    fr_t minus1;
    g2_t res;

    // Multiply the generator by minus one (the second root of unity)
    fr_from_uint64s(&minus1, m1);
    g2_mul(&res, &g2_generator, &minus1);

    TEST_CHECK(g2_equal(&res, &g2_negative_generator));
}

void p2_sub_works(void) {
    g2_t tmp, res;

    // 2 * g2_gen = g2_gen - g2_gen_neg
    g2_dbl(&tmp, &g2_generator);
    g2_sub(&res, &g2_generator, &g2_negative_generator);

    TEST_CHECK(g2_equal(&tmp, &res));
}

void g1_identity_is_infinity(void) {
    TEST_CHECK(g1_is_inf(&g1_identity));
}

void g1_identity_is_identity(void) {
    g1_t actual;
    g1_add_or_dbl(&actual, &g1_generator, &g1_identity);
    TEST_CHECK(g1_equal(&g1_generator, &actual));
}

void g1_make_linear_combination(void) {
    int len = 255;
    fr_t coeffs[len], tmp;
    g1_t p[len], res, exp;
    for (int i = 0; i < len; i++) {
        fr_from_uint64(coeffs + i, i + 1);
        p[i] = g1_generator;
    }

    // Expected result
    fr_from_uint64(&tmp, len * (len + 1) / 2);
    g1_mul(&exp, &g1_generator, &tmp);

    // Test result
    g1_linear_combination(&res, p, coeffs, len);
    TEST_CHECK(g1_equal(&exp, &res));
}

void g1_random_linear_combination(void) {
    int len = 8192;
    fr_t coeffs[len];
    g1_t p[len], p1tmp = g1_generator;
    for (int i = 0; i < len; i++) {
        coeffs[i] = rand_fr();
        p[i] = p1tmp;
        g1_dbl(&p1tmp, &p1tmp);
    }

    // Expected result
    g1_t exp = g1_identity;
    for (uint64_t i = 0; i < len; i++) {
        g1_mul(&p1tmp, &p[i], &coeffs[i]);
        g1_add_or_dbl(&exp, &exp, &p1tmp);
    }

    // Test result
    g1_t res;
    g1_linear_combination(&res, p, coeffs, len);
    TEST_CHECK(g1_equal(&exp, &res));
}

void pairings_work(void) {
    // Verify that e([3]g1, [5]g2) = e([5]g1, [3]g2)
    fr_t three, five;
    g1_t g1_3, g1_5;
    g2_t g2_3, g2_5;

    // Set up
    fr_from_uint64(&three, 3);
    fr_from_uint64(&five, 5);
    g1_mul(&g1_3, &g1_generator, &three);
    g1_mul(&g1_5, &g1_generator, &five);
    g2_mul(&g2_3, &g2_generator, &three);
    g2_mul(&g2_5, &g2_generator, &five);

    // Verify the pairing
    TEST_CHECK(true == pairings_verify(&g1_3, &g2_5, &g1_5, &g2_3));
    TEST_CHECK(false == pairings_verify(&g1_3, &g2_3, &g1_5, &g2_5));
}

TEST_LIST = {
    {"BLS12_384_TEST", title},
    {"log_2_byte_works", log_2_byte_works},
    {"fr_is_zero_works", fr_is_zero_works},
    {"fr_is_one_works", fr_is_one_works},
    {"fr_is_null_works", fr_is_null_works},
    {"fr_from_uint64_works", fr_from_uint64_works},
    {"fr_equal_works", fr_equal_works},
    {"fr_negate_works", fr_negate_works},
    {"fr_pow_works", fr_pow_works},
    {"fr_div_works", fr_div_works},
    {"fr_div_by_zero", fr_div_by_zero},
    {"fr_uint64s_roundtrip", fr_uint64s_roundtrip},
    {"p1_mul_works", p1_mul_works},
    {"p1_sub_works", p1_sub_works},
    {"p2_add_or_dbl_works", p2_add_or_dbl_works},
    {"p2_mul_works", p2_mul_works},
    {"p2_sub_works", p2_sub_works},
    {"g1_identity_is_infinity", g1_identity_is_infinity},
    {"g1_identity_is_identity", g1_identity_is_identity},
    {"g1_make_linear_combination", g1_make_linear_combination},
    {"g1_random_linear_combination", g1_make_linear_combination},
    {"pairings_work", pairings_work},
    {NULL, NULL} /* zero record marks the end of the list */
};

#endif // KZGTEST