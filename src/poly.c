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
 * @file poly.c
 *
 * Operations on polynomials defined over the finite field.
 */

#include "control.h"
#include "c_kzg_alloc.h"
#include "utility.h"

/**
 * Internal utility for calculating the length to be allocated for the result of dividing two polynomials.
 *
 * @param[in] dividend The dividend polynomial
 * @param[in] divisor The divisor polynomial
 * @return Size of polynomial that needs to be allocated to hold the result of the division
 */
static uint64_t poly_quotient_length(const poly *dividend, const poly *divisor) {
    return dividend->length >= divisor->length ? dividend->length - divisor->length + 1 : 0;
}

/**
 * Pad with zeros or truncate an array of field elements to a specific size.
 *
 * @param[out] out   The padded/truncated array
 * @param[in]  in    The original array to be padded
 * @param[in]  n_in  The number of elements of @p in to take
 * @param[in]  n_out The length of @p out
 */
static void pad(fr_t *out, const fr_t *in, uint64_t n_in, uint64_t n_out) {
    uint64_t num = min_u64(n_in, n_out);
    for (int i = 0; i < num; i++) {
        out[i] = in[i];
    }
    for (int i = num; i < n_out; i++) {
        out[i] = fr_zero;
    }
}

/**
 * Return a copy of a polynomial ensuring that the order is correct.
 *
 * @param[in] p A pointer to the polynomial to be normalised
 * @return The normalised polynomial
 */
static poly poly_norm(const poly *p) {
    poly ret = *p;
    while (ret.length > 0 && fr_is_zero(&ret.coeffs[ret.length - 1])) {
        ret.length--;
    }
    if (ret.length == 0) {
        ret.coeffs = NULL;
    }
    return ret;
}

/**
 * Evaluate a polynomial over the finite field at a point.
 *
 * @param[out] out The value of the polynomial at the point @p x
 * @param[in]  p   The polynomial
 * @param[in]  x   The x-coordinate to be evaluated
 */
void eval_poly(fr_t *out, const poly *p, const fr_t *x) {
    fr_t tmp;
    uint64_t i;

    if (p->length == 0) {
        *out = fr_zero;
        return;
    }

    if (fr_is_zero(x)) {
        *out = p->coeffs[0];
        return;
    }

    // Horner's method
    *out = p->coeffs[p->length - 1];
    i = p->length - 2;
    while (true) {
        fr_mul(&tmp, out, x);
        fr_add(out, &tmp, &p->coeffs[i]);
        if (i == 0) break;
        --i;
    }
}

/**
 * Polynomial division in the finite field via long division.
 *
 * Returns the polynomial resulting from dividing @p dividend by @p divisor.
 *
 * Should be O(m.n) where m is the length of the dividend, and n the length of the divisor.
 *
 * @remark @p out must be sized large enough for the resulting polynomial.
 *
 * @remark For some ranges of @p dividend and @p divisor, #poly_fast_div is much, much faster.
 *
 * @param[out] out      An appropriately sized poly type that will contain the result of the division
 * @param[in]  dividend The dividend polynomial
 * @param[in]  divisor  The divisor polynomial
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
static C_KZG_RET poly_long_div(poly *out, const poly *dividend, const poly *divisor) {
    uint64_t a_pos = dividend->length - 1;
    uint64_t b_pos = divisor->length - 1;
    uint64_t diff = a_pos - b_pos;
    fr_t *a;

    // Dividing by zero is undefined
    CHECK(divisor->length > 0);

    // The divisor's highest coefficient must be non-zero
    CHECK(!fr_is_zero(&divisor->coeffs[divisor->length - 1]));

    // Deal with the size of the output polynomial
    uint64_t out_length = poly_quotient_length(dividend, divisor);
    CHECK(out->length >= out_length);
    out->length = out_length;

    // If the divisor is larger than the dividend, the result is zero-length
    if (out_length == 0) {
        return C_KZG_OK;
    }

    TRY(new_fr_array(&a, dividend->length));
    for (uint64_t i = 0; i < dividend->length; i++) {
        a[i] = dividend->coeffs[i];
    }

    while (diff > 0) {
        fr_div(&out->coeffs[diff], &a[a_pos], &divisor->coeffs[b_pos]);
        for (uint64_t i = 0; i <= b_pos; i++) {
            fr_t tmp;
            // a[diff + i] -= b[i] * quot
            fr_mul(&tmp, &out->coeffs[diff], &divisor->coeffs[i]);
            fr_sub(&a[diff + i], &a[diff + i], &tmp);
        }
        --diff;
        --a_pos;
    }
    fr_div(&out->coeffs[0], &a[a_pos], &divisor->coeffs[b_pos]);

    free(a);
    return C_KZG_OK;
}

/**
 * Calculate the (possibly truncated) product of two polynomials.
 *
 * The size of the output polynomial determines the number of coefficients returned.
 *
 * @param[in,out] out The result of the division - its size determines the number of coefficients returned
 * @param[in]     a   The muliplicand polynomial
 * @param[in]     b   The multiplier polynomial
 * @retval C_CZK_OK   All is well
 */
static C_KZG_RET poly_mul_direct(poly *out, const poly *a, const poly *b) {

    uint64_t a_degree = a->length - 1;
    uint64_t b_degree = b->length - 1;

    for (uint64_t k = 0; k < out->length; k++) {
        out->coeffs[k] = fr_zero;
    }

    // Truncate the output to the length of the output polynomial
    for (uint64_t i = 0; i <= a_degree; i++) {
        for (uint64_t j = 0; j <= b_degree && i + j < out->length; j++) {
            fr_t tmp;
            fr_mul(&tmp, &a->coeffs[i], &b->coeffs[j]);
            fr_add(&out->coeffs[i + j], &out->coeffs[i + j], &tmp);
        }
    }

    return C_KZG_OK;
}

/**
 * Calculate the (possibly truncated) product of two polynomials.
 *
 * The size of the output polynomial determines the number of coefficients returned.
 *
 * @remark This version uses FFTs to calculate the product via convolution, and is very efficient for large
 * calculations. If @p fs is supplied as NULL, then the FFTSettings are allocated internally, otherwise the supplied
 * settings are used, which must be sufficiently sized for the calculation.
 *
 * @param[in,out] out The result of the division - its size determines the number of coefficients returned
 * @param[in]     a   The muliplicand polynomial
 * @param[in]     b   The multiplier polynomial
 * @param[in]     fs_ Either NULL or a sufficiently sized FFTSettings structure
 * @retval C_CZK_OK   All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_ERROR   An internal error occurred
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
static C_KZG_RET poly_mul_fft(poly *out, const poly *a, const poly *b, FFTSettings *fs_) {

    // Truncate a and b so as not to do excess work for the number of coefficients required.
    uint64_t a_len = min_u64(a->length, out->length);
    uint64_t b_len = min_u64(b->length, out->length);
    uint64_t length = next_power_of_two(a_len + b_len - 1);

    // If the FFT settings are NULL then make a local set, otherwise use the ones passed in.
    FFTSettings fs, *fs_p;
    if (fs_ != NULL) {
        fs_p = fs_;
    } else {
        fs_p = &fs;
        int scale = log2_pow2(length); // TODO only good up to length < 32 bits
        TRY(new_fft_settings(fs_p, scale));
    }
    CHECK(length <= fs_p->max_width);

    fr_t *a_pad, *b_pad, *a_fft, *b_fft;
    TRY(new_fr_array(&a_pad, length));
    TRY(new_fr_array(&b_pad, length));
    pad(a_pad, a->coeffs, a_len, length);
    pad(b_pad, b->coeffs, b_len, length);

    TRY(new_fr_array(&a_fft, length));
    TRY(new_fr_array(&b_fft, length));
    TRY(fft_fr(a_fft, a_pad, false, length, fs_p));
    TRY(fft_fr(b_fft, b_pad, false, length, fs_p));

    fr_t *ab_fft = a_pad; // reuse the a_pad array
    fr_t *ab = b_pad;     // reuse the b_pad array
    for (uint64_t i = 0; i < length; i++) {
        fr_mul(&ab_fft[i], &a_fft[i], &b_fft[i]);
    }
    TRY(fft_fr(ab, ab_fft, true, length, fs_p));

    // Copy result to output
    uint64_t data_len = min_u64(out->length, length);
    for (uint64_t i = 0; i < data_len; i++) {
        out->coeffs[i] = ab[i];
    }
    for (uint64_t i = data_len; i < out->length; i++) {
        out->coeffs[i] = fr_zero;
    }

    free(a_pad);
    free(b_pad);
    free(a_fft);
    free(b_fft);
    if (fs_p == &fs) {
        free_fft_settings(fs_p);
    }

    return C_KZG_OK;
}

/**
 * Calculate terms in the inverse of a polynomial.
 *
 * Returns terms in the expansion of `1 / b(x)` (aka the Maclaurin series).
 *
 * The size of @p out determines the number of terms returned.
 *
 * This is a non-recursive version of the algorithm in https://tc-arg.tk/pdfs/2020/fft.pdf theorem 3.4.
 *
 * @remark The constant term of @p b must be nonzero.
 *
 * @param[in, out] out A poly whose length determines the number of terms returned
 * @param[in]      b   The polynomial to be inverted
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_ERROR   An internal error occurred
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET poly_inverse(poly *out, poly *b) {
    poly tmp0, tmp1;
    fr_t fr_two;

    CHECK(out->length > 0);
    CHECK(b->length > 0);
    CHECK(!fr_is_zero(&b->coeffs[0]));

    // If the input polynomial is constant, the remainder of the series is zero
    if (b->length == 1) {
        fr_inv(&out->coeffs[0], &b->coeffs[0]);
        for (uint64_t i = 1; i < out->length; i++) {
            out->coeffs[i] = fr_zero;
        }
        return C_KZG_OK;
    }

    uint64_t length = out->length;
    uint64_t maxd = length - 1;
    uint64_t d = 0;

    // Max space for multiplications is (2 * length - 1)
    int scale = log2_pow2(next_power_of_two(2 * length - 1));
    FFTSettings fs;
    TRY(new_fft_settings(&fs, scale));

    // To store intermediate results
    TRY(new_poly(&tmp0, length));
    TRY(new_poly(&tmp1, length));

    // Base case for d == 0
    fr_inv(&out->coeffs[0], &b->coeffs[0]);
    out->length = 1;

    uint64_t mask = (uint64_t)1 << log2_u64(maxd);
    while (mask) {

        d = 2 * d + ((maxd & mask) != 0);
        mask >>= 1;

        // b.c -> tmp0 (we're using out for c)
        tmp0.length = min_u64(d + 1, b->length + out->length - 1);
        TRY(poly_mul_(&tmp0, b, out, &fs));

        // 2 - b.c -> tmp0
        for (int i = 0; i < tmp0.length; i++) {
            fr_negate(&tmp0.coeffs[i], &tmp0.coeffs[i]);
        }
        fr_from_uint64(&fr_two, 2);
        fr_add(&tmp0.coeffs[0], &tmp0.coeffs[0], &fr_two);

        // c.(2 - b.c) -> tmp1;
        tmp1.length = d + 1;
        TRY(poly_mul_(&tmp1, out, &tmp0, &fs));

        // tmp1 -> c
        out->length = tmp1.length;
        for (uint64_t i = 0; i < out->length; i++) {
            out->coeffs[i] = tmp1.coeffs[i];
        }
    }
    ASSERT(d + 1 == length);

    free_poly(&tmp0);
    free_poly(&tmp1);
    free_fft_settings(&fs);

    return C_KZG_OK;
}

/**
 * Reverse the order of the coefficients of a polynomial.
 *
 * Corresponds to returning x^n.p(1/x).
 *
 * @param[out] out The flipped polynomial. Its size must be the same as the size of @p in
 * @param[in]  in  The polynomial to be flipped
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 */
C_KZG_RET poly_flip(poly *out, const poly *in) {
    CHECK(out->length == in->length);
    for (uint64_t i = 0; i < in->length; i++) {
        out->coeffs[out->length - i - 1] = in->coeffs[i];
    }
    return C_KZG_OK;
}

/**
 * Fast polynomial division in the finite field.
 *
 * Returns the polynomial resulting from dividing @p dividend by @p divisor.
 *
 * Implements https://tc-arg.tk/pdfs/2020/fft.pdf theorem 3.5.
 *
 * Should be O(m.log(m)) where m is the length of the dividend.
 *
 * @remark @p out must be sized large enough for the resulting polynomial.
 *
 * @remark For some ranges of @p dividend and @p divisor, #poly_long_div may be a little faster.
 *
 * @param[out] out      An appropriately sized poly type that will contain the result of the division
 * @param[in]  dividend The dividend polynomial
 * @param[in]  divisor  The divisor polynomial
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_ERROR   An internal error occurred
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
static C_KZG_RET poly_fast_div(poly *out, const poly *dividend, const poly *divisor) {

    // Dividing by zero is undefined
    CHECK(divisor->length > 0);

    // The divisor's highest coefficient must be non-zero
    CHECK(!fr_is_zero(&divisor->coeffs[divisor->length - 1]));

    uint64_t m = dividend->length - 1;
    uint64_t n = divisor->length - 1;

    // If the divisor is larger than the dividend, the result is zero-length
    if (n > m) {
        out->length = 0;
        return C_KZG_OK;
    }

    // Ensure the output poly has enough space allocated
    CHECK(out->length >= m - n + 1);

    // Ensure that the divisor is well-formed for the inverse operation
    CHECK(!fr_is_zero(&divisor->coeffs[divisor->length - 1]));

    // Special case for divisor.length == 1 (it's a constant)
    if (divisor->length == 1) {
        out->length = dividend->length;
        for (uint64_t i = 0; i < out->length; i++) {
            fr_div(&out->coeffs[i], &dividend->coeffs[i], &divisor->coeffs[0]);
        }
        return C_KZG_OK;
    }

    poly a_flip, b_flip;
    TRY(new_poly(&a_flip, dividend->length));
    TRY(new_poly(&b_flip, divisor->length));
    TRY(poly_flip(&a_flip, dividend));
    TRY(poly_flip(&b_flip, divisor));

    poly inv_b_flip;
    TRY(new_poly(&inv_b_flip, m - n + 1));
    TRY(poly_inverse(&inv_b_flip, &b_flip));

    poly q_flip;
    // We need only m - n + 1 coefficients of q_flip
    TRY(new_poly(&q_flip, m - n + 1));
    TRY(poly_mul(&q_flip, &a_flip, &inv_b_flip));

    out->length = m - n + 1;
    TRY(poly_flip(out, &q_flip));

    free_poly(&a_flip);
    free_poly(&b_flip);
    free_poly(&inv_b_flip);
    free_poly(&q_flip);

    return C_KZG_OK;
}

/**
 * Calculate the (possibly truncated) product of two polynomials.
 *
 * This is just a wrapper around #poly_mul_direct and #poly_mul_fft that selects the faster based on the size of the
 * problem.
 *
 * @param[in,out] out The result of the division - its size determines the number of coefficients returned
 * @param[in]     a   The muliplicand polynomial
 * @param[in]     b   The multiplier polynomial
 * @param[in]     fs  Either NULL or a sufficiently sized FFTSettings structure
 * @retval C_CZK_OK   All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_ERROR   An internal error occurred
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET poly_mul_(poly *out, const poly *a, const poly *b, FFTSettings *fs) {
    if (a->length < 64 || b->length < 64 || out->length < 128) { // Tunable parameter
        return poly_mul_direct(out, a, b);
    } else {
        return poly_mul_fft(out, a, b, fs);
    }
}

/**
 * Calculate the (possibly truncated) product of two polynomials.
 *
 * This is just a wrapper around #poly_mul_direct and #poly_mul_fft that selects the faster based on the size of the
 * problem.
 *
 * @param[in,out] out The result of the division - its size determines the number of coefficients returned
 * @param[in]     a   The muliplicand polynomial
 * @param[in]     b   The multiplier polynomial
 * @retval C_CZK_OK   All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_ERROR   An internal error occurred
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET poly_mul(poly *out, const poly *a, const poly *b) {
    return poly_mul_(out, a, b, NULL);
}

/**
 * Polynomial division in the finite field.
 *
 * Returns the polynomial resulting from dividing @p dividend_ by @p divisor_.
 *
 * This is a wrapper around #poly_long_div and #poly_fast_div that chooses the fastest based on problem size.
 *
 * @remark @p out must be an uninitialised #poly. Space is allocated for it here, which
 * must be later reclaimed by calling #free_poly().
 *
 * @param[out] out       An uninitialised poly type that will contain the result of the division
 * @param[in]  dividend_ The dividend polynomial
 * @param[in]  divisor_  The divisor polynomial
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_ERROR   An internal error occurred
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET new_poly_div(poly *out, const poly *dividend_, const poly *divisor_) {

    poly dividend = poly_norm(dividend_);
    poly divisor = poly_norm(divisor_);

    TRY(new_poly(out, poly_quotient_length(&dividend, &divisor)));
    if (divisor.length >= dividend.length || divisor.length < 128) { // Tunable paramter
        return poly_long_div(out, &dividend, &divisor);
    } else {
        return poly_fast_div(out, &dividend, &divisor);
    }
}

/**
 * Initialise an empty polynomial of the given size.
 *
 * @remark This allocates space for the polynomial coefficients that must be later reclaimed by calling #free_poly.
 *
 * @param[out] out    The initialised polynomial structure
 * @param[in]  length The number of coefficients required, which is one more than the polynomial's degree
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET new_poly(poly *out, uint64_t length) {
    out->length = length;
    return new_fr_array(&out->coeffs, length);
}

/**
 * Initialise a polynomial of the given size with the given coefficients.
 *
 * @remark This allocates space for the polynomial coefficients that must be later reclaimed by calling #free_poly.
 *
 * @param[out] out    The initialised polynomial structure
 * @param[in]  coeffs `coeffs[i]` is the coefficient of the `x^i` term of the polynomial
 * @param[in]  length The number of coefficients, which is one more than the polynomial's degree
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_MALLOC  Memory allocation failed
 *
 * @todo This is likely not useful. Remove?
 */
C_KZG_RET new_poly_with_coeffs(poly *out, const fr_t *coeffs, uint64_t length) {
    TRY(new_poly(out, length));
    for (uint64_t i = 0; i < length; i++) {
        out->coeffs[i] = coeffs[i];
    }
    return C_KZG_OK;
}

/**
 * Reclaim the memory used by a polynomial.
 *
 * @remark To avoid memory leaks, this must be called for polynomials initialised with #new_poly or
 * #new_poly_with_coeffs after use.
 *
 * @param[in,out] p The polynomial
 */
void free_poly(poly *p) {
    if (p->coeffs != NULL) {
        free(p->coeffs);
    }
}

#ifdef KZGTEST

#include "../inc/acutest.h"
#include "test_util.h"

// If anyone has a nicer way to initialise these test data, I'd love to hear it.
typedef struct polydata {
    int length;
    int coeffs[];
} polydata;

// (x^2 - 1) / (x + 1) = x - 1
polydata test_0_0 = {3, {-1, 0, 1}};
polydata test_0_1 = {2, {1, 1}};
polydata test_0_2 = {2, {-1, 1}};

// (12x^3 - 11x^2 + 9x + 18) / (4x + 3) = 3x^2 - 5x + 6
polydata test_1_0 = {4, {18, 9, -11, 12}};
polydata test_1_1 = {2, {3, 4}};
polydata test_1_2 = {3, {6, -5, 3}};

// (x + 1) / (x^2 - 1) = nil
polydata test_2_0 = {2, {1, 1}};
polydata test_2_1 = {3, {-1, 0, 2}};
polydata test_2_2 = {0, {}};

// (10x^2 + 20x + 30) / 10 = x^2 + 2x + 3
polydata test_3_0 = {3, {30, 20, 10}};
polydata test_3_1 = {1, {10}};
polydata test_3_2 = {3, {3, 2, 1}};

// (x^2 + x) / (x + 1) = x
polydata test_4_0 = {3, {0, 1, 1}};
polydata test_4_1 = {2, {1, 1}};
polydata test_4_2 = {2, {0, 1}};

// (x^2 + x + 1) / 1 = x^2 + x + 1
polydata test_5_0 = {3, {1, 1, 1}};
polydata test_5_1 = {1, {1}};
polydata test_5_2 = {3, {1, 1, 1}};

// (x^2 + x + 1) / (0x + 1) = x^2 + x + 1
polydata test_6_0 = {3, {1, 1, 1}};
polydata test_6_1 = {2, {1, 0}}; // The highest coefficient is zero
polydata test_6_2 = {3, {1, 1, 1}};

polydata *test[][3] = {{&test_0_0, &test_0_1, &test_0_2}, {&test_1_0, &test_1_1, &test_1_2},
                       {&test_2_0, &test_2_1, &test_2_2}, {&test_3_0, &test_3_1, &test_3_2},
                       {&test_4_0, &test_4_1, &test_4_2}, {&test_5_0, &test_5_1, &test_5_2},
                       {&test_6_0, &test_6_1, &test_6_2}};

/* Internal utility function */
void new_test_poly(poly *p, polydata *data) {
    new_poly(p, data->length);
    for (int i = 0; i < p->length; i++) {
        int coeff = data->coeffs[i];
        if (coeff >= 0) {
            fr_from_uint64(&p->coeffs[i], coeff);
        } else {
            fr_from_uint64(&p->coeffs[i], -coeff);
            fr_negate(&p->coeffs[i], &p->coeffs[i]);
        }
    }
}

void poly_test_div(void) {
    poly dividend, divisor, expected, actual;
    int ntest = sizeof test / sizeof test[0];

    for (int i = 0; i < ntest; i++) {
        new_test_poly(&dividend, test[i][0]);
        new_test_poly(&divisor, test[i][1]);
        new_test_poly(&expected, test[i][2]);

        if (TEST_CHECK(C_KZG_OK == new_poly_div(&actual, &dividend, &divisor))) {
            if (TEST_CHECK(actual.length == expected.length)) {
                for (int j = 0; j < actual.length; j++) {
                    TEST_CHECK(fr_equal(&actual.coeffs[j], &expected.coeffs[j]));
                    TEST_MSG("Failed test %d with incorrect value", i);
                }
            } else {
                TEST_MSG("Failed test %d with incorrect length.", i);
            }
        } else {
            TEST_MSG("Failed test %d with bad return value.", i);
        }

        free_poly(&dividend);
        free_poly(&divisor);
        free_poly(&expected);
        free_poly(&actual);
    }
}

void poly_div_by_zero(void) {
    fr_t a[2];
    poly dividend, divisor, dummy;

    // Calculate (x + 1) / 0 = FAIL

    // Dividend
    fr_from_uint64(&a[0], 1);
    fr_from_uint64(&a[1], 1);
    dividend.length = 2;
    dividend.coeffs = a;

    // Divisor
    new_poly(&divisor, 0);

    TEST_CHECK(C_KZG_BADARGS == new_poly_div(&dummy, &dividend, &divisor));

    free_poly(&divisor);
    free_poly(&dummy);
}

void poly_eval_check(void) {
    uint64_t n = 10;
    fr_t actual, expected;
    poly p;
    new_poly(&p, n);
    for (uint64_t i = 0; i < n; i++) {
        fr_from_uint64(&p.coeffs[i], i + 1);
    }
    fr_from_uint64(&expected, n * (n + 1) / 2);

    eval_poly(&actual, &p, &fr_one);

    TEST_CHECK(fr_equal(&expected, &actual));

    free_poly(&p);
}

void poly_eval_0_check(void) {
    uint64_t n = 7, a = 597;
    fr_t actual, expected;
    poly p;
    new_poly(&p, n);
    for (uint64_t i = 0; i < n; i++) {
        fr_from_uint64(&p.coeffs[i], i + a);
    }
    fr_from_uint64(&expected, a);

    eval_poly(&actual, &p, &fr_zero);

    TEST_CHECK(fr_equal(&expected, &actual));

    free_poly(&p);
}

void poly_eval_nil_check(void) {
    uint64_t n = 0;
    fr_t actual;
    poly p;
    new_poly(&p, n);

    eval_poly(&actual, &p, &fr_one);

    TEST_CHECK(fr_equal(&fr_zero, &actual));

    free_poly(&p);
}

void poly_mul_direct_test(void) {

    // Calculate (3x^2 - 5x + 6) * (4x + 3) = 12x^3 - 11x^2 + 9x + 18
    static polydata multiplier_data = {3, {6, -5, 3}};
    static polydata multiplicand_data = {2, {3, 4}};
    static polydata expected_data = {4, {18, 9, -11, 12}};

    poly multiplicand, multiplier, expected, actual0, actual1;

    new_test_poly(&multiplicand, &multiplicand_data);
    new_test_poly(&multiplier, &multiplier_data);
    new_test_poly(&expected, &expected_data);

    new_poly(&actual0, 4);
    TEST_CHECK(C_KZG_OK == poly_mul_direct(&actual0, &multiplicand, &multiplier));
    TEST_CHECK(fr_equal(&expected.coeffs[0], &actual0.coeffs[0]));
    TEST_CHECK(fr_equal(&expected.coeffs[1], &actual0.coeffs[1]));
    TEST_CHECK(fr_equal(&expected.coeffs[2], &actual0.coeffs[2]));
    TEST_CHECK(fr_equal(&expected.coeffs[3], &actual0.coeffs[3]));

    // Check commutativity
    new_poly(&actual1, 4);
    TEST_CHECK(C_KZG_OK == poly_mul_direct(&actual1, &multiplier, &multiplicand));
    TEST_CHECK(fr_equal(&expected.coeffs[0], &actual1.coeffs[0]));
    TEST_CHECK(fr_equal(&expected.coeffs[1], &actual1.coeffs[1]));
    TEST_CHECK(fr_equal(&expected.coeffs[2], &actual1.coeffs[2]));
    TEST_CHECK(fr_equal(&expected.coeffs[3], &actual1.coeffs[3]));

    free_poly(&multiplicand);
    free_poly(&multiplier);
    free_poly(&expected);
    free_poly(&actual0);
    free_poly(&actual1);
}

void poly_mul_fft_test(void) {

    // Calculate (3x^2 - 5x + 6) * (4x + 3) = 12x^3 - 11x^2 + 9x + 18
    static polydata multiplier_data = {3, {6, -5, 3}};
    static polydata multiplicand_data = {2, {3, 4}};
    static polydata expected_data = {4, {18, 9, -11, 12}};

    poly multiplicand, multiplier, expected, actual0, actual1;

    new_test_poly(&multiplicand, &multiplicand_data);
    new_test_poly(&multiplier, &multiplier_data);
    new_test_poly(&expected, &expected_data);

    new_poly(&actual0, 4);
    TEST_CHECK(C_KZG_OK == poly_mul_fft(&actual0, &multiplicand, &multiplier, NULL));
    TEST_CHECK(fr_equal(&expected.coeffs[0], &actual0.coeffs[0]));
    TEST_CHECK(fr_equal(&expected.coeffs[1], &actual0.coeffs[1]));
    TEST_CHECK(fr_equal(&expected.coeffs[2], &actual0.coeffs[2]));
    TEST_CHECK(fr_equal(&expected.coeffs[3], &actual0.coeffs[3]));

    // Check commutativity
    new_poly(&actual1, 4);
    TEST_CHECK(C_KZG_OK == poly_mul_fft(&actual1, &multiplier, &multiplicand, NULL));
    TEST_CHECK(fr_equal(&expected.coeffs[0], &actual1.coeffs[0]));
    TEST_CHECK(fr_equal(&expected.coeffs[1], &actual1.coeffs[1]));
    TEST_CHECK(fr_equal(&expected.coeffs[2], &actual1.coeffs[2]));
    TEST_CHECK(fr_equal(&expected.coeffs[3], &actual1.coeffs[3]));

    free_poly(&multiplicand);
    free_poly(&multiplier);
    free_poly(&expected);
    free_poly(&actual0);
    free_poly(&actual1);
}

void poly_inverse_simple_0(void) {

    // 1 / (1 - x) = 1 + x + x^2 + ...

    poly p, q;
    int d = 16; // The number of terms to take

    new_poly(&p, 2);
    p.coeffs[0] = fr_one;
    p.coeffs[1] = fr_one;
    fr_negate(&p.coeffs[1], &p.coeffs[1]);

    new_poly(&q, d);
    TEST_CHECK(C_KZG_OK == poly_inverse(&q, &p));

    for (int i = 0; i < d; i++) {
        TEST_CHECK(fr_is_one(&q.coeffs[i]));
    }

    free_poly(&p);
    free_poly(&q);
}

void poly_inverse_simple_1(void) {

    // 1 / (1 + x) = 1 - x + x^2 - ...

    poly p, q;
    int d = 16; // The number of terms to take

    new_poly(&p, 2);
    p.coeffs[0] = fr_one;
    p.coeffs[1] = fr_one;

    new_poly(&q, d);
    TEST_CHECK(C_KZG_OK == poly_inverse(&q, &p));

    for (int i = 0; i < d; i++) {
        fr_t tmp = q.coeffs[i];
        if (i & 1) {
            fr_negate(&tmp, &tmp);
        }
        TEST_CHECK(fr_is_one(&tmp));
    }

    free_poly(&p);
    free_poly(&q);
}

void poly_mul_random(void) {

    // Compare the output of poly_mul_direct() and poly_mul_fft()

    poly multiplicand, multiplier;
    poly q0, q1;

    for (int k = 0; k < 256; k++) {

        int multiplicand_length = 1 + rand() % 1000;
        int multiplier_length = 1 + rand() % 1000;
        int out_length = 1 + rand() % 1000;

        new_poly(&multiplicand, multiplicand_length);
        new_poly(&multiplier, multiplier_length);

        for (int i = 0; i < multiplicand_length; i++) {
            multiplicand.coeffs[i] = rand_fr();
        }
        for (int i = 0; i < multiplier_length; i++) {
            multiplier.coeffs[i] = rand_fr();
        }

        // Ensure that the polynomials' orders corresponds to their lengths
        if (fr_is_zero(&multiplicand.coeffs[multiplicand.length - 1])) {
            multiplicand.coeffs[multiplicand.length - 1] = fr_one;
        }
        if (fr_is_zero(&multiplier.coeffs[multiplier.length - 1])) {
            multiplier.coeffs[multiplier.length - 1] = fr_one;
        }

        new_poly(&q0, out_length); // Truncate the result
        TEST_CHECK(C_KZG_OK == poly_mul_direct(&q0, &multiplicand, &multiplier));

        new_poly(&q1, out_length);
        TEST_CHECK(C_KZG_OK == poly_mul_fft(&q1, &multiplicand, &multiplier, NULL));

        TEST_CHECK(q1.length == q0.length);
        for (int i = 0; i < q0.length; i++) {
            if (!TEST_CHECK(fr_equal(&q0.coeffs[i], &q1.coeffs[i]))) {
                TEST_MSG("round = %d, i = %d, multiplicand_length = %lu, multiplier_length = %lu, out_length = %lu", k,
                         i, multiplicand.length, multiplier.length, q0.length);
            }
        }

        free_poly(&multiplicand);
        free_poly(&multiplier);
        free_poly(&q0);
        free_poly(&q1);
    }
}

void poly_div_random(void) {

    // Compare the output of poly_fast_div() and poly_long_div()

    poly dividend, divisor;
    poly q0, q1;

    for (int k = 0; k < 256; k++) {

        int dividend_length = 2 + rand() % 1000;
        int divisor_length = 1 + rand() % dividend_length;

        new_poly(&dividend, dividend_length);
        new_poly(&divisor, divisor_length);

        for (int i = 0; i < dividend_length; i++) {
            dividend.coeffs[i] = rand_fr();
        }
        for (int i = 0; i < divisor_length; i++) {
            divisor.coeffs[i] = rand_fr();
        }

        // Ensure that the polynomials' orders corresponds to their lengths
        if (fr_is_zero(&dividend.coeffs[dividend.length - 1])) {
            dividend.coeffs[dividend.length - 1] = fr_one;
        }
        if (fr_is_zero(&divisor.coeffs[divisor.length - 1])) {
            divisor.coeffs[divisor.length - 1] = fr_one;
        }

        new_poly(&q0, dividend.length - divisor.length + 1);
        TEST_CHECK(C_KZG_OK == poly_long_div(&q0, &dividend, &divisor));

        new_poly(&q1, dividend.length - divisor.length + 1);
        TEST_CHECK(C_KZG_OK == poly_fast_div(&q1, &dividend, &divisor));

        TEST_CHECK(q1.length == q0.length);
        for (int i = 0; i < q0.length; i++) {
            if (!TEST_CHECK(fr_equal(&q0.coeffs[i], &q1.coeffs[i]))) {
                TEST_MSG("round = %d, dividend_length = %lu, divisor_length = %lu, i = %d", k, dividend.length,
                         divisor.length, i);
            }
        }

        free_poly(&dividend);
        free_poly(&divisor);
        free_poly(&q0);
        free_poly(&q1);
    }
}

TEST_LIST = {
    {"POLY_TEST", title},
    {"poly_test_div", poly_test_div},
#ifndef DEBUG
    {"poly_div_by_zero", poly_div_by_zero},
#endif
    {"poly_eval_check", poly_eval_check},
    {"poly_eval_0_check", poly_eval_0_check},
    {"poly_eval_nil_check", poly_eval_nil_check},
    {"poly_mul_direct_test", poly_mul_direct_test},
    {"poly_mul_fft_test", poly_mul_fft_test},
    {"poly_inverse_simple_0", poly_inverse_simple_0},
    {"poly_inverse_simple_1", poly_inverse_simple_1},
    {"poly_mul_random", poly_mul_random},
    {"poly_div_random", poly_div_random},
    {NULL, NULL} /* zero record marks the end of the list */
};

#endif // KZGTEST
