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

#include "c_kzg_util.h"
#include "utility.h"
#include "poly.h"

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
C_KZG_RET poly_long_div(poly *out, const poly *dividend, const poly *divisor) {
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
C_KZG_RET poly_mul_direct(poly *out, const poly *a, const poly *b) {

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
 * Pad with zeros or truncate an array of field elements to a specific size.
 *
 * @param[out] out   The padded/truncated array
 * @param[in]  in    The original array to be padded
 * @param[in]  n_in  The number of elements of @p in to take
 * @param[in]  n_out The length of @p out
 */
void pad(fr_t *out, const fr_t *in, uint64_t n_in, uint64_t n_out) {
    uint64_t num = min_u64(n_in, n_out);
    for (int i = 0; i < num; i++) {
        out[i] = in[i];
    }
    for (int i = num; i < n_out; i++) {
        out[i] = fr_zero;
    }
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
C_KZG_RET poly_mul_fft(poly *out, const poly *a, const poly *b, FFTSettings *fs_) {

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
C_KZG_RET poly_fast_div(poly *out, const poly *dividend, const poly *divisor) {

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
 *
 * @todo Implement routine selection
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
 *
 * @todo Implement routine selection
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
