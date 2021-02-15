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
 *  @file poly.c
 *
 * Operations on polynomials defined over the finite field.
 */

#include "c_kzg_util.h"
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
 * Evaluate a polynomial over the finite field at a point.
 *
 * @param[out] out The value of the polynomial at the point @p x
 * @param[in]  p   The polynomial
 * @param[in]  x   The x-coordinate to be evaluated
 */
void eval_poly(blst_fr *out, const poly *p, const blst_fr *x) {
    blst_fr tmp;
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
        blst_fr_mul(&tmp, out, x);
        blst_fr_add(out, &tmp, &p->coeffs[i]);
        if (i == 0) break;
        --i;
    }
}

/**
 * Polynomial division in the finite field.
 *
 * Returns the polynomial resulting from dividing @p dividend by @p divisor.
 *
 * @remark @p out must be an uninitialised #poly. Space is allocated for it here, which
 * must be later reclaimed by calling #free_poly().
 *
 * @param[out] out      An uninitialised poly type that will contain the result of the division
 * @param[in]  dividend The dividend polynomial
 * @param[in]  divisor  The divisor polynomial
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET new_poly_long_div(poly *out, const poly *dividend, const poly *divisor) {
    uint64_t a_pos = dividend->length - 1;
    uint64_t b_pos = divisor->length - 1;
    uint64_t diff = a_pos - b_pos;
    blst_fr a[dividend->length];

    // Dividing by zero is undefined
    ASSERT(divisor->length > 0, C_KZG_BADARGS);

    // Initialise the output polynomial
    TRY(new_poly(out, poly_quotient_length(dividend, divisor)));

    // If the divisor is larger than the dividend, the result is zero-length
    if (out->length == 0) return C_KZG_OK;

    for (uint64_t i = 0; i < dividend->length; i++) {
        a[i] = dividend->coeffs[i];
    }

    while (diff > 0) {
        fr_div(&out->coeffs[diff], &a[a_pos], &divisor->coeffs[b_pos]);
        for (uint64_t i = 0; i <= b_pos; i++) {
            blst_fr tmp;
            // a[diff + i] -= b[i] * quot
            blst_fr_mul(&tmp, &out->coeffs[diff], &divisor->coeffs[i]);
            blst_fr_sub(&a[diff + i], &a[diff + i], &tmp);
        }
        --diff;
        --a_pos;
    }
    fr_div(&out->coeffs[0], &a[a_pos], &divisor->coeffs[b_pos]);

    return C_KZG_OK;
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
    return new_fr(&out->coeffs, length);
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
C_KZG_RET new_poly_with_coeffs(poly *out, const blst_fr *coeffs, uint64_t length) {
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
