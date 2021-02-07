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

#include <stdlib.h> // NULL, free()
#include "c_kzg_util.h"
#include "poly.h"

static void poly_factor_div(blst_fr *out, const blst_fr *a, const blst_fr *b) {
    blst_fr_eucl_inverse(out, b);
    blst_fr_mul(out, out, a);
}

C_KZG_RET init_poly(poly *out, const uint64_t length) {
    out->length = length;
    return c_kzg_malloc((void **)&out->coeffs, length * sizeof(blst_fr));
}

void free_poly(poly *p) {
    if (p->coeffs != NULL) {
        free(p->coeffs);
    }
}

void eval_poly(blst_fr *out, const poly *p, const blst_fr *x) {
    blst_fr tmp;
    uint64_t i;

    if (p->length == 0) {
        fr_from_uint64(out, 0);
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

// Call this to find out how much space to allocate for the result of `poly_long_div()`
uint64_t poly_quotient_length(const poly *dividend, const poly *divisor) {
    return dividend->length >= divisor->length ? dividend->length - divisor->length + 1 : 0;
}

// `out` must be an uninitialised poly and has space allocated for it here, which
// must be freed by calling `free_poly()` later.
C_KZG_RET poly_long_div(poly *out, const poly *dividend, const poly *divisor) {
    uint64_t a_pos = dividend->length - 1;
    uint64_t b_pos = divisor->length - 1;
    uint64_t diff = a_pos - b_pos;
    blst_fr a[dividend->length];

    // Dividing by zero is undefined
    ASSERT(divisor->length > 0, C_KZG_BADARGS);

    // Initialise the output polynomial
    ASSERT(init_poly(out, poly_quotient_length(dividend, divisor)) == C_KZG_OK, C_KZG_MALLOC);

    // If the divisor is larger than the dividend, the result is zero-length
    if (out->length == 0) return C_KZG_OK;

    for (uint64_t i = 0; i < dividend->length; i++) {
        a[i] = dividend->coeffs[i];
    }

    while (diff > 0) {
        poly_factor_div(&out->coeffs[diff], &a[a_pos], &divisor->coeffs[b_pos]);
        for (uint64_t i = 0; i <= b_pos; i++) {
            blst_fr tmp;
            // a[diff + i] -= b[i] * quot
            blst_fr_mul(&tmp, &out->coeffs[diff], &divisor->coeffs[i]);
            blst_fr_sub(&a[diff + i], &a[diff + i], &tmp);
        }
        --diff;
        --a_pos;
    }
    poly_factor_div(&out->coeffs[0], &a[a_pos], &divisor->coeffs[b_pos]);

    return C_KZG_OK;
}
