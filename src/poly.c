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

#include "poly.h"

static void poly_factor_div(blst_fr *out, const blst_fr *a, const blst_fr *b) {
    blst_fr_eucl_inverse(out, b);
    blst_fr_mul(out, out, a);
}

void poly_init(poly *out, const uint64_t length) {
    out->length = length;
    out->coeffs = malloc(length * sizeof(blst_fr));
}

void poly_free(poly p) {
    free(p.coeffs);
}

void poly_eval(blst_fr *out, const poly *p, const blst_fr *x) {
    blst_fr tmp;
    uint64_t i;

    if (p->length == 0) {
        fr_from_uint64(out, 0);
    }
    if (fr_is_zero(x)) {
        *out = p->coeffs[0];
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

// Call this to find out how much space to allocate for the result
C_KZG_RET poly_quotient_length(uint64_t *out, const poly *dividend, const poly *divisor) {
    ASSERT(dividend->length >= divisor->length, C_KZG_BADARGS);
    *out = dividend->length - divisor->length + 1;
    return C_KZG_OK;
}

// `out` must have been pre-allocated to the correct size, and the length is provided
// as a check
C_KZG_RET poly_long_div(poly *out, const poly *dividend, const poly *divisor) {
    uint64_t a_pos = dividend->length - 1;
    uint64_t b_pos = divisor->length - 1;
    uint64_t diff = a_pos - b_pos;
    blst_fr a[dividend->length];

    ASSERT(out->length == diff + 1, C_KZG_BADARGS);

    for (uint64_t i = 0; i < dividend->length; i++) {
        a[i] = dividend->coeffs[i];
    }

    while (true) {
        poly_factor_div(&out->coeffs[diff], &a[a_pos], &divisor->coeffs[b_pos]);
        for (uint64_t i = 0; i <= b_pos; i++) {
            blst_fr tmp;
            // a[diff + i] -= b[i] * quot
            blst_fr_mul(&tmp, &out->coeffs[diff], &divisor->coeffs[i]);
            blst_fr_sub(&a[diff + i], &a[diff + i], &tmp);
        }
        if (diff == 0) break;
        --diff;
        --a_pos;
    }

    return C_KZG_OK;
}
