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

/** @file poly.h */

#include "c_kzg.h"
#include "blst_util.h"

/**
 * Defines a polynomial whose coefficients are members of the finite field F_r.
 *
 * Initialise the storage with #init_poly. After use, free the storage with #free_poly.
 */
typedef struct {
    blst_fr *coeffs; /**< `coeffs[i]` is the coefficient of the `x^i` term of the polynomial. */
    uint64_t length; /**< One more than the polynomial's degree */
} poly;

void eval_poly(blst_fr *out, const poly *p, const blst_fr *x);
uint64_t poly_quotient_length(const poly *dividend, const poly *divisor);
C_KZG_RET poly_long_div(poly *out, const poly *dividend, const poly *divisor);
C_KZG_RET init_poly_with_coeffs(poly *out, const uint64_t *coeffs, const uint64_t length);
C_KZG_RET init_poly(poly *out, const uint64_t length);
void free_poly(poly *p);
