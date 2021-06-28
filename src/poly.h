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

#ifndef POLY_H
#define POLY_H

#include "c_kzg.h"
#include "fft_fr.h"

/**
 * Defines a polynomial whose coefficients are members of the finite field F_r.
 *
 * Initialise the storage with #new_poly. After use, free the storage with #free_poly.
 */
typedef struct {
    fr_t *coeffs;    /**< `coeffs[i]` is the coefficient of the `x^i` term of the polynomial. */
    uint64_t length; /**< One more than the polynomial's degree */
} poly;

void eval_poly(fr_t *out, const poly *p, const fr_t *x);
C_KZG_RET poly_long_div(poly *out, const poly *dividend, const poly *divisor);
C_KZG_RET poly_mul_direct(poly *out, const poly *a, const poly *b);
C_KZG_RET poly_mul_fft(poly *out, const poly *a, const poly *b, FFTSettings *fs);
C_KZG_RET poly_inverse(poly *out, poly *b);
C_KZG_RET poly_fast_div(poly *out, const poly *dividend, const poly *divisor);
C_KZG_RET poly_mul(poly *out, const poly *a, const poly *b);
C_KZG_RET poly_mul_(poly *out, const poly *a, const poly *b, FFTSettings *fs);
C_KZG_RET new_poly_div(poly *out, const poly *dividend, const poly *divisor);
C_KZG_RET new_poly(poly *out, uint64_t length);
C_KZG_RET new_poly_with_coeffs(poly *out, const fr_t *coeffs, uint64_t length);
void free_poly(poly *p);

#endif // POLY_H
