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

#include "blst_util.h"
#include "debug_util.h"

bool fr_is_one(const blst_fr *fr_p) {
    uint64_t a[4];
    blst_uint64_from_fr(a, fr_p);
    return a[0] == 1 && a[1] == 0 && a[2] == 0 && a[3] == 0;
}

void fr_from_uint64(blst_fr *a, const uint64_t n) {
    uint64_t vals[] = {n, 0, 0, 0};
    blst_fr_from_uint64(a, vals);
}

bool fr_equal(const blst_fr *aa, const blst_fr *bb) {
    uint64_t a[4], b[4];
    blst_uint64_from_fr(a, aa);
    blst_uint64_from_fr(b, bb);
    return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3];
}

// TODO: Is there really no better way to do this?
void p1_mul(blst_p1 *out, const blst_p1 *a, const blst_fr *b) {
    blst_scalar s;
    blst_scalar_from_fr(&s, b);
    blst_p1_mult(out, a, s.b, 8 * sizeof(blst_scalar));
}

void p1_sub(blst_p1 *out, const blst_p1 *a, const blst_p1 *b) {
    blst_p1 bneg = *b;
    blst_p1_cneg(&bneg, true);
    blst_p1_add_or_double(out, a, &bneg);
}

// TODO: would be good to have an optimised multiexp for this
void linear_combination_g1(blst_p1 *out, const blst_p1 *p, const blst_fr *coeffs, const uint64_t len) {
    blst_p1 tmp;
    blst_p1_from_affine(out, &identity_g1_affine);
    for (uint64_t i = 0; i < len; i++) {
        p1_mul(&tmp, &p[i], &coeffs[i]);
        blst_p1_add_or_double(out, out, &tmp);
    }
}
