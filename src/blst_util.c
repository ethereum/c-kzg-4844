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

// TODO - find a better way to do this
bool fr_is_zero(const blst_fr *p) {
    uint64_t a[4];
    blst_uint64_from_fr(a, p);
    return a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0;
}

// TODO - find a better way to do this
bool fr_is_one(const blst_fr *p) {
    uint64_t a[4];
    blst_uint64_from_fr(a, p);
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

void fr_negate(blst_fr *out, const blst_fr *in) {
    blst_fr_cneg(out, in, true);
}

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

void p2_mul(blst_p2 *out, const blst_p2 *a, const blst_fr *b) {
    blst_scalar s;
    blst_scalar_from_fr(&s, b);
    blst_p2_mult(out, a, s.b, 8 * sizeof(blst_scalar));
}

void p2_sub(blst_p2 *out, const blst_p2 *a, const blst_p2 *b) {
    blst_p2 bneg = *b;
    blst_p2_cneg(&bneg, true);
    blst_p2_add_or_double(out, a, &bneg);
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

bool pairings_verify(const blst_p1 *aa1, const blst_p2 *aa2, const blst_p1 *bb1, const blst_p2 *bb2) {
    blst_fp12 loop0, loop1, gt_point;
    blst_p1_affine a1, b1;
    blst_p2_affine a2, b2;

    // As an optimisation, we want to invert one of the pairings,
    // so we negate one of the points.
    blst_p1 a1neg = *aa1;
    blst_p1_cneg(&a1neg, true);

    blst_p1_to_affine(&a1, &a1neg);
    blst_p1_to_affine(&b1, bb1);
    blst_p2_to_affine(&a2, aa2);
    blst_p2_to_affine(&b2, bb2);

    blst_miller_loop(&loop0, &a2, &a1);
    blst_miller_loop(&loop1, &b2, &b1);

    blst_fp12_mul(&gt_point, &loop0, &loop1);
    blst_final_exp(&gt_point, &gt_point);

    return blst_fp12_is_one(&gt_point);
}
