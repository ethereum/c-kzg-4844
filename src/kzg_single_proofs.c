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

#include "kzg_single_proofs.h"

void commit_to_poly(blst_p1 *out, const KZGSettings *ks, const poly *p) {
    linear_combination_g1(out, ks->secret_g1, p->coeffs, p->length);
}

// Compute KZG proof for polynomial at position x0
void compute_proof_single(blst_p1 *out, const KZGSettings *ks, poly *p, const uint64_t x0) {
    poly divisor, q;
    blst_fr tmp;

    // The divisor is x - x0
    poly_init(&divisor, 2);
    fr_from_uint64(&tmp, x0);
    fr_negate(&divisor.coeffs[0],&tmp);
    divisor.coeffs[1] = one;

    // Calculate q = p / (x - x0)
    poly_init(&q, poly_quotient_length(p, &divisor));
    poly_long_div(&q, p, &divisor);

    linear_combination_g1(out, ks->secret_g1, q.coeffs, q.length);

    poly_free(q);
    poly_free(divisor);
}

bool check_proof_single(const KZGSettings *ks, const blst_p1 *commitment, const blst_p1 *proof, const blst_fr *x, blst_fr *y) {
    blst_p2 x_g2, s_minus_x;
    blst_p1 y_g1, commitment_minus_y;
    p2_mul(&x_g2, blst_p2_generator(), x);
    p2_sub(&s_minus_x, &ks->secret_g2[1], &x_g2);
    p1_mul(&y_g1, blst_p1_generator(), y);
    p1_sub(&commitment_minus_y, commitment, &y_g1);

    return pairings_verify(&commitment_minus_y, blst_p2_generator(), proof, &s_minus_x);
}
