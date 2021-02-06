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

#include "kzg_proofs.h"

C_KZG_RET new_kzg_settings(KZGSettings *ks, FFTSettings *fs, blst_p1 *secret_g1, blst_p2 *secret_g2, uint64_t length) {
    ASSERT(length >= fs->max_width, C_KZG_BADARGS);
    ks->fs = fs;
    ks->secret_g1 = secret_g1;
    ks->extended_secret_g1 = NULL;
    ks->secret_g2 = secret_g2;
    ks->length = length;
    return C_KZG_OK;
}

void commit_to_poly(blst_p1 *out, const KZGSettings *ks, const poly *p) {
    linear_combination_g1(out, ks->secret_g1, p->coeffs, p->length);
}

// Compute KZG proof for polynomial at position x0
C_KZG_RET compute_proof_single(blst_p1 *out, const KZGSettings *ks, poly *p, const blst_fr *x0) {
    return compute_proof_multi(out, ks, p, x0, 1);
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

// Compute KZG proof for polynomial in coefficient form at positions x * w^y where w is
// an n-th root of unity (this is the proof for one data availability sample, which consists
// of several polynomial evaluations)
C_KZG_RET compute_proof_multi(blst_p1 *out, const KZGSettings *ks, poly *p, const blst_fr *x0, uint64_t n) {
    poly divisor, q;
    uint64_t len;
    blst_fr x_pow_n;

    ASSERT(p->length >= n + 1, C_KZG_BADARGS);

    // Construct x^n - x0^n = (x - w^0)(x - w^1)...(x - w^(n-1))
    init_poly(&divisor, n + 1);

    // -(x0^n)
    fr_pow(&x_pow_n, x0, n);
    fr_negate(&divisor.coeffs[0], &x_pow_n);

    // Zeros
    for (uint64_t i = 1; i < n; i++) {
        divisor.coeffs[i] = fr_zero;
    }

    // x^n
    divisor.coeffs[n] = fr_one;

    // Calculate q = p / (x^n - x0^n)
    // Discard the return codes since we already checked above that all should be fine.
    poly_quotient_length(&len, p, &divisor);
    init_poly(&q, len);
    poly_long_div(&q, p, &divisor);

    commit_to_poly(out, ks, &q);

    free_poly(&q);
    free_poly(&divisor);

    return C_KZG_OK;
}

// Check a proof for a KZG commitment for an evaluation f(x w^i) = y_i
// The ys must have a power of 2 length
bool check_proof_multi(const KZGSettings *ks, const blst_p1 *commitment, const blst_p1 *proof, const blst_fr *x, const blst_fr *ys, uint64_t n) {
    poly interp;
    blst_fr inv_x, inv_x_pow, x_pow;
    blst_p2 xn2, xn_minus_yn;
    blst_p1 is1, commit_minus_interp;
    //C_KZG_RET ret; // TODO - error handling

    // Interpolate at a coset.
    init_poly(&interp, n);
    fft_fr(interp.coeffs, ys, ks->fs, true, n);
    // if (ret != C_KZG_OK) return ret;

    // Because it is a coset, not the subgroup, we have to multiply the polynomial coefficients by x^-i
    blst_fr_eucl_inverse(&inv_x, x);
    inv_x_pow = inv_x;
    for (uint64_t i = 1; i < n; i++) {
        blst_fr_mul(&interp.coeffs[i], &interp.coeffs[i], &inv_x_pow);
        blst_fr_mul(&inv_x_pow, &inv_x_pow, &inv_x);
    }

    // [x^n]_2
    blst_fr_eucl_inverse(&x_pow, &inv_x_pow);
    p2_mul(&xn2, blst_p2_generator(), &x_pow);

    // [s^n - x^n]_2
    p2_sub(&xn_minus_yn, &ks->secret_g2[n], &xn2);

    // [interpolation_polynomial(s)]_1
    commit_to_poly(&is1, ks, &interp);

	// [commitment - interpolation_polynomial(s)]_1 = [commit]_1 - [interpolation_polynomial(s)]_1
    p1_sub(&commit_minus_interp, commitment, &is1);

    return pairings_verify(&commit_minus_interp, blst_p2_generator(), proof, &xn_minus_yn);
}