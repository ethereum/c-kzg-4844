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
 *  @file kzg_proofs.c
 *
 * Implements KZG proofs for making, opening, and verifying polynomial commitments.
 *
 * See the paper [Constant-Size Commitments to Polynomials andTheir
 * Applications](https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf) for the theoretical background.
 */

#include <stddef.h> // NULL
#include "kzg_proofs.h"
#include "c_kzg_util.h"
#include "utility.h"
#include <assert.h>

/**
 * Make a KZG commitment to a polynomial.
 *
 * @param[out] out The commitment to the polynomial, in the form of a G1 group point
 * @param[in]  p   The polynomial to be committed to
 * @param[in]  ks  The settings containing the secrets, previously initialised with #new_kzg_settings
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 */
C_KZG_RET commit_to_poly(g1_t *out, const poly *p, const KZGSettings *ks) {
    CHECK(p->length <= ks->length);
    g1_linear_combination(out, ks->secret_g1, p->coeffs, p->length);
    return C_KZG_OK;
}

/**
 * Compute KZG proof for polynomial at position x0.
 *
 * @param[out] out The proof, in the form of a G1 point
 * @param[in]  p   The polynomial
 * @param[in]  x0  The x-value the polynomial is to be proved at
 * @param[in]  ks  The settings containing the secrets, previously initialised with #new_kzg_settings
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_ERROR   An internal error occurred
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET compute_proof_single(g1_t *out, const poly *p, const fr_t *x0, const KZGSettings *ks) {
    return compute_proof_multi(out, p, x0, 1, ks);
}

/**
 * Check a KZG proof at a point against a commitment.
 *
 * Given a @p commitment to a polynomial, a @p proof for @p x, and the claimed value @p y at @p x, verify the claim.
 *
 * @param[out] out        `true` if the proof is valid, `false` if not
 * @param[in]  commitment The commitment to a polynomial
 * @param[in]  proof      A proof of the value of the polynomial at the point @p x
 * @param[in]  x          The point at which the proof is to be checked (opened)
 * @param[in]  y          The claimed value of the polynomial at @p x
 * @param[in]  ks  The settings containing the secrets, previously initialised with #new_kzg_settings
 * @retval C_CZK_OK      All is well
 */
C_KZG_RET check_proof_single(bool *out, const g1_t *commitment, const g1_t *proof, const fr_t *x, fr_t *y,
                             const KZGSettings *ks) {
    g2_t x_g2, s_minus_x;
    g1_t y_g1, commitment_minus_y;
    g2_mul(&x_g2, &g2_generator, x);
    g2_sub(&s_minus_x, &ks->secret_g2[1], &x_g2);
    g1_mul(&y_g1, &g1_generator, y);
    g1_sub(&commitment_minus_y, commitment, &y_g1);

    *out = pairings_verify(&commitment_minus_y, &g2_generator, proof, &s_minus_x);

    return C_KZG_OK;
}

/**
 * Compute KZG proof for polynomial at positions x0 * w^y where w is an n-th root of unity.
 *
 * This constitutes the proof for one data availability sample, which consists
 * of several polynomial evaluations.
 *
 * @param[out] out The combined proof as a single G1 element
 * @param[in]  p   The polynomial
 * @param[in]  x0  The generator x-value for the evaluation points
 * @param[in]  n   The number of points at which to evaluate the polynomial, must be a power of two
 * @param[in]  ks  The settings containing the secrets, previously initialised with #new_kzg_settings
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_ERROR   An internal error occurred
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET compute_proof_multi(g1_t *out, const poly *p, const fr_t *x0, uint64_t n, const KZGSettings *ks) {
    poly divisor, q;
    fr_t x_pow_n;

    CHECK(is_power_of_two(n));

    // Construct x^n - x0^n = (x - x0.w^0)(x - x0.w^1)...(x - x0.w^(n-1))
    TRY(new_poly(&divisor, n + 1));

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
    TRY(new_poly_div(&q, p, &divisor));

    TRY(commit_to_poly(out, &q, ks));

    free_poly(&q);
    free_poly(&divisor);

    return C_KZG_OK;
}

/**
 * Check a proof for a KZG commitment for evaluations `f(x * w^i) = y_i`.
 *
 * Given a @p commitment to a polynomial, a @p proof for @p x, and the claimed values @p y at values @p x `* w^i`,
 * verify the claim. Here, `w` is an `n`th root of unity.
 *
 * @param[out] out        `true` if the proof is valid, `false` if not
 * @param[in]  commitment The commitment to a polynomial
 * @param[in]  proof      A proof of the value of the polynomial at the points @p x * w^i
 * @param[in]  x          The generator x-value for the evaluation points
 * @param[in]  ys         The claimed value of the polynomial at the points @p x * w^i
 * @param[in]  n          The number of points at which to evaluate the polynomial, must be a power of two
 * @param[in]  ks         The settings containing the secrets, previously initialised with #new_kzg_settings
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_ERROR   An internal error occurred
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET check_proof_multi(bool *out, const g1_t *commitment, const g1_t *proof, const fr_t *x, const fr_t *ys,
                            uint64_t n, const KZGSettings *ks) {
    poly interp;
    fr_t inv_x, inv_x_pow, x_pow;
    g2_t xn2, xn_minus_yn;
    g1_t is1, commit_minus_interp;

    CHECK(is_power_of_two(n));

    // Interpolate at a coset.
    TRY(new_poly(&interp, n));
    TRY(fft_fr(interp.coeffs, ys, true, n, ks->fs));

    // Because it is a coset, not the subgroup, we have to multiply the polynomial coefficients by x^-i
    fr_inv(&inv_x, x);
    inv_x_pow = inv_x;
    for (uint64_t i = 1; i < n; i++) {
        fr_mul(&interp.coeffs[i], &interp.coeffs[i], &inv_x_pow);
        fr_mul(&inv_x_pow, &inv_x_pow, &inv_x);
    }

    // [x^n]_2
    fr_inv(&x_pow, &inv_x_pow);
    g2_mul(&xn2, &g2_generator, &x_pow);

    // [s^n - x^n]_2
    g2_sub(&xn_minus_yn, &ks->secret_g2[n], &xn2);

    // [interpolation_polynomial(s)]_1
    TRY(commit_to_poly(&is1, &interp, ks));

    // [commitment - interpolation_polynomial(s)]_1 = [commit]_1 - [interpolation_polynomial(s)]_1
    g1_sub(&commit_minus_interp, commitment, &is1);

    *out = pairings_verify(&commit_minus_interp, &g2_generator, proof, &xn_minus_yn);

    free_poly(&interp);
    return C_KZG_OK;
}

/**
 * Initialise a KZGSettings structure.
 *
 * Space is allocated for the provided secrets (the "trusted setup"), and copies of the secrets are made.
 *
 * @remark As with all functions prefixed `new_`, this allocates memory that needs to be reclaimed by calling the
 * corresponding `free_` function. In this case, #free_kzg_settings.
 *
 * @param[out] ks        The new settings
 * @param[in]  secret_g1 The G1 points from the trusted setup (an array of length at least @p length)
 * @param[in]  secret_g2 The G2 points from the trusted setup (an array of length at least @p length)
 * @param[in]  length    The length of the secrets arrays to create, must be at least @p fs->max_width
 * @param[in]  fs        A previously initialised FFTSettings structure
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET new_kzg_settings(KZGSettings *ks, const g1_t *secret_g1, const g2_t *secret_g2, uint64_t length,
                           FFTSettings const *fs) {

    CHECK(length >= fs->max_width);
    ks->length = length;

    // Allocate space for the secrets
    TRY(new_g1_array(&ks->secret_g1, ks->length));
    TRY(new_g2_array(&ks->secret_g2, ks->length));

    // Populate the secrets
    for (uint64_t i = 0; i < ks->length; i++) {
        ks->secret_g1[i] = secret_g1[i];
        ks->secret_g2[i] = secret_g2[i];
    }
    ks->fs = fs;

    return C_KZG_OK;
}

/**
 * Free the memory that was previously allocated by #new_kzg_settings.
 *
 * @param ks The settings to be freed
 */
void free_kzg_settings(KZGSettings *ks) {
    free(ks->secret_g1);
    free(ks->secret_g2);
    ks->length = 0;
}
