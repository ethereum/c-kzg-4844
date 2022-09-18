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
#include "control.h"
#include "c_kzg_alloc.h"
#include "utility.h"

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
 * Make a KZG commitment to a polynomial in Lagrange form.
 *
 * @param[out] out The commitment to the polynomial, in the form of a G1 group point
 * @param[in]  p_l The polynomial to be committed to
 * @param[in]  ks  The settings containing the secrets, previously initialised with #new_kzg_settings
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 */
C_KZG_RET commit_to_poly_l(g1_t *out, const poly_l *p_l, const KZGSettings *ks) {
    CHECK(p_l->length <= ks->length);
    g1_linear_combination(out, ks->secret_g1_l, p_l->values, p_l->length);
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
 * Compute KZG proof for polynomial in Lagrange form at position x0
 *
 * @param[out] out The combined proof as a single G1 element
 * @param[in]  p   The polynomial in Lagrange form
 * @param[in]  x  The generator x-value for the evaluation points
 * @param[in]  y   The value of @p p at @p x
 * @param[in]  ks  The settings containing the secrets, previously initialised with #new_kzg_settings
 * @retval C_KZG_OK      All is well
 * @retval C_KZG_ERROR   An internal error occurred
 * @retval C_KZG_MALLOC  Memory allocation failed
 */
C_KZG_RET compute_proof_single_l(g1_t *out, const poly_l *p, const fr_t *x, const fr_t *y, const KZGSettings *ks) {
  fr_t tmp, tmp2;
  poly_l q;
  uint64_t i, m = 0;

  new_poly_l(&q, p->length);

  fr_t *inverses_in, *inverses;

  TRY(new_fr_array(&inverses_in, p->length));
  TRY(new_fr_array(&inverses, p->length));

  for (i = 0; i < q.length; i++) {
    if (fr_equal(x, &ks->fs->expanded_roots_of_unity[i])) {
      m = i + 1;
      continue;
    }
    // (p_i - y) / (ω_i - x)
    fr_sub(&q.values[i], &p->values[i], y);
    fr_sub(&inverses_in[i], &ks->fs->expanded_roots_of_unity[i], x);
  }

  TRY(fr_batch_inv(inverses, inverses_in, q.length));

  for (i = 0; i < q.length; i++) {
    fr_mul(&q.values[i], &q.values[i], &inverses[i]);
  }  
  if (m) { // ω_m == x
    q.values[--m] = fr_zero;
    for (i=0; i < q.length; i++) {
      if (i == m) continue;
      // (p_i - y) * ω_i / (x * (x - ω_i))
      fr_sub(&tmp, x, &ks->fs->expanded_roots_of_unity[i]);
      fr_mul(&inverses_in[i], &tmp, x);
    }
    TRY(fr_batch_inv(inverses, inverses_in, q.length));
    for (i=0; i < q.length; i++) {
      fr_sub(&tmp2, &p->values[i], y);
      fr_mul(&tmp, &tmp2, &inverses[i]);
      fr_mul(&tmp, &tmp, &ks->fs->expanded_roots_of_unity[i]);
      fr_add(&q.values[m], &q.values[m], &tmp);
    }
  }
  free(inverses_in);
  free(inverses);
  return commit_to_poly_l(out, &q, ks);
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
 * @retval C_KZG_OK      All is well
 * @retval C_KZG_BADARGS Invalid parameters were supplied
 * @retval C_KZG_ERROR   An internal error occurred
 * @retval C_KZG_MALLOC  Memory allocation failed
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
    TRY(new_g1_array(&ks->secret_g1_l, ks->length));
    TRY(new_g2_array(&ks->secret_g2, ks->length));

    // Populate the secrets
    for (uint64_t i = 0; i < ks->length; i++) {
        ks->secret_g1[i] = secret_g1[i];
        ks->secret_g2[i] = secret_g2[i];
    }
    ks->fs = fs;

    // Add Lagrange form (and return its success)
    return fft_g1(ks->secret_g1_l, ks->secret_g1, true, length, fs);
}

/**
 * Free the memory that was previously allocated by #new_kzg_settings.
 *
 * @param ks The settings to be freed
 */
void free_kzg_settings(KZGSettings *ks) {
    free(ks->secret_g1);
    free(ks->secret_g1_l);
    free(ks->secret_g2);
    ks->length = 0;
}

#ifdef KZGTEST

#include "../inc/acutest.h"
#include "test_util.h"

void proof_single(void) {
    // Our polynomial: degree 15, 16 coefficients
    uint64_t coeffs[] = {1, 2, 3, 4, 7, 7, 7, 7, 13, 13, 13, 13, 13, 13, 13, 13};
    int poly_len = sizeof coeffs / sizeof coeffs[0];
    uint64_t secrets_len = poly_len;

    FFTSettings fs;
    KZGSettings ks;
    g1_t s1[secrets_len];
    g2_t s2[secrets_len];
    poly p;
    g1_t commitment, proof;
    fr_t x, value;
    bool result;

    // Create the polynomial
    new_poly(&p, poly_len);
    for (int i = 0; i < poly_len; i++) {
        fr_from_uint64(&p.coeffs[i], coeffs[i]);
    }

    // Initialise the secrets and data structures
    generate_trusted_setup(s1, s2, &secret, secrets_len);
    TEST_CHECK(C_KZG_OK == new_fft_settings(&fs, 4)); // ln_2 of poly_len
    TEST_CHECK(C_KZG_OK == new_kzg_settings(&ks, s1, s2, secrets_len, &fs));

    // Compute the proof for x = 25
    fr_from_uint64(&x, 25);
    TEST_CHECK(C_KZG_OK == commit_to_poly(&commitment, &p, &ks));
    TEST_CHECK(C_KZG_OK == compute_proof_single(&proof, &p, &x, &ks));

    eval_poly(&value, &p, &x);

    // Verify the proof that the (unknown) polynomial has y = value at x = 25
    TEST_CHECK(C_KZG_OK == check_proof_single(&result, &commitment, &proof, &x, &value, &ks));
    TEST_CHECK(true == result);

    // Change the value and check that the proof fails
    fr_add(&value, &value, &fr_one);
    TEST_CHECK(C_KZG_OK == check_proof_single(&result, &commitment, &proof, &x, &value, &ks));
    TEST_CHECK(false == result);

    free_fft_settings(&fs);
    free_kzg_settings(&ks);
    free_poly(&p);
}

void proof_single_l(void) {
    // Our polynomial: degree 15, 16 coefficients
    uint64_t coeffs[] = {1, 2, 3, 4, 7, 7, 7, 7, 13, 13, 13, 13, 13, 13, 13, 13};
    int poly_len = sizeof coeffs / sizeof coeffs[0];
    uint64_t secrets_len = poly_len;

    FFTSettings fs;
    KZGSettings ks;
    g1_t s1[secrets_len];
    g2_t s2[secrets_len];
    poly p;
    poly_l p_l;
    g1_t commitment, proof;
    fr_t x, value;
    bool result;

    // Create the polynomial
    new_poly(&p, poly_len);
    for (int i = 0; i < poly_len; i++) {
        fr_from_uint64(&p.coeffs[i], coeffs[i]);
    }

    // Initialise the secrets and data structures
    generate_trusted_setup(s1, s2, &secret, secrets_len);
    TEST_CHECK(C_KZG_OK == new_fft_settings(&fs, 4)); // ln_2 of poly_len
    TEST_CHECK(C_KZG_OK == new_kzg_settings(&ks, s1, s2, secrets_len, &fs));

    // Create Lagrange form
    new_poly_l_from_poly(&p_l, &p, &ks);

    // Compute the proof for x = 25
    fr_from_uint64(&x, 25);
    TEST_CHECK(C_KZG_OK == commit_to_poly_l(&commitment, &p_l, &ks));
    eval_poly_l(&value, &p_l, &x, &fs);
    TEST_CHECK(C_KZG_OK == compute_proof_single_l(&proof, &p_l, &x, &value, &ks));

    // Verify the proof that the (unknown) polynomial has y = value at x = 25
    TEST_CHECK(C_KZG_OK == check_proof_single(&result, &commitment, &proof, &x, &value, &ks));
    TEST_CHECK(true == result);

    // Change the value and check that the proof fails
    fr_add(&value, &value, &fr_one);
    TEST_CHECK(C_KZG_OK == check_proof_single(&result, &commitment, &proof, &x, &value, &ks));
    TEST_CHECK(false == result);

    free_fft_settings(&fs);
    free_kzg_settings(&ks);
    free_poly(&p);
    free_poly_l(&p_l);
}

void proof_single_l_at_root(void) {
    // Our polynomial: degree 15, 16 coefficients
    uint64_t coeffs[] = {3, 2, 13, 4, 7, 7, 9, 7, 9913, 13, 8813, 13, 7713, 13, 5513, 14};
    int poly_len = sizeof coeffs / sizeof coeffs[0];
    uint64_t secrets_len = poly_len;

    FFTSettings fs;
    KZGSettings ks;
    g1_t s1[secrets_len];
    g2_t s2[secrets_len];
    poly p;
    poly_l p_l;
    g1_t commitment, proof;
    fr_t value;
    fr_t *x;
    bool result;

    // Create the polynomial
    new_poly(&p, poly_len);
    for (int i = 0; i < poly_len; i++) {
        fr_from_uint64(&p.coeffs[i], coeffs[i]);
    }

    // Initialise the secrets and data structures
    generate_trusted_setup(s1, s2, &secret, secrets_len);
    TEST_CHECK(C_KZG_OK == new_fft_settings(&fs, 4)); // ln_2 of poly_len
    TEST_CHECK(C_KZG_OK == new_kzg_settings(&ks, s1, s2, secrets_len, &fs));

    // Create Lagrange form
    new_poly_l_from_poly(&p_l, &p, &ks);

    // Compute the proof for x = the 5th root of unity
    x = &fs.expanded_roots_of_unity[6];
    TEST_CHECK(C_KZG_OK == commit_to_poly_l(&commitment, &p_l, &ks));
    eval_poly_l(&value, &p_l, x, &fs);
    TEST_CHECK(C_KZG_OK == compute_proof_single_l(&proof, &p_l, x, &value, &ks));

    // Verify the proof that the (unknown) polynomial has y = value at x = ω_5
    TEST_CHECK(C_KZG_OK == check_proof_single(&result, &commitment, &proof, x, &value, &ks));
    TEST_CHECK(true == result);

    // Change the value and check that the proof fails
    fr_add(&value, &value, &fr_one);
    TEST_CHECK(C_KZG_OK == check_proof_single(&result, &commitment, &proof, x, &value, &ks));
    TEST_CHECK(false == result);

    free_fft_settings(&fs);
    free_kzg_settings(&ks);
    free_poly(&p);
    free_poly_l(&p_l);
}

void proof_multi(void) {
    // Our polynomial: degree 15, 16 coefficients
    uint64_t coeffs[] = {1, 2, 3, 4, 7, 7, 7, 7, 13, 13, 13, 13, 13, 13, 13, 13};
    int poly_len = sizeof coeffs / sizeof coeffs[0];

    FFTSettings fs;
    KZGSettings ks;
    poly p;
    g1_t commitment, proof;
    fr_t x, tmp;
    bool result;

    // Compute proof at 2^coset_scale points
    int coset_scale = 3, coset_len = (1 << coset_scale);
    fr_t y[coset_len];

    uint64_t secrets_len = poly_len > coset_len ? poly_len : coset_len;
    g1_t s1[secrets_len];
    g2_t s2[secrets_len];

    // Create the polynomial
    new_poly(&p, poly_len);
    for (int i = 0; i < poly_len; i++) {
        fr_from_uint64(&p.coeffs[i], coeffs[i]);
    }

    // Initialise the secrets and data structures
    generate_trusted_setup(s1, s2, &secret, secrets_len);
    TEST_CHECK(C_KZG_OK == new_fft_settings(&fs, 4)); // ln_2 of poly_len
    TEST_CHECK(C_KZG_OK == new_kzg_settings(&ks, s1, s2, secrets_len, &fs));

    // Commit to the polynomial
    TEST_CHECK(C_KZG_OK == commit_to_poly(&commitment, &p, &ks));

    // Compute proof at the points [x * root_i] 0 <= i < coset_len
    fr_from_uint64(&x, 5431);
    TEST_CHECK(C_KZG_OK == compute_proof_multi(&proof, &p, &x, coset_len, &ks));

    // y_i is the value of the polynomial at each x_i
    uint64_t stride = secrets_len / coset_len;
    for (int i = 0; i < coset_len; i++) {
        fr_mul(&tmp, &x, &fs.expanded_roots_of_unity[i * stride]);
        eval_poly(&y[i], &p, &tmp);
    }

    // Verify the proof that the (unknown) polynomial has value y_i at x_i
    TEST_CHECK(C_KZG_OK == check_proof_multi(&result, &commitment, &proof, &x, y, coset_len, &ks));
    TEST_CHECK(true == result);

    // Change a value and check that the proof fails
    fr_add(y + coset_len / 2, y + coset_len / 2, &fr_one);
    TEST_CHECK(C_KZG_OK == check_proof_multi(&result, &commitment, &proof, &x, y, coset_len, &ks));
    TEST_CHECK(false == result);

    free_fft_settings(&fs);
    free_kzg_settings(&ks);
    free_poly(&p);
}

void commit_to_nil_poly(void) {
    poly a;
    FFTSettings fs;
    KZGSettings ks;
    uint64_t secrets_len = 16;
    g1_t s1[secrets_len];
    g2_t s2[secrets_len];
    g1_t result;

    // Initialise the (arbitrary) secrets and data structures
    generate_trusted_setup(s1, s2, &secret, secrets_len);
    TEST_CHECK(C_KZG_OK == new_fft_settings(&fs, 4));
    TEST_CHECK(C_KZG_OK == new_kzg_settings(&ks, s1, s2, secrets_len, &fs));

    new_poly(&a, 0);
    TEST_CHECK(C_KZG_OK == commit_to_poly(&result, &a, &ks));
    TEST_CHECK(g1_equal(&g1_identity, &result));

    free_fft_settings(&fs);
    free_kzg_settings(&ks);
}

void commit_to_too_long_poly(void) {
    poly a;
    FFTSettings fs;
    KZGSettings ks;
    uint64_t poly_len = 32, secrets_len = 16; // poly is longer than secrets!
    g1_t s1[secrets_len];
    g2_t s2[secrets_len];
    g1_t result;

    // Initialise the (arbitrary) secrets and data structures
    generate_trusted_setup(s1, s2, &secret, secrets_len);
    TEST_CHECK(C_KZG_OK == new_fft_settings(&fs, 4));
    TEST_CHECK(C_KZG_OK == new_kzg_settings(&ks, s1, s2, secrets_len, &fs));

    new_poly(&a, poly_len);
    TEST_CHECK(C_KZG_BADARGS == commit_to_poly(&result, &a, &ks));

    free_fft_settings(&fs);
    free_kzg_settings(&ks);
}

void commit_to_poly_lagrange(void) {
    // Our polynomial: degree 15, 16 coefficients
    uint64_t coeffs[] = {12, 2, 8, 4, 7, 9, 1337, 227, 3, 13, 13, 130, 13, 13111, 13, 12223};
    int poly_len = sizeof coeffs / sizeof coeffs[0];
    uint64_t secrets_len = poly_len;

    FFTSettings fs;
    KZGSettings ks;
    g1_t s1[secrets_len];
    g2_t s2[secrets_len];
    poly p;
    poly_l p_l;
    g1_t commitment, commitment_l;

    // Create the polynomial
    new_poly(&p, poly_len);
    for (int i = 0; i < poly_len; i++) {
        fr_from_uint64(&p.coeffs[i], coeffs[i]);
    }

    // Initialise the secrets and data structures
    generate_trusted_setup(s1, s2, &secret, secrets_len);
    TEST_CHECK(C_KZG_OK == new_fft_settings(&fs, 4)); // ln_2 of poly_len
    TEST_CHECK(C_KZG_OK == new_kzg_settings(&ks, s1, s2, secrets_len, &fs));

    // Create Lagrange form
    new_poly_l_from_poly(&p_l, &p, &ks);

    // Compute commitments
    TEST_CHECK(C_KZG_OK == commit_to_poly(&commitment, &p, &ks));
    TEST_CHECK(C_KZG_OK == commit_to_poly_l(&commitment_l, &p_l, &ks));

    // Check commitments are equal
    TEST_CHECK(g1_equal(&commitment, &commitment_l));

    free_fft_settings(&fs);
    free_kzg_settings(&ks);
    free_poly(&p);
    free_poly_l(&p_l);
}

void poly_eval_l_check(void) {
    uint64_t n = 10;
    fr_t actual, expected;
    poly p;
    new_poly(&p, n);
    for (uint64_t i = 0; i < n; i++) {
        fr_from_uint64(&p.coeffs[i], i + 1);
    }
    fr_t x;
    fr_from_uint64(&x, 39);
    // x = fr_one;
    eval_poly(&expected, &p, &x);

    poly_l p_l;
    FFTSettings fs;
    KZGSettings ks;
    uint64_t secrets_len = 16;
    g1_t s1[secrets_len];
    g2_t s2[secrets_len];

    generate_trusted_setup(s1, s2, &secret, secrets_len);
    TEST_CHECK(C_KZG_OK == new_fft_settings(&fs, 4)); // log_2(secrets_len)
    TEST_CHECK(C_KZG_OK == new_kzg_settings(&ks, s1, s2, secrets_len, &fs));

    TEST_CHECK(C_KZG_OK == new_poly_l_from_poly(&p_l, &p, &ks));

    eval_poly_l(&actual, &p_l, &x, &fs);

    TEST_CHECK(fr_equal(&expected, &actual));

    free_fft_settings(&fs);
    free_kzg_settings(&ks);
    free_poly(&p);
    free_poly_l(&p_l);
}

void eval_poly_l_at_first_root_of_unity(void) {
    uint64_t n = 10;
    fr_t actual, expected;
    poly p;
    new_poly(&p, n);
    for (uint64_t i = 0; i < n; i++) {
        fr_from_uint64(&p.coeffs[i], i + 2);
    }

    poly_l p_l;
    FFTSettings fs;
    KZGSettings ks;
    uint64_t secrets_len = 16;
    g1_t s1[secrets_len];
    g2_t s2[secrets_len];

    generate_trusted_setup(s1, s2, &secret, secrets_len);
    TEST_CHECK(C_KZG_OK == new_fft_settings(&fs, 4)); // log_2(secrets_len)
    TEST_CHECK(C_KZG_OK == new_kzg_settings(&ks, s1, s2, secrets_len, &fs));

    eval_poly(&expected, &p, &fs.expanded_roots_of_unity[0]);

    TEST_CHECK(C_KZG_OK == new_poly_l_from_poly(&p_l, &p, &ks));

    eval_poly_l(&actual, &p_l, &fs.expanded_roots_of_unity[0], &fs);

    TEST_CHECK(fr_equal(&expected, &actual));

    free_fft_settings(&fs);
    free_kzg_settings(&ks);
    free_poly(&p);
    free_poly_l(&p_l);
}

void eval_poly_l_at_another_root_of_unity(void) {
    uint64_t n = 13;
    fr_t actual, expected;
    poly p;
    new_poly(&p, n);
    for (uint64_t i = 0; i < n; i++) {
        fr_from_uint64(&p.coeffs[i], 2 * n - i);
    }

    poly_l p_l;
    FFTSettings fs;
    KZGSettings ks;
    uint64_t secrets_len = 16;
    g1_t s1[secrets_len];
    g2_t s2[secrets_len];

    generate_trusted_setup(s1, s2, &secret, secrets_len);
    TEST_CHECK(C_KZG_OK == new_fft_settings(&fs, 4)); // log_2(secrets_len)
    TEST_CHECK(C_KZG_OK == new_kzg_settings(&ks, s1, s2, secrets_len, &fs));

    eval_poly(&expected, &p, &fs.expanded_roots_of_unity[5]);

    TEST_CHECK(C_KZG_OK == new_poly_l_from_poly(&p_l, &p, &ks));

    eval_poly_l(&actual, &p_l, &fs.expanded_roots_of_unity[5], &fs);

    TEST_CHECK(fr_equal(&expected, &actual));

    free_fft_settings(&fs);
    free_kzg_settings(&ks);
    free_poly(&p);
    free_poly_l(&p_l);
}


TEST_LIST = {
    {"KZG_PROOFS_TEST", title},
    {"poly_eval_l_check", poly_eval_l_check},
    {"eval_poly_l_at_first_root_of_unity", eval_poly_l_at_first_root_of_unity},
    {"eval_poly_l_at_another_root_of_unity", eval_poly_l_at_another_root_of_unity},
    {"proof_single", proof_single},
    {"proof_single_l", proof_single_l},
    {"proof_single_l_at_root", proof_single_l_at_root},
    {"proof_multi", proof_multi},
    {"commit_to_nil_poly", commit_to_nil_poly},
    {"commit_to_too_long_poly", commit_to_too_long_poly},
    {"commit_to_poly_lagrange", commit_to_poly_lagrange},
    {NULL, NULL} /* zero record marks the end of the list */
};

#endif // KZGTEST
