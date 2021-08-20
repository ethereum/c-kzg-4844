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
 *  @file fk20_proofs.c
 *
 * Implements amortised KZG proofs as per the [FK20
 * paper](https://github.com/khovratovich/Kate/blob/master/Kate_amortized.pdf).
 *
 * @todo Split this out into smaller files.
 */

#include "control.h"
#include "c_kzg_alloc.h"
#include "utility.h"

/**
 * The first part of the Toeplitz matrix multiplication algorithm: the Fourier
 * transform of the vector @p x extended.
 *
 * @param[out] out The FFT of the extension of @p x, size @p n * 2
 * @param[in]  x   The input vector, size @p n
 * @param[in]  n   The length of the input vector @p x
 * @param[in]  fs  The FFT settings previously initialised with #new_fft_settings
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_ERROR   An internal error occurred
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
static C_KZG_RET toeplitz_part_1(g1_t *out, const g1_t *x, uint64_t n, const FFTSettings *fs) {
    uint64_t n2 = n * 2;
    g1_t *x_ext;

    TRY(new_g1_array(&x_ext, n2));
    for (uint64_t i = 0; i < n; i++) {
        x_ext[i] = x[i];
    }
    for (uint64_t i = n; i < n2; i++) {
        x_ext[i] = g1_identity;
    }

    TRY(fft_g1(out, x_ext, false, n2, fs));

    free(x_ext);
    return C_KZG_OK;
}

/**
 * The second part of the Toeplitz matrix multiplication algorithm.
 *
 * @param[out] out Array of G1 group elements, length `n`
 * @param[in]  toeplitz_coeffs Toeplitz coefficients, a polynomial length `n`
 * @param[in]  x_ext_fft The Fourier transform of the extended `x` vector, length `n`
 * @param[in]  fs  The FFT settings previously initialised with #new_fft_settings
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_ERROR   An internal error occurred
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
static C_KZG_RET toeplitz_part_2(g1_t *out, const poly *toeplitz_coeffs, const g1_t *x_ext_fft, const FFTSettings *fs) {
    fr_t *toeplitz_coeffs_fft;

    // CHECK(toeplitz_coeffs->length == fk->x_ext_fft_len); // TODO: how to implement?

    TRY(new_fr_array(&toeplitz_coeffs_fft, toeplitz_coeffs->length));
    TRY(fft_fr(toeplitz_coeffs_fft, toeplitz_coeffs->coeffs, false, toeplitz_coeffs->length, fs));

    for (uint64_t i = 0; i < toeplitz_coeffs->length; i++) {
        g1_mul(&out[i], &x_ext_fft[i], &toeplitz_coeffs_fft[i]);
    }

    free(toeplitz_coeffs_fft);
    return C_KZG_OK;
}

/**
 * The third part of the Toeplitz matrix multiplication algorithm: transform back and zero the top half.
 *
 * @param[out] out Array of G1 group elements, length @p n2
 * @param[in]  h_ext_fft FFT of the extended `h` values, length @p n2
 * @param[in]  n2  Size of the arrays
 * @param[in]  fs  The FFT settings previously initialised with #new_fft_settings
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_ERROR   An internal error occurred
 */
static C_KZG_RET toeplitz_part_3(g1_t *out, const g1_t *h_ext_fft, uint64_t n2, const FFTSettings *fs) {
    uint64_t n = n2 / 2;

    TRY(fft_g1(out, h_ext_fft, true, n2, fs));

    // Zero the second half of h
    for (uint64_t i = n; i < n2; i++) {
        out[i] = g1_identity;
    }

    return C_KZG_OK;
}

/**
 * Reorder and extend polynomial coefficients for the toeplitz method, strided version.
 *
 * @remark The upper half of the input polynomial coefficients is treated as being zero.
 *
 * @param[out] out The reordered polynomial, size `n * 2 / stride`
 * @param[in]  in  The input polynomial, size `n`
 * @param[in]  offset The offset
 * @param[in]  stride The stride
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
static C_KZG_RET toeplitz_coeffs_stride(poly *out, const poly *in, uint64_t offset, uint64_t stride) {
    uint64_t n = in->length, k, k2;

    CHECK(stride > 0);

    k = n / stride;
    k2 = k * 2;

    CHECK(out->length >= k2);

    out->coeffs[0] = in->coeffs[n - 1 - offset];
    for (uint64_t i = 1; i <= k + 1 && i < k2; i++) {
        out->coeffs[i] = fr_zero;
    }
    for (uint64_t i = k + 2, j = 2 * stride - offset - 1; i < k2; i++, j += stride) {
        out->coeffs[i] = in->coeffs[j];
    }

    return C_KZG_OK;
}

/**
 * Reorder and extend polynomial coefficients for the toeplitz method.
 *
 * @remark The upper half of the input polynomial coefficients is treated as being zero.
 *
 * @param[out] out The reordered polynomial, size `n * 2`
 * @param[in]  in  The input polynomial, size `n`
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
static C_KZG_RET toeplitz_coeffs_step(poly *out, const poly *in) {
    return toeplitz_coeffs_stride(out, in, 0, 1);
}

/**
 * Optimised version of the FK20 algorithm for use in data availability checks.
 *
 * Simultaneously calculates all the KZG proofs for `x_i = w^i` (`0 <= i < 2n`), where `w` is a `(2 * n)`th root of
 * unity. The `2n` comes from the polynomial being extended with zeros to twice the original size.
 *
 * `out[i]` is the proof for `y[i]`, the evaluation of the polynomial at `fs.expanded_roots_of_unity[i]`.
 *
 * @remark Only the lower half of the polynomial is supplied; the upper, zero, half is assumed. The
 * #toeplitz_coeffs_step routine does the right thing.
 *
 * @param[out] out Array size `n * 2`
 * @param[in]  p   Polynomial, size `n`
 * @param[in]  fk  FK20 single settings previously initialised by #new_fk20_single_settings
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_ERROR   An internal error occurred
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
static C_KZG_RET fk20_single_da_opt(g1_t *out, const poly *p, const FK20SingleSettings *fk) {
    uint64_t n = p->length, n2 = n * 2;
    g1_t *h, *h_ext_fft;
    poly toeplitz_coeffs;

    CHECK(n2 <= fk->ks->fs->max_width);
    CHECK(is_power_of_two(n));

    TRY(new_poly(&toeplitz_coeffs, 2 * p->length));
    TRY(toeplitz_coeffs_step(&toeplitz_coeffs, p));

    TRY(new_g1_array(&h_ext_fft, toeplitz_coeffs.length));
    TRY(toeplitz_part_2(h_ext_fft, &toeplitz_coeffs, fk->x_ext_fft, fk->ks->fs));

    TRY(new_g1_array(&h, n2));
    TRY(toeplitz_part_3(h, h_ext_fft, n2, fk->ks->fs));

    TRY(fft_g1(out, h, false, n2, fk->ks->fs));

    free_poly(&toeplitz_coeffs);
    free(h_ext_fft);
    free(h);
    return C_KZG_OK;
}

/**
 * Data availability using the FK20 single algorithm.
 *
 * Simultaneously calculates all the KZG proofs for `x_i = w^i` (`0 <= i < 2n`), where `w` is a `(2 * n)`th root of
 * unity. The `2n` comes from the polynomial being extended with zeros to twice the original size.
 *
 * `out[reverse_bits_limited(2 * n, i)]` is the proof for `y[i]`, the evaluation of the polynomial at
 * `fs.expanded_roots_of_unity[i]`.
 *
 * @param[out] out All the proofs, array length 2 * `n`
 * @param[in]  p   Polynomial, size `n`
 * @param[in]  fk  FK20 single settings previously initialised by #new_fk20_single_settings
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_ERROR   An internal error occurred
 */
C_KZG_RET da_using_fk20_single(g1_t *out, const poly *p, const FK20SingleSettings *fk) {
    uint64_t n = p->length, n2 = n * 2;

    CHECK(n2 <= fk->ks->fs->max_width);
    CHECK(is_power_of_two(n));

    TRY(fk20_single_da_opt(out, p, fk));
    TRY(reverse_bit_order(out, sizeof out[0], n2));

    return C_KZG_OK;
}

/**
 * FK20 Method to compute all proofs - multi proof method
 *
 * Toeplitz multiplication as per http://www.netlib.org/utk/people/JackDongarra/etemplates/node384.html
 *
 * For a polynomial of size `n`, let `w` be a `n`th root of unity. Then this method will return
 * `k = n / l` KZG proofs for the points:
 *
 * ```
 * proof[0]: w^(0*l + 0), w^(0*l + 1), ... w^(0*l + l - 1)
 * proof[1]: w^(1*l + 0), w^(1*l + 1), ... w^(1*l + l - 1)
 * ...
 * proof[i]: w^(i*l + 0), w^(i*l + 1), ... w^(i*l + l - 1)
 * ```
 *
 * @param[out] out The proofs, array size @p p->length * 2
 * @param[in]  p   The polynomial
 * @param[in]  fk  FK20 multi settings previously initialised by #new_fk20_multi_settings
 */
C_KZG_RET fk20_compute_proof_multi(g1_t *out, const poly *p, const FK20MultiSettings *fk) {
    uint64_t n = p->length, n2 = n * 2;
    g1_t *h_ext_fft, *h_ext_fft_file, *h;
    poly toeplitz_coeffs;

    CHECK(fk->ks->fs->max_width >= n2);

    TRY(new_g1_array(&h_ext_fft, n2));
    for (uint64_t i = 0; i < n2; i++) {
        h_ext_fft[i] = g1_identity;
    }

    TRY(new_poly(&toeplitz_coeffs, 2 * p->length));
    TRY(new_g1_array(&h_ext_fft_file, toeplitz_coeffs.length));
    for (uint64_t i = 0; i < fk->chunk_len; i++) {
        TRY(toeplitz_coeffs_step(&toeplitz_coeffs, p));
        TRY(toeplitz_part_2(h_ext_fft_file, &toeplitz_coeffs, fk->x_ext_fft_files[i], fk->ks->fs));
        for (uint64_t j = 0; j < n2; j++) {
            g1_add_or_dbl(&h_ext_fft[j], &h_ext_fft[j], &h_ext_fft_file[j]);
        }
    }
    free_poly(&toeplitz_coeffs);
    free(h_ext_fft_file);

    TRY(new_g1_array(&h, n2));
    TRY(toeplitz_part_3(h, h_ext_fft, n2, fk->ks->fs));

    TRY(fft_g1(out, h, false, n2, fk->ks->fs));

    free(h_ext_fft);
    free(h);
    return C_KZG_OK;
}

/**
 * FK20 multi-proof method, optimized for data availability where the top half of polynomial
 * coefficients is zero.
 *
 * @remark Only the lower half of the polynomial is supplied; the upper, zero, half is assumed. The
 * #toeplitz_coeffs_stride routine does the right thing.
 *
 * @param[out] out The proofs, array size `2 * n / fk->chunk_length`
 * @param[in]  p   The polynomial, length `n`
 * @param[in]  fk  FK20 multi settings previously initialised by #new_fk20_multi_settings
 */
static C_KZG_RET fk20_multi_da_opt(g1_t *out, const poly *p, const FK20MultiSettings *fk) {
    uint64_t n = p->length, n2 = n * 2, k, k2;
    g1_t *h_ext_fft, *h_ext_fft_file, *h;
    poly toeplitz_coeffs;

    CHECK(n2 <= fk->ks->fs->max_width);
    CHECK(is_power_of_two(n));

    n = n2 / 2;
    k = n / fk->chunk_len;
    k2 = k * 2;

    TRY(new_g1_array(&h_ext_fft, k2));
    for (uint64_t i = 0; i < k2; i++) {
        h_ext_fft[i] = g1_identity;
    }

    TRY(new_poly(&toeplitz_coeffs, n2 / fk->chunk_len));
    TRY(new_g1_array(&h_ext_fft_file, toeplitz_coeffs.length));
    for (uint64_t i = 0; i < fk->chunk_len; i++) {
        TRY(toeplitz_coeffs_stride(&toeplitz_coeffs, p, i, fk->chunk_len));
        TRY(toeplitz_part_2(h_ext_fft_file, &toeplitz_coeffs, fk->x_ext_fft_files[i], fk->ks->fs));
        for (uint64_t j = 0; j < k2; j++) {
            g1_add_or_dbl(&h_ext_fft[j], &h_ext_fft[j], &h_ext_fft_file[j]);
        }
    }
    free_poly(&toeplitz_coeffs);
    free(h_ext_fft_file);

    // Calculate `h`
    TRY(new_g1_array(&h, k2));
    TRY(toeplitz_part_3(h, h_ext_fft, k2, fk->ks->fs));

    // Overwrite the second half of `h` with zero
    for (uint64_t i = k; i < k2; i++) {
        h[i] = g1_identity;
    }

    TRY(fft_g1(out, h, false, k2, fk->ks->fs));

    free(h_ext_fft);
    free(h);

    return C_KZG_OK;
}

/**
 * Computes all the KZG proofs for data availability checks.
 *
 * This involves sampling on the double domain and reordering according to reverse bit order.
 *
 */
C_KZG_RET da_using_fk20_multi(g1_t *out, const poly *p, const FK20MultiSettings *fk) {
    uint64_t n = p->length, n2 = n * 2;

    CHECK(n2 <= fk->ks->fs->max_width);
    CHECK(is_power_of_two(n));

    TRY(fk20_multi_da_opt(out, p, fk));
    TRY(reverse_bit_order(out, sizeof out[0], n2 / fk->chunk_len));

    return C_KZG_OK;
}

/**
 * Initialise settings for an FK20 single proof.
 *
 * @remark As with all functions prefixed `new_`, this allocates memory that needs to be reclaimed by calling
 * the corresponding `free_` function. In this case, #free_fk20_single_settings.
 *
 * @param[out] fk The initialised settings
 * @param[in]  n2 The desired size of `x_ext_fft`, a power of two
 * @param[in]  ks KZGSettings that have already been initialised
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_ERROR   An internal error occurred
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET new_fk20_single_settings(FK20SingleSettings *fk, uint64_t n2, const KZGSettings *ks) {
    int n = n2 / 2;
    g1_t *x;

    CHECK(n2 <= ks->fs->max_width);
    CHECK(is_power_of_two(n2));
    CHECK(n2 >= 2);

    fk->ks = ks;
    fk->x_ext_fft_len = n2;

    TRY(new_g1_array(&x, n));
    for (uint64_t i = 0; i < n - 1; i++) {
        x[i] = ks->secret_g1[n - 2 - i];
    }
    x[n - 1] = g1_identity;

    TRY(new_g1_array(&fk->x_ext_fft, 2 * n));
    TRY(toeplitz_part_1(fk->x_ext_fft, x, n, ks->fs));

    free(x);
    return C_KZG_OK;
}

/**
 * Initialise settings for an FK20 multi proof.
 *
 * @remark As with all functions prefixed `new_`, this allocates memory that needs to be reclaimed by calling the
 * corresponding `free_` function. In this case, #free_fk20_multi_settings.
 *
 * @param[out] fk The initialised settings
 * @param[in]  n2 The desired size of `x_ext_fft`, a power of two
 * @param[in]  chunk_len TODO
 * @param[in]  ks KZGSettings that have already been initialised
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_ERROR   An internal error occurred
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET new_fk20_multi_settings(FK20MultiSettings *fk, uint64_t n2, uint64_t chunk_len, const KZGSettings *ks) {
    uint64_t n, k;
    g1_t *x;

    CHECK(n2 <= ks->fs->max_width);
    CHECK(is_power_of_two(n2));
    CHECK(n2 >= 2);
    CHECK(chunk_len <= n2 / 2);
    CHECK(is_power_of_two(chunk_len));
    CHECK(chunk_len > 0);

    n = n2 / 2;
    k = n / chunk_len;

    fk->ks = ks;
    fk->chunk_len = chunk_len;

    // `x_ext_fft_files` is two dimensional. Allocate space for pointers to the rows.
    TRY(new_g1_array_2(&fk->x_ext_fft_files, chunk_len * sizeof *fk->x_ext_fft_files));

    TRY(new_g1_array(&x, k));
    for (uint64_t offset = 0; offset < chunk_len; offset++) {
        uint64_t start = n - chunk_len - 1 - offset;
        for (uint64_t i = 0, j = start; i + 1 < k; i++, j -= chunk_len) {
            x[i] = ks->secret_g1[j];
        }
        x[k - 1] = g1_identity;

        TRY(new_g1_array(&fk->x_ext_fft_files[offset], 2 * k));
        TRY(toeplitz_part_1(fk->x_ext_fft_files[offset], x, k, ks->fs));
    }

    free(x);
    return C_KZG_OK;
}

/**
 * Free the memory that was previously allocated by #new_fk20_single_settings.
 *
 * @param fk The settings to be freed
 */
void free_fk20_single_settings(FK20SingleSettings *fk) {
    free(fk->x_ext_fft);
    fk->x_ext_fft_len = 0;
}

/**
 * Free the memory that was previously allocated by #new_fk20_multi_settings.
 *
 * @param fk The settings to be freed
 */
void free_fk20_multi_settings(FK20MultiSettings *fk) {
    for (uint64_t i = 0; i < fk->chunk_len; i++) {
        free((fk->x_ext_fft_files)[i]);
    }
    free(fk->x_ext_fft_files);
    fk->chunk_len = 0;
    fk->length = 0;
}

#ifdef KZGTEST

#include "../inc/acutest.h"
#include "test_util.h"

void fk_single(void) {
    // Our polynomial: degree 15, 16 coefficients
    uint64_t coeffs[] = {1, 2, 3, 4, 7, 7, 7, 7, 13, 13, 13, 13, 13, 13, 13, 13};
    int poly_len = sizeof coeffs / sizeof coeffs[0];

    // The FFT settings size
    uint64_t n = 5, n_len = (uint64_t)1 << n;

    FFTSettings fs;
    KZGSettings ks;
    FK20SingleSettings fk;
    uint64_t secrets_len = n_len + 1;
    g1_t s1[secrets_len];
    g2_t s2[secrets_len];
    poly p;
    g1_t commitment, all_proofs[2 * poly_len], proof;
    fr_t x, y;
    bool result;

    TEST_CHECK(n_len >= 2 * poly_len);
    TEST_CHECK(new_poly(&p, poly_len) == C_KZG_OK);
    for (uint64_t i = 0; i < poly_len; i++) {
        fr_from_uint64(&p.coeffs[i], coeffs[i]);
    }

    // Initialise the secrets and data structures
    generate_trusted_setup(s1, s2, &secret, secrets_len);
    TEST_CHECK(C_KZG_OK == new_fft_settings(&fs, n));
    TEST_CHECK(C_KZG_OK == new_kzg_settings(&ks, s1, s2, secrets_len, &fs));
    TEST_CHECK(C_KZG_OK == new_fk20_single_settings(&fk, 2 * poly_len, &ks));

    // Commit to the polynomial
    TEST_CHECK(C_KZG_OK == commit_to_poly(&commitment, &p, &ks));

    // 1. First with `da_using_fk20_single`

    // Generate the proofs
    TEST_CHECK(da_using_fk20_single(all_proofs, &p, &fk) == C_KZG_OK);

    // Verify the proof at each root of unity
    for (uint64_t i = 0; i < 2 * poly_len; i++) {
        x = fs.expanded_roots_of_unity[i];
        eval_poly(&y, &p, &x);
        proof = all_proofs[reverse_bits_limited(2 * poly_len, i)];

        TEST_CHECK(C_KZG_OK == check_proof_single(&result, &commitment, &proof, &x, &y, &ks));
        TEST_CHECK(true == result);
    }

    // 2. Exactly the same thing again with `fk20_single_da_opt`

    // Generate the proofs
    TEST_CHECK(fk20_single_da_opt(all_proofs, &p, &fk) == C_KZG_OK);

    // Verify the proof at each root of unity
    for (uint64_t i = 0; i < 2 * poly_len; i++) {
        x = fs.expanded_roots_of_unity[i];
        eval_poly(&y, &p, &x);
        proof = all_proofs[i];

        TEST_CHECK(C_KZG_OK == check_proof_single(&result, &commitment, &proof, &x, &y, &ks));
        TEST_CHECK(true == result);
    }

    // Clean up
    free_poly(&p);
    free_fft_settings(&fs);
    free_kzg_settings(&ks);
    free_fk20_single_settings(&fk);
}

void fk_single_strided(void) {
    // Our polynomial: degree 15, 16 coefficients
    uint64_t coeffs[] = {1, 2, 3, 4, 7, 7, 7, 7, 13, 13, 13, 13, 13, 13, 13, 13};
    int poly_len = sizeof coeffs / sizeof coeffs[0];

    // We can set up the FFTs for bigger widths if we wish.
    // This is a useful canary for issues elsewhere in the code.
    uint64_t n = 8, n_len = (uint64_t)1 << n;
    uint64_t stride = n_len / (2 * poly_len);

    FFTSettings fs;
    KZGSettings ks;
    FK20SingleSettings fk;
    uint64_t secrets_len = n_len + 1;
    g1_t s1[secrets_len];
    g2_t s2[secrets_len];
    poly p;
    g1_t commitment, all_proofs[2 * poly_len], proof;
    fr_t x, y;
    bool result;

    TEST_CHECK(n_len >= 2 * poly_len);
    TEST_CHECK(new_poly(&p, poly_len) == C_KZG_OK);
    for (uint64_t i = 0; i < poly_len; i++) {
        fr_from_uint64(&p.coeffs[i], coeffs[i]);
    }

    // Initialise the secrets and data structures
    generate_trusted_setup(s1, s2, &secret, secrets_len);
    TEST_CHECK(C_KZG_OK == new_fft_settings(&fs, n));
    TEST_CHECK(C_KZG_OK == new_kzg_settings(&ks, s1, s2, secrets_len, &fs));
    TEST_CHECK(C_KZG_OK == new_fk20_single_settings(&fk, 2 * poly_len, &ks));

    // Commit to the polynomial
    TEST_CHECK(C_KZG_OK == commit_to_poly(&commitment, &p, &ks));

    // Generate the proofs
    TEST_CHECK(da_using_fk20_single(all_proofs, &p, &fk) == C_KZG_OK);

    // Verify the proof at each root of unity
    for (uint64_t i = 0; i < 2 * poly_len; i++) {
        x = fs.expanded_roots_of_unity[i * stride];
        eval_poly(&y, &p, &x);
        proof = all_proofs[reverse_bits_limited(2 * poly_len, i)];

        TEST_CHECK(C_KZG_OK == check_proof_single(&result, &commitment, &proof, &x, &y, &ks));
        TEST_CHECK(true == result);
    }

    // Clean up
    free_poly(&p);
    free_fft_settings(&fs);
    free_kzg_settings(&ks);
    free_fk20_single_settings(&fk);
}

void fk_multi_settings(void) {
    FFTSettings fs;
    KZGSettings ks;
    FK20MultiSettings fk;
    uint64_t n = 5;
    uint64_t secrets_len = 33;
    g1_t s1[secrets_len];
    g2_t s2[secrets_len];

    // Initialise the secrets and data structures
    generate_trusted_setup(s1, s2, &secret, secrets_len);
    TEST_CHECK(C_KZG_OK == new_fft_settings(&fs, n));
    TEST_CHECK(C_KZG_OK == new_kzg_settings(&ks, s1, s2, secrets_len, &fs));
    TEST_CHECK(C_KZG_OK == new_fk20_multi_settings(&fk, 32, 4, &ks));

    // Don't do anything. Run this with `valgrind` to check that memory is correctly allocated and freed.

    free_fft_settings(&fs);
    free_kzg_settings(&ks);
    free_fk20_multi_settings(&fk);
}

void fk_multi_case(int chunk_len, int n) {
    FFTSettings fs;
    KZGSettings ks;
    FK20MultiSettings fk;
    uint64_t chunk_count, width;
    uint64_t secrets_len;
    g1_t *s1;
    g2_t *s2;
    poly p;
    uint64_t vv[] = {1, 2, 3, 4, 7, 8, 9, 10, 13, 14, 1, 15, 1, 1000, 134, 33};
    g1_t commitment;
    g1_t *all_proofs;
    fr_t *extended_coeffs, *extended_coeffs_fft;
    fr_t *ys, *ys2;
    uint64_t domain_stride;

    TEST_ASSERT(is_power_of_two(n));
    TEST_ASSERT(is_power_of_two(chunk_len));
    TEST_ASSERT(n % 16 == 0);
    TEST_ASSERT(n >= chunk_len);

    chunk_count = n / chunk_len;
    secrets_len = 2 * n;
    width = log2_pow2(secrets_len);

    TEST_CHECK(C_KZG_OK == new_g1_array(&s1, secrets_len));
    TEST_CHECK(C_KZG_OK == new_g2_array(&s2, secrets_len));

    generate_trusted_setup(s1, s2, &secret, secrets_len);
    TEST_CHECK(C_KZG_OK == new_fft_settings(&fs, width));
    TEST_CHECK(C_KZG_OK == new_kzg_settings(&ks, s1, s2, secrets_len, &fs));
    TEST_CHECK(C_KZG_OK == new_fk20_multi_settings(&fk, n * 2, chunk_len, &ks));

    // Create a test polynomial of size n that's independent of chunk_len
    TEST_CHECK(C_KZG_OK == new_poly(&p, n));
    for (int i = 0; i < chunk_count; i++) {
        for (int j = 0; j < chunk_len; j++) {
            int p_index = i * chunk_len + j;
            int v_index = p_index % 16;
            uint64_t v = vv[v_index];
            int tmp = i * chunk_len / 16;
            if (v_index == 3) v += tmp;
            if (v_index == 5) v += tmp * tmp;
            fr_from_uint64(&p.coeffs[p_index], v);
            if (v_index == 12) fr_negate(&p.coeffs[p_index], &p.coeffs[p_index]);
            if (v_index == 14) fr_negate(&p.coeffs[p_index], &p.coeffs[p_index]);
        }
    }

    TEST_CHECK(C_KZG_OK == commit_to_poly(&commitment, &p, &ks));

    // Compute the multi proofs, assuming that the polynomial will be extended with zeros
    TEST_CHECK(C_KZG_OK == new_g1_array(&all_proofs, 2 * chunk_count));
    TEST_CHECK(C_KZG_OK == da_using_fk20_multi(all_proofs, &p, &fk));

    // Now actually extend the polynomial with zeros
    TEST_CHECK(C_KZG_OK == new_fr_array(&extended_coeffs, 2 * n));
    for (uint64_t i = 0; i < n; i++) {
        extended_coeffs[i] = p.coeffs[i];
    }
    for (uint64_t i = n; i < 2 * n; i++) {
        extended_coeffs[i] = fr_zero;
    }
    TEST_CHECK(C_KZG_OK == new_fr_array(&extended_coeffs_fft, 2 * n));
    TEST_CHECK(C_KZG_OK == fft_fr(extended_coeffs_fft, extended_coeffs, false, 2 * n, &fs));
    TEST_CHECK(C_KZG_OK == reverse_bit_order(extended_coeffs_fft, sizeof extended_coeffs_fft[0], 2 * n));

    // Verify the proofs
    TEST_CHECK(C_KZG_OK == new_fr_array(&ys, chunk_len));
    TEST_CHECK(C_KZG_OK == new_fr_array(&ys2, chunk_len));
    domain_stride = fs.max_width / (2 * n);
    for (uint64_t pos = 0; pos < 2 * chunk_count; pos++) {
        uint64_t domain_pos, stride;
        fr_t x;
        bool result;

        domain_pos = reverse_bits_limited(2 * chunk_count, pos);
        x = fs.expanded_roots_of_unity[domain_pos * domain_stride];

        // The ys from the extended coeffients
        for (uint64_t i = 0; i < chunk_len; i++) {
            ys[i] = extended_coeffs_fft[chunk_len * pos + i];
        }
        TEST_CHECK(C_KZG_OK == reverse_bit_order(ys, sizeof ys[0], chunk_len));

        // Now recreate the ys by evaluating the polynomial in the sub-domain range
        stride = fs.max_width / chunk_len;
        for (uint64_t i = 0; i < chunk_len; i++) {
            fr_t z;
            fr_mul(&z, &x, &fs.expanded_roots_of_unity[i * stride]);
            eval_poly(&ys2[i], &p, &z);
        }

        // ys and ys2 should be equal
        for (uint64_t i = 0; i < chunk_len; i++) {
            TEST_CHECK(fr_equal(&ys[i], &ys2[i]));
        }

        // Verify this proof
        TEST_CHECK(C_KZG_OK == check_proof_multi(&result, &commitment, &all_proofs[pos], &x, ys, chunk_len, &ks));
        TEST_CHECK(true == result);
    }

    free_poly(&p);
    free(all_proofs);
    free(extended_coeffs);
    free(extended_coeffs_fft);
    free(ys);
    free(ys2);
    free(s1);
    free(s2);
    free_fft_settings(&fs);
    free_kzg_settings(&ks);
    free_fk20_multi_settings(&fk);
}

void fk_multi_chunk_len_16_512() {
    fk_multi_case(16, 512);
}

void fk_multi_chunk_len_1_512() {
    fk_multi_case(1, 512);
}

void fk_multi_chunk_len_16_16() {
    fk_multi_case(16, 16);
}

// TODO: compare results of fk20_multi_da_opt() and  fk20_compute_proof_multi()

TEST_LIST = {
    {"FK20_PROOFS_TEST", title},
    {"fk_single", fk_single},
    {"fk_single_strided", fk_single_strided},
    {"fk_multi_settings", fk_multi_settings},
    {"fk_multi_chunk_len_1_512", fk_multi_chunk_len_1_512},
    {"fk_multi_chunk_len_16_512", fk_multi_chunk_len_16_512},
    {"fk_multi_chunk_len_16_16", fk_multi_chunk_len_16_16},
    {NULL, NULL} /* zero record marks the end of the list */
};

#endif