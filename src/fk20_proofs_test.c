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

#include "../inc/acutest.h"
#include "test_util.h"
#include "fk20_proofs.h"
#include "c_kzg_util.h"
#include "utility.h"

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

void fk_multi_0(void) {
    FFTSettings fs;
    KZGSettings ks;
    FK20MultiSettings fk;
    uint64_t n, chunk_len, chunk_count;
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

    chunk_len = 16;
    chunk_count = 32;
    n = chunk_len * chunk_count;
    secrets_len = 2 * n;

    TEST_CHECK(C_KZG_OK == new_g1_array(&s1, secrets_len));
    TEST_CHECK(C_KZG_OK == new_g2_array(&s2, secrets_len));

    generate_trusted_setup(s1, s2, &secret, secrets_len);
    TEST_CHECK(C_KZG_OK == new_fft_settings(&fs, 4 + 5 + 1));
    TEST_CHECK(C_KZG_OK == new_kzg_settings(&ks, s1, s2, secrets_len, &fs));
    TEST_CHECK(C_KZG_OK == new_fk20_multi_settings(&fk, n * 2, chunk_len, &ks));

    // Create a test polynomial: 512 coefficients
    TEST_CHECK(C_KZG_OK == new_poly(&p, n));
    for (int i = 0; i < chunk_count; i++) {
        for (int j = 0; j < chunk_len; j++) {
            uint64_t v = vv[j];
            if (j == 3) v += i;
            if (j == 5) v += i * i;
            fr_from_uint64(&p.coeffs[i * chunk_len + j], v);
        }
        fr_negate(&p.coeffs[i * chunk_len + 12], &p.coeffs[i * chunk_len + 12]);
        fr_negate(&p.coeffs[i * chunk_len + 14], &p.coeffs[i * chunk_len + 14]);
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

// TODO: compare results of fk20_multi_da_opt() and  fk20_compute_proof_multi()

TEST_LIST = {
    {"FK20_PROOFS_TEST", title},
    {"fk_single", fk_single},
    {"fk_single_strided", fk_single_strided},
    {"fk_multi_settings", fk_multi_settings},
    {"fk_multi_0", fk_multi_0},
    {NULL, NULL} /* zero record marks the end of the list */
};
