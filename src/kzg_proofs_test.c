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
#include "kzg_proofs.h"

void proof_single(void) {
    // Our polynomial: degree 15, 16 coefficients
    uint64_t coeffs[] = {1, 2, 3, 4, 7, 7, 7, 7, 13, 13, 13, 13, 13, 13, 13, 13};
    int poly_len = sizeof coeffs / sizeof coeffs[0];
    uint64_t secrets_len = poly_len + 1;

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

void proof_multi(void) {
    // Our polynomial: degree 15, 16 coefficients
    uint64_t coeffs[] = {1, 2, 3, 4, 7, 7, 7, 7, 13, 13, 13, 13, 13, 13, 13, 13};
    int poly_len = sizeof coeffs / sizeof coeffs[0];

    FFTSettings fs1, fs2;
    KZGSettings ks1, ks2;
    poly p;
    g1_t commitment, proof;
    fr_t x, tmp;
    bool result;

    // Compute proof at 2^coset_scale points
    int coset_scale = 3, coset_len = (1 << coset_scale);
    fr_t y[coset_len];

    uint64_t secrets_len = poly_len > coset_len ? poly_len + 1 : coset_len + 1;
    g1_t s1[secrets_len];
    g2_t s2[secrets_len];

    // Create the polynomial
    new_poly(&p, poly_len);
    for (int i = 0; i < poly_len; i++) {
        fr_from_uint64(&p.coeffs[i], coeffs[i]);
    }

    // Initialise the secrets and data structures
    generate_trusted_setup(s1, s2, &secret, secrets_len);
    TEST_CHECK(C_KZG_OK == new_fft_settings(&fs1, 4)); // ln_2 of poly_len
    TEST_CHECK(C_KZG_OK == new_kzg_settings(&ks1, s1, s2, secrets_len, &fs1));

    // Commit to the polynomial
    TEST_CHECK(C_KZG_OK == commit_to_poly(&commitment, &p, &ks1));

    TEST_CHECK(C_KZG_OK == new_fft_settings(&fs2, coset_scale));
    TEST_CHECK(C_KZG_OK == new_kzg_settings(&ks2, s1, s2, secrets_len, &fs2));

    // Compute proof at the points [x * root_i] 0 <= i < coset_len
    fr_from_uint64(&x, 5431);
    TEST_CHECK(C_KZG_OK == compute_proof_multi(&proof, &p, &x, coset_len, &ks2));

    // y_i is the value of the polynomial at each x_i
    for (int i = 0; i < coset_len; i++) {
        fr_mul(&tmp, &x, &ks2.fs->expanded_roots_of_unity[i]);
        eval_poly(&y[i], &p, &tmp);
    }

    // Verify the proof that the (unknown) polynomial has value y_i at x_i
    TEST_CHECK(C_KZG_OK == check_proof_multi(&result, &commitment, &proof, &x, y, coset_len, &ks2));
    TEST_CHECK(true == result);

    // Change a value and check that the proof fails
    fr_add(y + coset_len / 2, y + coset_len / 2, &fr_one);
    TEST_CHECK(C_KZG_OK == check_proof_multi(&result, &commitment, &proof, &x, y, coset_len, &ks2));
    TEST_CHECK(false == result);

    free_fft_settings(&fs1);
    free_fft_settings(&fs2);
    free_kzg_settings(&ks1);
    free_kzg_settings(&ks2);
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

TEST_LIST = {
    {"KZG_PROOFS_TEST", title},
    {"proof_single", proof_single},
    {"proof_multi", proof_multi},
    {"commit_to_nil_poly", commit_to_nil_poly},
    {"commit_to_too_long_poly", commit_to_too_long_poly},
    {NULL, NULL} /* zero record marks the end of the list */
};
