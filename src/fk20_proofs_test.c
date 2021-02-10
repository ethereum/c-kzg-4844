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
#include "debug_util.h"
#include "test_util.h"
#include "fk20_proofs.h"

void test_reverse_bits_macros(void) {
    TEST_CHECK(128 == rev_byte(1));
    TEST_CHECK(128 == rev_byte(257));
    TEST_CHECK((uint32_t)1 << 31 == rev_4byte(1));
    TEST_CHECK(0x1e6a2c48 == rev_4byte(0x12345678));
    TEST_CHECK(0x00000000 == rev_4byte(0x00000000));
    TEST_CHECK(0xffffffff == rev_4byte(0xffffffff));
}

void test_reverse_bits_0(void) {
    uint32_t actual, expected;
    for (int i = 0; i < 32; i++) {
        expected = (uint32_t)1 << (31 - i);
        actual = reverse_bits((uint32_t)1 << i);
        TEST_CHECK(expected == actual);
    }
}

void test_reverse_bits_1(void) {
    TEST_CHECK(0x84c2a6e1 == reverse_bits(0x87654321));
}

void test_log2_pow2(void) {
    int actual, expected;
    for (int i = 0; i < 32; i++) {
        expected = i;
        actual = log2_pow2((uint32_t)1 << i);
        TEST_CHECK(expected == actual);
    }
}

void test_reverse_bit_order_g1(void) {
    int size = 10, n = 1 << size;
    blst_p1 a[n], b[n];
    blst_fr tmp;

    for (int i = 0; i < n; i++) {
        fr_from_uint64(&tmp, i);
        p1_mul(&a[i], blst_p1_generator(), &tmp);
        b[i] = a[i];
    }

    TEST_CHECK(C_KZG_OK == reverse_bit_order(a, sizeof(blst_p1), n));
    for (int i = 0; i < n; i++) {
        TEST_CHECK(true == blst_p1_is_equal(&b[reverse_bits(i) >> (32 - size)], &a[i]));
    }

    // Hand check a few select values
    TEST_CHECK(true == blst_p1_is_equal(&b[0], &a[0]));
    TEST_CHECK(false == blst_p1_is_equal(&b[1], &a[1]));
    TEST_CHECK(true == blst_p1_is_equal(&b[n - 1], &a[n - 1]));
}

void test_reverse_bit_order_fr(void) {
    int size = 12, n = 1 << size;
    blst_fr a[n], b[n];

    for (int i = 0; i < n; i++) {
        fr_from_uint64(&a[i], i);
        b[i] = a[i];
    }

    TEST_CHECK(C_KZG_OK == reverse_bit_order(a, sizeof(blst_fr), n));
    for (int i = 0; i < n; i++) {
        TEST_CHECK(true == fr_equal(&b[reverse_bits(i) >> (32 - size)], &a[i]));
    }

    // Hand check a few select values
    TEST_CHECK(true == fr_equal(&b[0], &a[0]));
    TEST_CHECK(false == fr_equal(&b[1], &a[1]));
    TEST_CHECK(true == fr_equal(&b[n - 1], &a[n - 1]));
}

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
    blst_p1 *s1;
    blst_p2 *s2;
    poly p;
    blst_p1 commitment, all_proofs[2 * poly_len], proof;
    blst_fr x, y;
    bool result;

    TEST_CHECK(n_len >= 2 * poly_len);
    TEST_CHECK(init_poly_with_coeffs(&p, coeffs, poly_len) == C_KZG_OK);

    // Initialise the secrets and data structures
    generate_trusted_setup(&s1, &s2, &secret, secrets_len);
    TEST_CHECK(C_KZG_OK == new_fft_settings(&fs, n));
    TEST_CHECK(C_KZG_OK == new_kzg_settings(&ks, s1, s2, secrets_len, &fs));
    TEST_CHECK(C_KZG_OK == new_fk20_single_settings(&fk, 2 * poly_len, &ks));

    // Generate the proofs
    commit_to_poly(&commitment, &p, &ks);
    TEST_CHECK(da_using_fk20_single(all_proofs, &p, &fk) == C_KZG_OK);

    // Verify the proof at each position
    for (uint64_t i = 0; i < 2 * poly_len; i++) {
        x = fs.expanded_roots_of_unity[i];
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
    free_trusted_setup(s1, s2);
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
    blst_p1 *s1;
    blst_p2 *s2;
    poly p;
    blst_p1 commitment, all_proofs[2 * poly_len], proof;
    blst_fr x, y;
    bool result;

    TEST_CHECK(n_len >= 2 * poly_len);
    TEST_CHECK(init_poly_with_coeffs(&p, coeffs, poly_len) == C_KZG_OK);

    // Initialise the secrets and data structures
    generate_trusted_setup(&s1, &s2, &secret, secrets_len);
    TEST_CHECK(C_KZG_OK == new_fft_settings(&fs, n));
    TEST_CHECK(C_KZG_OK == new_kzg_settings(&ks, s1, s2, secrets_len, &fs));
    TEST_CHECK(C_KZG_OK == new_fk20_single_settings(&fk, 2 * poly_len, &ks));

    // Generate the proofs
    commit_to_poly(&commitment, &p, &ks);
    TEST_CHECK(da_using_fk20_single(all_proofs, &p, &fk) == C_KZG_OK);

    // Verify the proof at each position
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
    free_trusted_setup(s1, s2);
}

TEST_LIST = {
    {"FK20_PROOFS_TEST", title},
    {"test_reverse_bits_macros", test_reverse_bits_macros},
    {"test_reverse_bits_0", test_reverse_bits_0},
    {"test_reverse_bits_1", test_reverse_bits_1},
    {"test_log2_pow2", test_log2_pow2},
    {"test_reverse_bit_order_g1", test_reverse_bit_order_g1},
    {"test_reverse_bit_order_fr", test_reverse_bit_order_fr},
    {"fk_single", fk_single},
    {"fk_single_strided", fk_single_strided},
    {NULL, NULL} /* zero record marks the end of the list */
};
