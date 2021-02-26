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
#include "c_kzg_util.h"
#include "test_util.h"
#include "zero_poly.h"
#include "poly.h"
#include "fft_fr.h"
#include "debug_util.h"

bool exists[16] = {true,  false, false, true, false, true, true,  false,
                   false, false, true,  true, false, true, false, true};

uint64_t expected_eval_u64[16][4] = {
    {0xf675fcb368535efaL, 0xe702bee472f5a74cL, 0xb2f500c4418d44d8L, 0x204089b477319517L},
    {0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L},
    {0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L},
    {0x2be1bf25823353ecL, 0xe98177cae115131bL, 0xe0de4495f16788fbL, 0x37e5487beb15a91eL},
    {0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L},
    {0xa8fd50243ec6f6daL, 0xb5863f0c04559733L, 0xbb55a8d735b8ceafL, 0x15856a55a6ba245bL},
    {0x40d8d622337027e7L, 0xd0c41e3defe394e5L, 0x25d1a6848cfbe861L, 0x6615977f56ab9ad1L},
    {0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L},
    {0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L},
    {0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L},
    {0x19b6d37343ac8596L, 0x9ac16b5b3f0c39eaL, 0x1938f2cc6f656899L, 0x2bc6a69eab7ebeadL},
    {0x75ceddca83d9b1e4L, 0x69917e9ccac289bcL, 0x7564f74fd58cc97aL, 0x7215036c8f20939fL},
    {0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L},
    {0x0088e6ba87233593L, 0xcc4a412d77455e7eL, 0x06ce406c147ada85L, 0x44275d7e26f9392cL},
    {0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L},
    {0x05ced2791378da2bL, 0xd16275df7a713f92L, 0x0cd24cf43668722dL, 0x22635b695b0fd198L}};

uint64_t expected_poly_u64[16][4] = {
    {0x6a20b4c8fbee018eL, 0x34c8bd90143c7a43L, 0xc4a72e43a8f20dbbL, 0x24c14de4b45f2d7bL},
    {0xba227dc25dab47c2L, 0xfa1cdd366cf44de2L, 0x2920a9a04dd15d06L, 0x0174305e712df7baL},
    {0xa3c8b170d759d6c4L, 0x846e2f5bfc241b81L, 0x1e4c5e807b5793eeL, 0x0758eca45c6dec8aL},
    {0x2c280194f3795affL, 0x55035b9ba568dd4fL, 0x91dda79960525b60L, 0x3fbfd2edd4a105f3L},
    {0x537cca635e26d630L, 0xaed6c42a88801d8fL, 0x41b2fdf16c422f7dL, 0x1d45a831fe3bf66eL},
    {0x037b0169fc698ffdL, 0xe982a4842fc849f0L, 0xdd398294c762e031L, 0x4092c5b8416d2c2fL},
    {0x19d4cdbb82bb00fbL, 0x5f31525ea0987c51L, 0xe80dcdb499dca94aL, 0x3aae0972562d375fL},
    {0x91757d97669b7cc0L, 0x8e9c261ef753ba83L, 0x747c849bb4e1e1d8L, 0x02472328ddfa1df6L},
    {0x0000000000000001L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L},
    {0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L},
    {0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L},
    {0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L},
    {0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L},
    {0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L},
    {0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L},
    {0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L}};

void test_reduce_leaves(void) {
    FFTSettings fs;
    TEST_CHECK(C_KZG_OK == new_fft_settings(&fs, 4));
    fr_t from_tree_reduction[16], from_direct[9], scratch[48];

    // Via reduce_leaves

    fr_t *leaves[4];
    fr_t leaf0[3], leaf1[3], leaf2[3], leaf3[3];
    leaves[0] = leaf0;
    leaves[1] = leaf1;
    leaves[2] = leaf2;
    leaves[3] = leaf3;
    uint64_t leaf_lengths[] = {3, 3, 3, 3};
    const uint64_t leaf_indices[4][2] = {{1, 3}, {7, 8}, {9, 10}, {12, 13}};
    for (int i = 0; i < 4; i++) {
        TEST_CHECK(C_KZG_OK == do_zero_poly_mul_leaf(leaves[i], 3, leaf_indices[i], 2, 1, &fs));
    }
    TEST_CHECK(C_KZG_OK == reduce_leaves(from_tree_reduction, 16, scratch, 48, leaves, 4, leaf_lengths, &fs));

    // Direct
    uint64_t indices[] = {1, 3, 7, 8, 9, 10, 12, 13};
    TEST_CHECK(C_KZG_OK == do_zero_poly_mul_leaf(from_direct, 9, indices, 8, 1, &fs));

    // Compare
    for (int i = 0; i < 9; i++) {
        TEST_CHECK(fr_equal(&from_tree_reduction[i], &from_direct[i]));
    }

    free_fft_settings(&fs);
}

void reduce_leaves_random(void) {
    for (int scale = 5; scale < 13; scale++) {
        for (int ii = 1; ii <= 7; ii++) {
            float missing_ratio = 0.1 * ii;

            FFTSettings fs;
            new_fft_settings(&fs, scale);
            uint64_t point_count = fs.max_width;
            uint64_t missing_count = point_count * missing_ratio;

            uint64_t *missing;
            TEST_CHECK(C_KZG_OK == new_uint64_array(&missing, point_count));
            for (uint64_t i = 0; i < point_count; i++) {
                missing[i] = i;
            }
            shuffle(missing, point_count);

            // Build the leaves
            fr_t **leaves;
            const int points_per_leaf = 63;
            uint64_t indices[points_per_leaf];
            uint64_t leaf_count = (missing_count + points_per_leaf - 1) / points_per_leaf;
            uint64_t *leaf_lengths;
            TEST_CHECK(C_KZG_OK == new_uint64_array(&leaf_lengths, leaf_count));
            TEST_CHECK(C_KZG_OK == new_fr_array_2(&leaves, leaf_count));
            for (uint64_t i = 0; i < leaf_count; i++) {
                uint64_t start = i * points_per_leaf;
                uint64_t end = start + points_per_leaf;
                if (end > missing_count) end = missing_count;
                uint64_t leaf_size = end - start;
                TEST_CHECK(C_KZG_OK == new_fr_array(&leaves[i], leaf_size + 1));
                for (int j = 0; j < leaf_size; j++) {
                    indices[j] = missing[i * points_per_leaf + j];
                }
                leaf_lengths[i] = leaf_size + 1;
                TEST_CHECK(C_KZG_OK == do_zero_poly_mul_leaf(leaves[i], leaf_lengths[i], indices, leaf_size, 1, &fs));
            }

            // From tree reduction
            fr_t *from_tree_reduction, *scratch;
            TEST_CHECK(C_KZG_OK == new_fr_array(&from_tree_reduction, point_count));
            TEST_CHECK(C_KZG_OK == new_fr_array(&scratch, point_count * 3));
            TEST_CHECK(C_KZG_OK == reduce_leaves(from_tree_reduction, point_count, scratch, point_count * 3, leaves,
                                                 leaf_count, leaf_lengths, &fs));

            // From direct
            fr_t *from_direct;
            TEST_CHECK(C_KZG_OK == new_fr_array(&from_direct, missing_count + 1));
            TEST_CHECK(C_KZG_OK == do_zero_poly_mul_leaf(from_direct, missing_count + 1, missing, missing_count,
                                                         fs.max_width / point_count, &fs));

            for (uint64_t i = 0; i < missing_count + 1; i++) {
                TEST_CHECK(fr_equal(&from_tree_reduction[i], &from_direct[i]));
            }

            free(from_tree_reduction);
            free(from_direct);
            free(scratch);
            for (uint64_t i = 0; i < leaf_count; i++) {
                free(leaves[i]);
            }
            free(leaves);
            free(leaf_lengths);
            free(missing);
            free_fft_settings(&fs);
        }
    }
}

void check_test_data(void) {
    FFTSettings fs;
    poly expected_eval, expected_poly, tmp_poly;
    new_poly(&expected_eval, 16);
    new_poly(&expected_poly, 16);
    new_poly(&tmp_poly, 16);
    new_fft_settings(&fs, 4);

    for (int i = 0; i < 16; i++) {
        fr_from_uint64s(&expected_eval.coeffs[i], expected_eval_u64[i]);
        fr_from_uint64s(&expected_poly.coeffs[i], expected_poly_u64[i]);
    }

    // Polynomial evalutes to zero at the expected places
    for (int i = 0; i < 16; i++) {
        if (!exists[i]) {
            fr_t tmp;
            eval_poly(&tmp, &expected_poly, &fs.expanded_roots_of_unity[i]);
            TEST_CHECK(fr_is_zero(&tmp));
            TEST_MSG("Failed for i = %d", i);
        }
    }

    // This is a curiosity
    for (int i = 1; i < 8; i++) {
        fr_t tmp;
        eval_poly(&tmp, &expected_eval, &fs.expanded_roots_of_unity[i]);
        TEST_CHECK(fr_is_zero(&tmp));
        TEST_MSG("Failed for i = %d", i);
    }

    // The eval poly is the FFT of the zero poly
    TEST_CHECK(C_KZG_OK == fft_fr(tmp_poly.coeffs, expected_eval.coeffs, true, tmp_poly.length, &fs));
    for (int i = 0; i < 16; i++) {
        TEST_CHECK(fr_equal(&tmp_poly.coeffs[i], &expected_poly.coeffs[i]));
        TEST_MSG("Failed for i = %d", i);
    }

    free_poly(&expected_poly);
    free_poly(&expected_eval);
    free_poly(&tmp_poly);
    free_fft_settings(&fs);
}

void zero_poly_known(void) {
    FFTSettings fs;
    poly expected_eval, expected_poly, zero_eval, zero_poly;
    uint64_t missing[16];
    uint64_t len_missing = 0;
    uint64_t zero_poly_len;
    new_poly(&expected_eval, 16);
    new_poly(&expected_poly, 16);
    new_poly(&zero_eval, 16);
    new_poly(&zero_poly, 16);
    new_fft_settings(&fs, 4);

    for (int i = 0; i < 16; i++) {
        fr_from_uint64s(&expected_eval.coeffs[i], expected_eval_u64[i]);
        fr_from_uint64s(&expected_poly.coeffs[i], expected_poly_u64[i]);
        if (!exists[i]) {
            missing[len_missing++] = i;
        }
    }

    TEST_CHECK(C_KZG_OK == zero_polynomial_via_multiplication(zero_eval.coeffs, zero_poly.coeffs, &zero_poly_len,
                                                              zero_eval.length, missing, len_missing, &fs));

    TEST_CHECK(expected_poly.length == zero_poly_len);
    TEST_MSG("Expected %lu, got %lu", expected_poly.length, zero_poly_len);

    for (int i = 0; i < expected_eval.length; i++) {
        TEST_CHECK(fr_equal(&expected_eval.coeffs[i], &zero_eval.coeffs[i]));
        TEST_CHECK(fr_equal(&expected_poly.coeffs[i], &zero_poly.coeffs[i]));
    }

    free_poly(&expected_poly);
    free_poly(&expected_eval);
    free_poly(&zero_poly);
    free_poly(&zero_eval);
    free_fft_settings(&fs);
}

void zero_poly_random(void) {
    for (int its = 0; its < 8; its++) {
        for (int scale = 3; scale < 13; scale++) {
            FFTSettings fs;
            TEST_CHECK(C_KZG_OK == new_fft_settings(&fs, scale));

            uint64_t missing[fs.max_width];
            int len_missing = 0;

            for (int i = 0; i < fs.max_width; i++) {
                if (rand() % 2) {
                    missing[len_missing++] = i;
                }
            }

            fr_t *zero_eval, *zero_poly;
            uint64_t zero_poly_len;
            TEST_CHECK(C_KZG_OK == new_fr_array(&zero_eval, fs.max_width));
            TEST_CHECK(C_KZG_OK == new_fr_array(&zero_poly, fs.max_width));
            TEST_CHECK(C_KZG_OK == zero_polynomial_via_multiplication(zero_eval, zero_poly, &zero_poly_len,
                                                                      fs.max_width, missing, len_missing, &fs));

            poly p;
            p.length = zero_poly_len;
            p.coeffs = zero_poly;
            int ret = 0;
            for (int i = 0; i < len_missing; i++) {
                fr_t out;
                eval_poly(&out, &p, &fs.expanded_roots_of_unity[missing[i]]);
                ret = TEST_CHECK(fr_is_zero(&out));
                TEST_MSG("Failed for missing[%d] = %lu", i, missing[i]);
            }
            TEST_MSG("Failed for scale %d", scale);

            fr_t *zero_eval_fft;
            TEST_CHECK(C_KZG_OK == new_fr_array(&zero_eval_fft, fs.max_width));
            TEST_CHECK(C_KZG_OK == fft_fr(zero_eval_fft, zero_eval, true, fs.max_width, &fs));
            for (uint64_t i = 0; i < zero_poly_len; i++) {
                TEST_CHECK(fr_equal(&zero_poly[i], &zero_eval_fft[i]));
            }
            for (uint64_t i = zero_poly_len; i < fs.max_width; i++) {
                TEST_CHECK(fr_is_zero(&zero_eval_fft[i]));
            }

            free(zero_poly);
            free(zero_eval);
            free(zero_eval_fft);
            free_fft_settings(&fs);
        }
    }
}

TEST_LIST = {
    {"ZERO_POLY_TEST", title},
    {"test_reduce_leaves", test_reduce_leaves},
    {"check_test_data", check_test_data},
    {"reduce_leaves_random", reduce_leaves_random},
    {"zero_poly_known", zero_poly_known},
    {"zero_poly_random", zero_poly_random},
    {NULL, NULL} /* zero record marks the end of the list */
};
