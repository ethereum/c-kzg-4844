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

void test_reduce_partials(void) {
    FFTSettings fs;
    TEST_CHECK(C_KZG_OK == new_fft_settings(&fs, 4));
    fr_t from_tree_reduction_coeffs[16], from_direct_coeffs[9], scratch[48];
    poly from_tree_reduction, from_direct;
    from_tree_reduction.coeffs = from_tree_reduction_coeffs;
    from_tree_reduction.length = 16;
    from_direct.coeffs = from_direct_coeffs;
    from_direct.length = 9;

    // Via reduce_partials

    poly partials[4];
    fr_t partial0[3], partial1[3], partial2[3], partial3[3];
    partials[0].coeffs = partial0, partials[0].length = 3;
    partials[1].coeffs = partial1, partials[1].length = 3;
    partials[2].coeffs = partial2, partials[2].length = 3;
    partials[3].coeffs = partial3, partials[3].length = 3;
    const uint64_t partial_indices[4][2] = {{1, 3}, {7, 8}, {9, 10}, {12, 13}};
    for (int i = 0; i < 4; i++) {
        TEST_CHECK(C_KZG_OK == do_zero_poly_mul_partial(&partials[i], partial_indices[i], 2, 1, &fs));
    }
    TEST_CHECK(C_KZG_OK == reduce_partials(&from_tree_reduction, 16, scratch, 48, partials, 4, &fs));

    // Direct
    uint64_t indices[] = {1, 3, 7, 8, 9, 10, 12, 13};
    TEST_CHECK(C_KZG_OK == do_zero_poly_mul_partial(&from_direct, indices, 8, 1, &fs));

    // Compare
    for (int i = 0; i < 9; i++) {
        TEST_CHECK(fr_equal(&from_tree_reduction.coeffs[i], &from_direct.coeffs[i]));
    }

    free_fft_settings(&fs);
}

void reduce_partials_random(void) {
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

            // Build the partials
            poly *partials;
            const int missing_per_partial = 63;
            uint64_t indices[missing_per_partial];
            uint64_t partial_count = (missing_count + missing_per_partial - 1) / missing_per_partial;
            TEST_CHECK(C_KZG_OK == new_poly_array(&partials, partial_count));
            for (uint64_t i = 0; i < partial_count; i++) {
                uint64_t start = i * missing_per_partial;
                uint64_t end = start + missing_per_partial;
                if (end > missing_count) end = missing_count;
                uint64_t partial_size = end - start;
                TEST_CHECK(C_KZG_OK == new_fr_array(&partials[i].coeffs, partial_size + 1));
                for (int j = 0; j < partial_size; j++) {
                    indices[j] = missing[i * missing_per_partial + j];
                }
                partials[i].length = partial_size + 1;
                TEST_CHECK(C_KZG_OK == do_zero_poly_mul_partial(&partials[i], indices, partial_size, 1, &fs));
            }

            // From tree reduction
            poly from_tree_reduction;
            TEST_CHECK(C_KZG_OK == new_poly(&from_tree_reduction, point_count));
            fr_t *scratch;
            TEST_CHECK(C_KZG_OK == new_fr_array(&scratch, point_count * 3));
            TEST_CHECK(C_KZG_OK == reduce_partials(&from_tree_reduction, point_count, scratch, point_count * 3,
                                                   partials, partial_count, &fs));

            // From direct
            poly from_direct;
            TEST_CHECK(C_KZG_OK == new_poly(&from_direct, missing_count + 1));
            TEST_CHECK(C_KZG_OK ==
                       do_zero_poly_mul_partial(&from_direct, missing, missing_count, fs.max_width / point_count, &fs));

            for (uint64_t i = 0; i < missing_count + 1; i++) {
                TEST_CHECK(fr_equal(&from_tree_reduction.coeffs[i], &from_direct.coeffs[i]));
            }

            free_poly(&from_tree_reduction);
            free_poly(&from_direct);
            free(scratch);
            for (uint64_t i = 0; i < partial_count; i++) {
                free_poly(&partials[i]);
            }
            free(partials);
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

    TEST_CHECK(C_KZG_OK == zero_polynomial_via_multiplication(zero_eval.coeffs, &zero_poly, zero_eval.length, missing,
                                                              len_missing, &fs));

    TEST_CHECK(len_missing + 1 == zero_poly.length);
    TEST_MSG("Expected %lu, got %lu", len_missing + 1, zero_poly.length);

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
        srand(its);
        for (int scale = 3; scale < 13; scale++) {
            FFTSettings fs;
            TEST_CHECK(C_KZG_OK == new_fft_settings(&fs, scale));

            uint64_t *missing;
            TEST_CHECK(C_KZG_OK == new_uint64_array(&missing, fs.max_width));
            int len_missing = 0;

            for (int i = 0; i < fs.max_width; i++) {
                if (rand() % 2) {
                    missing[len_missing++] = i;
                }
            }

            // We know it doesn't work when all indices are missing
            if (len_missing == fs.max_width) {
                free_fft_settings(&fs);
                continue;
            }

            fr_t *zero_eval;
            poly zero_poly;
            TEST_CHECK(C_KZG_OK == new_fr_array(&zero_eval, fs.max_width));
            TEST_CHECK(C_KZG_OK == new_poly(&zero_poly, fs.max_width));
            TEST_CHECK(C_KZG_OK == zero_polynomial_via_multiplication(zero_eval, &zero_poly, fs.max_width, missing,
                                                                      len_missing, &fs));

            TEST_CHECK(len_missing + 1 == zero_poly.length);
            TEST_MSG("ZeroPolyLen: expected %d, got %lu", len_missing + 1, zero_poly.length);

            int ret = 0;
            for (int i = 0; i < len_missing; i++) {
                fr_t out;
                eval_poly(&out, &zero_poly, &fs.expanded_roots_of_unity[missing[i]]);
                ret = TEST_CHECK(fr_is_zero(&out));
                TEST_MSG("Failed for missing[%d] = %lu", i, missing[i]);
            }

            fr_t *zero_eval_fft;
            TEST_CHECK(C_KZG_OK == new_fr_array(&zero_eval_fft, fs.max_width));
            TEST_CHECK(C_KZG_OK == fft_fr(zero_eval_fft, zero_eval, true, fs.max_width, &fs));
            for (uint64_t i = 0; i < zero_poly.length; i++) {
                TEST_CHECK(fr_equal(&zero_poly.coeffs[i], &zero_eval_fft[i]));
            }
            for (uint64_t i = zero_poly.length; i < fs.max_width; i++) {
                TEST_CHECK(fr_is_zero(&zero_eval_fft[i]));
            }

            free(missing);
            free_poly(&zero_poly);
            free(zero_eval);
            free(zero_eval_fft);
            free_fft_settings(&fs);
        }
    }
}

// This didn't work in the original version (ported from Go), but ought now be fine
void zero_poly_all_but_one(void) {
    FFTSettings fs;
    TEST_CHECK(C_KZG_OK == new_fft_settings(&fs, 8));

    uint64_t *missing;
    TEST_CHECK(C_KZG_OK == new_uint64_array(&missing, fs.max_width));

    // All but the first are missing
    for (int i = 0; i < fs.max_width - 1; i++) {
        missing[i] = i + 1;
    }
    int len_missing = fs.max_width - 1;

    fr_t *zero_eval;
    poly zero_poly;
    TEST_CHECK(C_KZG_OK == new_fr_array(&zero_eval, fs.max_width));
    TEST_CHECK(C_KZG_OK == new_poly(&zero_poly, fs.max_width));
    TEST_CHECK(C_KZG_OK ==
               zero_polynomial_via_multiplication(zero_eval, &zero_poly, fs.max_width, missing, len_missing, &fs));

    TEST_CHECK(len_missing + 1 == zero_poly.length);
    TEST_MSG("ZeroPolyLen: expected %d, got %lu", len_missing + 1, zero_poly.length);

    int ret = 0;
    for (int i = 0; i < len_missing; i++) {
        fr_t out;
        eval_poly(&out, &zero_poly, &fs.expanded_roots_of_unity[missing[i]]);
        ret = TEST_CHECK(fr_is_zero(&out));
        TEST_MSG("Failed for missing[%d] = %lu", i, missing[i]);
    }

    fr_t *zero_eval_fft;
    TEST_CHECK(C_KZG_OK == new_fr_array(&zero_eval_fft, fs.max_width));
    TEST_CHECK(C_KZG_OK == fft_fr(zero_eval_fft, zero_eval, true, fs.max_width, &fs));
    for (uint64_t i = 0; i < zero_poly.length; i++) {
        TEST_CHECK(fr_equal(&zero_poly.coeffs[i], &zero_eval_fft[i]));
    }
    for (uint64_t i = zero_poly.length; i < fs.max_width; i++) {
        TEST_CHECK(fr_is_zero(&zero_eval_fft[i]));
    }

    free(missing);
    free_poly(&zero_poly);
    free(zero_eval);
    free(zero_eval_fft);
    free_fft_settings(&fs);
}

// This is to prevent regressions - 252 missing at width 8 is an edge case which has 4 full partials
void zero_poly_252(void) {
    FFTSettings fs;
    TEST_CHECK(C_KZG_OK == new_fft_settings(&fs, 8));

    uint64_t *missing;
    TEST_CHECK(C_KZG_OK == new_uint64_array(&missing, fs.max_width));

    int len_missing = 252;
    for (int i = 0; i < len_missing; i++) {
        missing[i] = i;
    }

    fr_t *zero_eval;
    poly zero_poly;
    TEST_CHECK(C_KZG_OK == new_fr_array(&zero_eval, fs.max_width));
    TEST_CHECK(C_KZG_OK == new_poly(&zero_poly, fs.max_width));
    TEST_CHECK(C_KZG_OK ==
               zero_polynomial_via_multiplication(zero_eval, &zero_poly, fs.max_width, missing, len_missing, &fs));

    TEST_CHECK(len_missing + 1 == zero_poly.length);
    TEST_MSG("ZeroPolyLen: expected %d, got %lu", len_missing + 1, zero_poly.length);

    int ret = 0;
    for (int i = 0; i < len_missing; i++) {
        fr_t out;
        eval_poly(&out, &zero_poly, &fs.expanded_roots_of_unity[missing[i]]);
        ret = TEST_CHECK(fr_is_zero(&out));
        TEST_MSG("Failed for missing[%d] = %lu", i, missing[i]);
    }

    fr_t *zero_eval_fft;
    TEST_CHECK(C_KZG_OK == new_fr_array(&zero_eval_fft, fs.max_width));
    TEST_CHECK(C_KZG_OK == fft_fr(zero_eval_fft, zero_eval, true, fs.max_width, &fs));
    for (uint64_t i = 0; i < zero_poly.length; i++) {
        TEST_CHECK(fr_equal(&zero_poly.coeffs[i], &zero_eval_fft[i]));
    }
    for (uint64_t i = zero_poly.length; i < fs.max_width; i++) {
        TEST_CHECK(fr_is_zero(&zero_eval_fft[i]));
    }

    free(missing);
    free_poly(&zero_poly);
    free(zero_eval);
    free(zero_eval_fft);
    free_fft_settings(&fs);
}

TEST_LIST = {
    {"ZERO_POLY_TEST", title},
    {"test_reduce_partials", test_reduce_partials},
    {"check_test_data", check_test_data},
    {"reduce_partials_random", reduce_partials_random},
    {"zero_poly_known", zero_poly_known},
    {"zero_poly_random", zero_poly_random},
    {"zero_poly_all_but_one", zero_poly_all_but_one},
    {"zero_poly_252", zero_poly_252},
    {NULL, NULL} /* zero record marks the end of the list */
};
