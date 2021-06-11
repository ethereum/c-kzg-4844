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
    {0xfd5a5130b97ce0c3L, 0xb4748a4cb0f90e6dL, 0x12a1ab34b25b18c1L, 0x5a5ac0c81c9f7ea8L},
    {0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L},
    {0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L},
    {0xaa385cbce3dd1657L, 0x2fdab57a38bdb514L, 0x20e022e205dafa53L, 0x14077dd3f5d996b1L},
    {0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L},
    {0x194018614b6f7276L, 0xdf2b18f870532376L, 0x1ff427cd5b583fe6L, 0x014d6444ff03dd09L},
    {0xcc84c2de684c0ddeL, 0xf1e7ab32aa830d02L, 0x967bf35a2a691f20L, 0x046109731cdf0d3cL},
    {0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L},
    {0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L},
    {0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L},
    {0x96cddd2924212afbL, 0xeaa4c1f51421d8d8L, 0x3ae969cfa34d0ed1L, 0x6b6c5e876bc3916dL},
    {0x449310802f74ad49L, 0x47c940979163037aL, 0x10d311564afb9b2aL, 0x269b8531c369bafbL},
    {0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L},
    {0xd9af75fe35c16cf1L, 0x068bb140cea92f75L, 0xe769811965e10a47L, 0x48ed97e6745612f2L},
    {0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L},
    {0x7ef1f59bb1677685L, 0x33a637296680e8ceL, 0xaaf62b3f6e016709L, 0x454a299178a4dba9L}};

uint64_t expected_poly_u64[16][4] = {
    {0xac159e2688bd4333L, 0x3bfef0f00df2ec88L, 0x561dcd0fd4d314d9L, 0x533bd8c1e977024eL},
    {0x18bc6eedc010ef8dL, 0xc731a3eb4ea2ab70L, 0x5c2589357ae121a8L, 0x04f9108d308f7016L},
    {0x232759f49556ac08L, 0x9776fe2e9f4c613cL, 0x74d5bed4eb2de960L, 0x1f6cf6719bfa0e68L},
    {0xf2f3461e8ab1ae34L, 0xeb220fcc11ef1c80L, 0x7a4637d3a637739bL, 0x19901a58cd177c53L},
    {0x9340f62465a1f4feL, 0xd9cb3ea6de494a11L, 0xee92ebc763cdff5dL, 0x5443e89811b5b9f5L},
    {0x269a255e2e4e48a4L, 0xfadae7a89d9b2f2bL, 0xb5515799b41e1a88L, 0x2e990979a0ffcee5L},
    {0x1c2f3a5759088c29L, 0x2a958d654cf1795fL, 0x9ca121fa43d152d1L, 0x1425239535953093L},
    {0x4c634e2d63ad89fdL, 0xd6ea7bc7da4ebe1aL, 0x9730a8fb88c7c895L, 0x1a01ffae0477c2a8L},
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
