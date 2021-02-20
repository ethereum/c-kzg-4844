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
#include "fft_common.h"
#include "utility.h"

#define NUM_ROOTS 32

void roots_of_unity_is_the_expected_size(void) {
    TEST_CHECK(NUM_ROOTS == sizeof(scale2_root_of_unity) / sizeof(scale2_root_of_unity[0]));
}

void roots_of_unity_out_of_bounds_fails(void) {
    FFTSettings fs;
    TEST_CHECK(C_KZG_BADARGS == new_fft_settings(&fs, NUM_ROOTS));
}

void roots_of_unity_are_plausible(void) {
    fr_t r;
    for (int i = 0; i < NUM_ROOTS; i++) {
        fr_from_uint64s(&r, scale2_root_of_unity[i]);
        for (int j = 0; j < i; j++) {
            fr_sqr(&r, &r);
        }
        TEST_CHECK(true == fr_is_one(&r));
        TEST_MSG("Root %d failed", i);
    }
}

void expand_roots_is_plausible(void) {
    // Just test one (largeish) value of scale
    unsigned int scale = 15;
    unsigned int width = 1 << scale;
    fr_t root, expanded[width + 1], prod;

    // Initialise
    fr_from_uint64s(&root, scale2_root_of_unity[scale]);
    TEST_CHECK(expand_root_of_unity(expanded, &root, width) == C_KZG_OK);

    // Verify - each pair should multiply to one
    TEST_CHECK(true == fr_is_one(expanded + 0));
    TEST_CHECK(true == fr_is_one(expanded + width));
    for (unsigned int i = 1; i <= width / 2; i++) {
        fr_mul(&prod, expanded + i, expanded + width - i);
        TEST_CHECK(true == fr_is_one(&prod));
    }
}

void new_fft_settings_is_plausible(void) {
    // Just test one (largeish) value of scale
    int scale = 21;
    unsigned int width = 1 << scale;
    fr_t prod;
    FFTSettings s;

    TEST_CHECK(new_fft_settings(&s, scale) == C_KZG_OK);

    // Verify - each pair should multiply to one
    for (unsigned int i = 1; i <= width; i++) {
        fr_mul(&prod, s.expanded_roots_of_unity + i, s.reverse_roots_of_unity + i);
        TEST_CHECK(true == fr_is_one(&prod));
    }

    free_fft_settings(&s);
}

TEST_LIST = {
    {"FFT_COMMON_TEST", title},
    {"roots_of_unity_is_the_expected_size", roots_of_unity_is_the_expected_size},
    {"roots_of_unity_out_of_bounds_fails", roots_of_unity_out_of_bounds_fails},
    {"roots_of_unity_are_plausible", roots_of_unity_are_plausible},
    {"expand_roots_is_plausible", expand_roots_is_plausible},
    {"new_fft_settings_is_plausible", new_fft_settings_is_plausible},
    {NULL, NULL} /* zero record marks the end of the list */
};
