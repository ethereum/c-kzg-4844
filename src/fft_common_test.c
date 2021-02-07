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
#include "fft_common.h"
#include "blst_util.h"

#define NUM_ROOTS 32

void title(void) {
    ;
}

void roots_of_unity_is_the_expected_size(void) {
    TEST_CHECK(NUM_ROOTS == sizeof(scale2_root_of_unity) / sizeof(scale2_root_of_unity[0]));
}

void roots_of_unity_are_plausible(void) {
    blst_fr r;
    for (int i = 0; i < NUM_ROOTS; i++) {
        blst_fr_from_uint64(&r, scale2_root_of_unity[i]);
        for (int j = 0; j < i; j++) {
            blst_fr_sqr(&r, &r);
        }
        TEST_CHECK(true == fr_is_one(&r));
        TEST_MSG("Root %d failed", i);
    }
}

void reverse_works(void) {
    int n = 24;
    blst_fr arr[n + 1], rev[n + 1];
    blst_fr diff;

    // Initialise - increasing values
    arr[0] = fr_one;
    for (int i = 1; i <= n; i++) {
        blst_fr_add(arr + i, arr + i - 1, &fr_one);
    }

    // Reverse
    TEST_CHECK(reverse(rev, arr, n) == C_KZG_OK);

    // Verify - decreasing values
    for (int i = 0; i < n; i++) {
        blst_fr_sub(&diff, rev + i, rev + i + 1);
        TEST_CHECK(true == fr_is_one(&diff));
    }
    TEST_CHECK(true == fr_is_one(rev + n));
}

void expand_roots_is_plausible(void) {
    // Just test one (largeish) value of scale
    unsigned int scale = 15;
    unsigned int width = 1 << scale;
    blst_fr root, expanded[width + 1], prod;

    // Initialise
    blst_fr_from_uint64(&root, scale2_root_of_unity[scale]);
    TEST_CHECK(expand_root_of_unity(expanded, &root, width) == C_KZG_OK);

    // Verify - each pair should multiply to one
    TEST_CHECK(true == fr_is_one(expanded + 0));
    TEST_CHECK(true == fr_is_one(expanded + width));
    for (unsigned int i = 1; i <= width / 2; i++) {
        blst_fr_mul(&prod, expanded + i, expanded + width - i);
        TEST_CHECK(true == fr_is_one(&prod));
    }
}

void new_fft_settings_is_plausible(void) {
    // Just test one (largeish) value of scale
    int scale = 21;
    unsigned int width = 1 << scale;
    blst_fr prod;
    FFTSettings s;

    TEST_CHECK(new_fft_settings(&s, scale) == C_KZG_OK);

    // Verify - each pair should multiply to one
    for (unsigned int i = 1; i <= width; i++) {
        blst_fr_mul(&prod, s.expanded_roots_of_unity + i, s.reverse_roots_of_unity + i);
        TEST_CHECK(true == fr_is_one(&prod));
    }

    free_fft_settings(&s);
}

void is_power_of_two_works(void) {
    // All actual powers of two
    for (int i = 0; i <= 63; i++) {
        TEST_CHECK(true == is_power_of_two((uint64_t)1 << i));
        TEST_MSG("Case %d", i);
    }

    // This is a bit weird
    TEST_CHECK(true == is_power_of_two(0));

    // Not powers of two
    TEST_CHECK(false == is_power_of_two(123));
    TEST_CHECK(false == is_power_of_two(1234567));
}

TEST_LIST = {
    {"FFT_COMMON_TEST", title},
    {"roots_of_unity_is_the_expected_size", roots_of_unity_is_the_expected_size},
    {"roots_of_unity_are_plausible", roots_of_unity_are_plausible},
    {"reverse_works", reverse_works},
    {"expand_roots_is_plausible", expand_roots_is_plausible},
    {"new_fft_settings_is_plausible", new_fft_settings_is_plausible},
    {"is_power_of_two_works", is_power_of_two_works},
    {NULL, NULL} /* zero record marks the end of the list */
};
