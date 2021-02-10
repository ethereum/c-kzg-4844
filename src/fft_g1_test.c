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
#include "fft_g1.h"

void make_data(blst_p1 *out, uint64_t n) {
    // Multiples of g1_gen
    if (n == 0) return;
    blst_p1_from_affine(out + 0, &BLS12_381_G1);
    for (int i = 1; i < n; i++) {
        blst_p1_add_or_double_affine(out + i, out + i - 1, &BLS12_381_G1);
    }
}

void compare_sft_fft(void) {
    // Initialise: arbitrary size
    unsigned int size = 6;
    FFTSettings fs;
    TEST_CHECK(new_fft_settings(&fs, size) == C_KZG_OK);
    blst_p1 data[fs.max_width], slow[fs.max_width], fast[fs.max_width];
    make_data(data, fs.max_width);

    // Do both fast and slow transforms
    fft_g1_slow(slow, data, 1, fs.expanded_roots_of_unity, 1, fs.max_width);
    fft_g1_fast(fast, data, 1, fs.expanded_roots_of_unity, 1, fs.max_width);

    // Verify the results are identical
    for (int i = 0; i < fs.max_width; i++) {
        TEST_CHECK(blst_p1_is_equal(slow + i, fast + i));
    }

    free_fft_settings(&fs);
}

void roundtrip_fft(void) {
    // Initialise: arbitrary size
    unsigned int size = 10;
    FFTSettings fs;
    TEST_CHECK(new_fft_settings(&fs, size) == C_KZG_OK);
    blst_p1 expected[fs.max_width], data[fs.max_width], coeffs[fs.max_width];
    make_data(expected, fs.max_width);
    make_data(data, fs.max_width);

    // Forward and reverse FFT
    TEST_CHECK(fft_g1(coeffs, data, false, fs.max_width, &fs) == C_KZG_OK);
    TEST_CHECK(fft_g1(data, coeffs, true, fs.max_width, &fs) == C_KZG_OK);

    // Verify that the result is still ascending values of i
    for (int i = 0; i < fs.max_width; i++) {
        TEST_CHECK(blst_p1_is_equal(expected + i, data + i));
    }

    free_fft_settings(&fs);
}

void stride_fft(void) {
    unsigned int size1 = 9, size2 = 12;
    uint64_t width = size1 < size2 ? (uint64_t)1 << size1 : (uint64_t)1 << size2;
    FFTSettings fs1, fs2;
    TEST_CHECK(new_fft_settings(&fs1, size1) == C_KZG_OK);
    TEST_CHECK(new_fft_settings(&fs2, size2) == C_KZG_OK);
    blst_p1 data[width], coeffs1[width], coeffs2[width];
    make_data(data, width);

    TEST_CHECK(fft_g1(coeffs1, data, false, width, &fs1) == C_KZG_OK);
    TEST_CHECK(fft_g1(coeffs2, data, false, width, &fs2) == C_KZG_OK);

    for (int i = 0; i < width; i++) {
        TEST_CHECK(blst_p1_is_equal(coeffs1 + i, coeffs2 + i));
    }

    free_fft_settings(&fs1);
    free_fft_settings(&fs2);
}

TEST_LIST = {
    {"FFT_G1_TEST", title},
    {"compare_sft_fft", compare_sft_fft},
    {"roundtrip_fft", roundtrip_fft},
    {"stride_fft", stride_fft},
    {NULL, NULL} /* zero record marks the end of the list */
};
