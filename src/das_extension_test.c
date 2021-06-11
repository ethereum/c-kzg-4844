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
#include "fft_fr.h"
#include "das_extension.h"

void das_extension_test_known(void) {
    FFTSettings fs;
    uint64_t half;
    fr_t *data;
    // The expected output (from go-kzg):
    const uint64_t expected_u[8][4] = {
        {0xa0c43757db972d7dL, 0x79d15a1e0677962cL, 0xf678865c0c95fa6aL, 0x4e85fd4814f96825L},
        {0xad9f844939f2705dL, 0x319e440c9f3b0325L, 0x4cbd29a60e160a28L, 0x665961d85d90c4c0L},
        {0x5f3ac8a72468d28bL, 0xede949e28383c5d2L, 0xaf6f84dd8708d8c9L, 0x2567aa0b14a41521L},
        {0x25abe312b96aadadL, 0x4abf043f091ff417L, 0x43824b53e09536dbL, 0x195dbe06a28ca227L},
        {0x5f3ac8a72468d28bL, 0xede949e28383c5d2L, 0xaf6f84dd8708d8c9L, 0x2567aa0b14a41521L},
        {0xad9f844939f2705dL, 0x319e440c9f3b0325L, 0x4cbd29a60e160a28L, 0x665961d85d90c4c0L},
        {0xa0c43757db972d7dL, 0x79d15a1e0677962cL, 0xf678865c0c95fa6aL, 0x4e85fd4814f96825L},
        {0x7f171458d2b071a9L, 0xd185bbb2a46cbd9bL, 0xa41aab0d02886e80L, 0x01cacceef58ccee9L}};

    TEST_CHECK(C_KZG_OK == new_fft_settings(&fs, 4));
    half = fs.max_width / 2;

    TEST_CHECK(C_KZG_OK == new_fr_array(&data, half));
    for (uint64_t i = 0; i < half; i++) {
        fr_from_uint64(data + i, i);
    }

    TEST_CHECK(C_KZG_OK == das_fft_extension(data, half, &fs));

    // Check against the expected values
    for (uint64_t i = 0; i < 8; i++) {
        fr_t expected;
        fr_from_uint64s(&expected, expected_u[i]);
        TEST_CHECK(fr_equal(&expected, data + i));
    }

    free(data);
    free_fft_settings(&fs);
}

// Caution: uses random data
void das_extension_test_random(void) {
    FFTSettings fs;
    fr_t *even_data, *odd_data, *data, *coeffs;
    for (int scale = 4; scale < 10; scale++) {
        TEST_CHECK(C_KZG_OK == new_fft_settings(&fs, scale));
        TEST_CHECK(C_KZG_OK == new_fr_array(&even_data, fs.max_width / 2));
        TEST_CHECK(C_KZG_OK == new_fr_array(&odd_data, fs.max_width / 2));
        TEST_CHECK(C_KZG_OK == new_fr_array(&data, fs.max_width));
        TEST_CHECK(C_KZG_OK == new_fr_array(&coeffs, fs.max_width));

        for (int rep = 0; rep < 4; rep++) {

            // Make random input data, and save a copy of it
            for (int i = 0; i < fs.max_width / 2; i++) {
                even_data[i] = rand_fr();
                odd_data[i] = even_data[i];
            }

            // Extend the odd data
            TEST_CHECK(C_KZG_OK == das_fft_extension(odd_data, fs.max_width / 2, &fs));

            // Reconstruct the data
            for (int i = 0; i < fs.max_width; i += 2) {
                data[i] = even_data[i / 2];
                data[i + 1] = odd_data[i / 2];
            }
            TEST_CHECK(C_KZG_OK == fft_fr(coeffs, data, true, fs.max_width, &fs));

            // Second half of the coefficients should be all zeros
            for (int i = fs.max_width / 2; i < fs.max_width; i++) {
                TEST_CHECK(fr_is_zero(&coeffs[i]));
            }
        }

        free(even_data);
        free(odd_data);
        free(data);
        free(coeffs);
        free_fft_settings(&fs);
    }
}

TEST_LIST = {
    {"DAS_EXTENSION_TEST", title},
    {"das_extension_test_known", das_extension_test_known},
    {"das_extension_test_random", das_extension_test_random},
    {NULL, NULL} /* zero record marks the end of the list */
};
