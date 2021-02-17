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
        {0x740e9eb4cef44b7fL, 0xb66dfe6438d1316aL, 0xc62c567f7b9c5e97L, 0x5a4f75d3eb7951c4L},
        {0x52617bb5c60d8fabL, 0x0e225ff8d6c658d9L, 0x73ce7b30718ed2aeL, 0x0d94457acc0cb888L},
        {0x8bf0614a310bb489L, 0xb14ca59c512a2a94L, 0xdfbbb4ba1802749cL, 0x199e317f3e242b82L},
        {0x98cbae3b8f66f769L, 0x69198f8ae9ed978dL, 0x360058041982845aL, 0x3171960f86bb881dL},
        {0x8bf0614a310bb489L, 0xb14ca59c512a2a94L, 0xdfbbb4ba1802749cL, 0x199e317f3e242b82L},
        {0x52617bb5c60d8fabL, 0x0e225ff8d6c658d9L, 0x73ce7b30718ed2aeL, 0x0d94457acc0cb888L},
        {0x740e9eb4cef44b7fL, 0xb66dfe6438d1316aL, 0xc62c567f7b9c5e97L, 0x5a4f75d3eb7951c4L},
        {0xc2735a57e47de950L, 0xa665548b548a12beL, 0x3040233ff907b7f0L, 0x2753864e0ac8841bL}};

    TEST_CHECK(C_KZG_OK == new_fft_settings(&fs, 4));
    half = fs.max_width / 2;

    TEST_CHECK(C_KZG_OK == new_fr(&data, half));
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
        TEST_CHECK(C_KZG_OK == new_fr(&even_data, fs.max_width / 2));
        TEST_CHECK(C_KZG_OK == new_fr(&odd_data, fs.max_width / 2));
        TEST_CHECK(C_KZG_OK == new_fr(&data, fs.max_width));
        TEST_CHECK(C_KZG_OK == new_fr(&coeffs, fs.max_width));

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
