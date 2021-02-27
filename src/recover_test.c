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
#include "recover.h"
#include "fft_fr.h"
#include "debug_util.h"

// Utility for setting a random (len_data - known) number of elements to NULL
void random_missing(fr_t *with_missing, fr_t *data, uint64_t len_data, uint64_t known) {
    uint64_t *missing_idx;
    TEST_CHECK(C_KZG_OK == new_uint64_array(&missing_idx, len_data));
    for (uint64_t i = 0; i < len_data; i++) {
        missing_idx[i] = i;
    }
    shuffle(missing_idx, len_data);

    for (uint64_t i = 0; i < len_data; i++) {
        with_missing[i] = data[i];
    }
    for (uint64_t i = 0; i < len_data - known; i++) {
        with_missing[missing_idx[i]] = fr_null;
    }

    free(missing_idx);
}

void recover_simple(void) {
    FFTSettings fs;
    TEST_CHECK(C_KZG_OK == new_fft_settings(&fs, 2));

    fr_t poly[fs.max_width];
    for (int i = 0; i < fs.max_width / 2; i++) {
        fr_from_uint64(&poly[i], i);
    }
    for (int i = fs.max_width / 2; i < fs.max_width; i++) {
        poly[i] = fr_zero;
    }

    fr_t data[fs.max_width];
    TEST_CHECK(C_KZG_OK == fft_fr(data, poly, false, fs.max_width, &fs));

    fr_t sample[fs.max_width];
    sample[0] = data[0];
    sample[1] = fr_null;
    sample[2] = fr_null;
    sample[3] = data[3];

    fr_t recovered[fs.max_width];
    TEST_CHECK(C_KZG_OK == recover_poly_from_samples(recovered, sample, fs.max_width, &fs));

    // Check recovered data
    for (int i = 0; i < fs.max_width; i++) {
        TEST_CHECK(fr_equal(&data[i], &recovered[i]));
    }

    // Also check against original coefficients
    fr_t back[fs.max_width];
    TEST_CHECK(C_KZG_OK == fft_fr(back, recovered, true, fs.max_width, &fs));
    for (int i = 0; i < fs.max_width / 2; i++) {
        TEST_CHECK(fr_equal(&poly[i], &back[i]));
    }
    for (int i = fs.max_width / 2; i < fs.max_width; i++) {
        TEST_CHECK(fr_is_zero(&back[i]));
    }

    free_fft_settings(&fs);
}

void recover_random(void) {
    FFTSettings fs;
    TEST_CHECK(C_KZG_OK == new_fft_settings(&fs, 12));

    fr_t *poly, *data, *samples, *recovered, *back;
    TEST_CHECK(C_KZG_OK == new_fr_array(&poly, fs.max_width));
    TEST_CHECK(C_KZG_OK == new_fr_array(&data, fs.max_width));
    TEST_CHECK(C_KZG_OK == new_fr_array(&samples, fs.max_width));
    TEST_CHECK(C_KZG_OK == new_fr_array(&recovered, fs.max_width));
    TEST_CHECK(C_KZG_OK == new_fr_array(&back, fs.max_width));

    for (int i = 0; i < fs.max_width / 2; i++) {
        fr_from_uint64(&poly[i], i);
    }
    for (int i = fs.max_width / 2; i < fs.max_width; i++) {
        poly[i] = fr_zero;
    }

    TEST_CHECK(C_KZG_OK == fft_fr(data, poly, false, fs.max_width, &fs));

    // Having half of the data is the minimum
    for (float known_ratio = 0.5; known_ratio < 1.0; known_ratio += 0.05) {
        uint64_t known = fs.max_width * known_ratio;
        for (int i = 0; i < 4; i++) {
            random_missing(samples, data, fs.max_width, known);

            TEST_CHECK(C_KZG_OK == recover_poly_from_samples(recovered, samples, fs.max_width, &fs));
            for (int i = 0; i < fs.max_width; i++) {
                TEST_CHECK(fr_equal(&data[i], &recovered[i]));
            }

            // Also check against original coefficients
            fr_t back[fs.max_width];
            TEST_CHECK(C_KZG_OK == fft_fr(back, recovered, true, fs.max_width, &fs));
            for (int i = 0; i < fs.max_width / 2; i++) {
                TEST_CHECK(fr_equal(&poly[i], &back[i]));
            }
            for (int i = fs.max_width / 2; i < fs.max_width; i++) {
                TEST_CHECK(fr_is_zero(&back[i]));
            }
        }
    }

    free(poly);
    free(data);
    free(samples);
    free(recovered);
    free(back);
    free_fft_settings(&fs);
}

TEST_LIST = {
    {"RECOVER_TEST", title},
    {"recover_simple", recover_simple},
    {"recover_random", recover_random},
    {NULL, NULL} /* zero record marks the end of the list */
};
