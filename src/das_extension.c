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

/**
 * @file das_extension.c
 *
 * Perform polynomial extension for data availability sampling.
 */

#include "control.h"
#include "c_kzg.h"
#include "utility.h"

/**
 * Recursive implementation of #das_fft_extension.
 *
 * @param[in, out] ab     Input: values of the even indices. Output: values of the odd indices (in-place)
 * @param[in]      n      The length of @p ab
 * @param[in]      stride The step length through the roots of unity
 * @param[in]      fs     The FFT settings previously initialised with #new_fft_settings
 */
static void das_fft_extension_stride(fr_t *ab, uint64_t n, uint64_t stride, const FFTSettings *fs) {

    if (n < 2) return;

    if (n == 2) {
        fr_t x, y, tmp;
        fr_add(&x, &ab[0], &ab[1]);
        fr_sub(&y, &ab[0], &ab[1]);
        fr_mul(&tmp, &y, &fs->expanded_roots_of_unity[stride]);
        fr_add(&ab[0], &x, &tmp);
        fr_sub(&ab[1], &x, &tmp);
    } else {
        uint64_t half = n, halfhalf = half / 2;
        fr_t *ab_half_0s = ab;
        fr_t *ab_half_1s = ab + halfhalf;

        // Modify ab_half_* in-place, rather than allocating L0 and L1 arrays.
        // L0[i] = (((a_half0 + a_half1) % modulus) * inv2) % modulus
        // R0[i] = (((a_half0 - L0[i]) % modulus) * inverse_domain[i * 2]) % modulus
        for (uint64_t i = 0; i < halfhalf; i++) {
            fr_t tmp1, tmp2;
            fr_t *a_half_0 = ab_half_0s + i;
            fr_t *a_half_1 = ab_half_1s + i;
            fr_add(&tmp1, a_half_0, a_half_1);
            fr_sub(&tmp2, a_half_0, a_half_1);
            fr_mul(a_half_1, &tmp2, &fs->reverse_roots_of_unity[i * 2 * stride]);
            *a_half_0 = tmp1;
        }

        // Recurse
        das_fft_extension_stride(ab_half_0s, halfhalf, stride * 2, fs);
        das_fft_extension_stride(ab_half_1s, halfhalf, stride * 2, fs);

        // The odd deduced outputs are written to the output array already, but then updated in-place
        // L1 = b[:halfHalf]
        // R1 = b[halfHalf:]

        for (uint64_t i = 0; i < halfhalf; i++) {
            fr_t y_times_root;
            fr_t x = ab_half_0s[i];
            fr_t y = ab_half_1s[i];
            fr_mul(&y_times_root, &y, &fs->expanded_roots_of_unity[(1 + 2 * i) * stride]);
            // write outputs in place, avoid unnecessary list allocations
            fr_add(&ab_half_0s[i], &x, &y_times_root);
            fr_sub(&ab_half_1s[i], &x, &y_times_root);
        }
    }
}

/**
 * Perform polynomial extension for data availability sampling.
 *
 * The input is the even-numbered indices, which is replaced by the odd indices required to make the right half of the
 * coefficients of the inverse FFT of the combined indices zero.
 *
 * @remark The input (even index) values are replace by the output (odd index) values.
 *
 * @param[in, out] vals Input: values of the even indices. Output: values of the odd indices (in place)
 * @param[in]      n    The length of @p vals
 * @param[in]      fs   The FFT settings previously initialised with #new_fft_settings
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 */
C_KZG_RET das_fft_extension(fr_t *vals, uint64_t n, const FFTSettings *fs) {
    fr_t invlen;

    CHECK(n > 0);
    CHECK(is_power_of_two(n));
    CHECK(n * 2 <= fs->max_width);

    das_fft_extension_stride(vals, n, fs->max_width / (n * 2), fs);

    fr_from_uint64(&invlen, n);
    fr_inv(&invlen, &invlen);
    for (uint64_t i = 0; i < n; i++) {
        fr_mul(&vals[i], &vals[i], &invlen);
    }

    return C_KZG_OK;
}

#ifdef KZGTEST

#include "../inc/acutest.h"
#include "c_kzg_alloc.h"
#include "test_util.h"

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

void das_extension_test_random(void) {
    FFTSettings fs;
    fr_t *even_data, *odd_data, *data, *coeffs;
    int max_scale = 15;

    TEST_CHECK(C_KZG_OK == new_fft_settings(&fs, max_scale));
    for (int scale = 1; scale <= max_scale; scale++) {
        uint64_t width = (uint64_t)1 << scale;
        TEST_ASSERT(width <= fs.max_width);
        TEST_CHECK(C_KZG_OK == new_fr_array(&even_data, width / 2));
        TEST_CHECK(C_KZG_OK == new_fr_array(&odd_data, width / 2));
        TEST_CHECK(C_KZG_OK == new_fr_array(&data, width));
        TEST_CHECK(C_KZG_OK == new_fr_array(&coeffs, width));

        for (int rep = 0; rep < 4; rep++) {

            // Make random even data and duplicate temporarily in the odd_data
            for (int i = 0; i < width / 2; i++) {
                even_data[i] = rand_fr();
                odd_data[i] = even_data[i];
            }

            // Extend the even data to create the odd data required to make the second half of the FFT zero
            TEST_CHECK(C_KZG_OK == das_fft_extension(odd_data, width / 2, &fs));

            // Reconstruct the full data
            for (int i = 0; i < width; i += 2) {
                data[i] = even_data[i / 2];
                data[i + 1] = odd_data[i / 2];
            }
            TEST_CHECK(C_KZG_OK == fft_fr(coeffs, data, true, width, &fs));

            // Second half of the coefficients should be all zeros
            for (int i = width / 2; i < width; i++) {
                TEST_CHECK(fr_is_zero(&coeffs[i]));
            }
        }

        free(even_data);
        free(odd_data);
        free(data);
        free(coeffs);
    }
    free_fft_settings(&fs);
}

TEST_LIST = {
    {"DAS_EXTENSION_TEST", title},
    {"das_extension_test_known", das_extension_test_known},
    {"das_extension_test_random", das_extension_test_random},
    {NULL, NULL} /* zero record marks the end of the list */
};

#endif // KZGTEST