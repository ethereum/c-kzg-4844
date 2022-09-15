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
 * @file fft_g1.c
 *
 * Discrete fourier transforms over arrays of G1 group elements.
 *
 * Also known as [number theoretic
 * transforms](https://en.wikipedia.org/wiki/Discrete_Fourier_transform_(general)#Number-theoretic_transform).
 *
 * @remark Functions here work only for lengths that are a power of two.
 */

#include "control.h"
#include "c_kzg.h"
#include "utility.h"

/**
 * Fast Fourier Transform.
 *
 * Recursively divide and conquer.
 *
 * @param[out] out    The results (array of length @p n)
 * @param[in]  in     The input data (array of length @p n * @p stride)
 * @param[in]  stride The input data stride
 * @param[in]  roots  Roots of unity (array of length @p n * @p roots_stride)
 * @param[in]  roots_stride The stride interval among the roots of unity
 * @param[in]  n      Length of the FFT, must be a power of two
 */
static void fft_g1_fast(g1_t *out, const g1_t *in, uint64_t stride, const fr_t *roots, uint64_t roots_stride,
                        uint64_t n) {
    uint64_t half = n / 2;
    if (half > 0) { // Tunable parameter
        fft_g1_fast(out, in, stride * 2, roots, roots_stride * 2, half);
        fft_g1_fast(out + half, in + stride, stride * 2, roots, roots_stride * 2, half);
        for (uint64_t i = 0; i < half; i++) {
            g1_t y_times_root;
            g1_mul(&y_times_root, &out[i + half], &roots[i * roots_stride]);
            g1_sub(&out[i + half], &out[i], &y_times_root);
            g1_add_or_dbl(&out[i], &out[i], &y_times_root);
        }
    } else {
        *out = *in;
    }
}

/**
 * The main entry point for forward and reverse FFTs over the finite field.
 *
 * @param[out] out     The results (array of length @p n)
 * @param[in]  in      The input data (array of length @p n)
 * @param[in]  inverse `false` for forward transform, `true` for inverse transform
 * @param[in]  n       Length of the FFT, must be a power of two
 * @param[in]  fs      Pointer to previously initialised FFTSettings structure with `max_width` at least @p n.
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 */
C_KZG_RET fft_g1(g1_t *out, const g1_t *in, bool inverse, uint64_t n, const FFTSettings *fs) {
    uint64_t stride = fs->max_width / n;
    CHECK(n <= fs->max_width);
    CHECK(is_power_of_two(n));
    if (inverse) {
        fr_t inv_len;
        fr_from_uint64(&inv_len, n);
        fr_inv(&inv_len, &inv_len);
        fft_g1_fast(out, in, 1, fs->reverse_roots_of_unity, stride, n);
        for (uint64_t i = 0; i < n; i++) {
            g1_mul(&out[i], &out[i], &inv_len);
        }
    } else {
        fft_g1_fast(out, in, 1, fs->expanded_roots_of_unity, stride, n);
    }
    return C_KZG_OK;
}

#ifdef KZGTEST

#include "../inc/acutest.h"
#include "test_util.h"

static void make_data(g1_t *out, uint64_t n) {
    // Multiples of g1_gen
    if (n == 0) return;
    *out = g1_generator;
    for (int i = 1; i < n; i++) {
        g1_add_or_dbl(out + i, out + i - 1, &g1_generator);
    }
}

/**
 * Slow Fourier Transform.
 *
 * This is simple, and ok for small sizes. It's mostly useful for testing.
 *
 * @param[out] out    The results (array of length @p n)
 * @param[in]  in     The input data (array of length @p n * @p stride)
 * @param[in]  stride The input data stride
 * @param[in]  roots  Roots of unity (array of length @p n * @p roots_stride)
 * @param[in]  roots_stride The stride interval among the roots of unity
 * @param[in]  n      Length of the FFT, must be a power of two
 */
static void fft_g1_slow(g1_t *out, const g1_t *in, uint64_t stride, const fr_t *roots, uint64_t roots_stride,
                        uint64_t n) {
    g1_t v, last, jv;
    fr_t r;
    for (uint64_t i = 0; i < n; i++) {
        g1_mul(&last, &in[0], &roots[0]);
        for (uint64_t j = 1; j < n; j++) {
            jv = in[j * stride];
            r = roots[((i * j) % n) * roots_stride];
            g1_mul(&v, &jv, &r);
            g1_add_or_dbl(&last, &last, &v);
        }
        out[i] = last;
    }
}

void compare_sft_fft(void) {
    // Initialise: arbitrary size
    unsigned int size = 6;
    FFTSettings fs;
    TEST_CHECK(new_fft_settings(&fs, size) == C_KZG_OK);
    g1_t data[fs.max_width], slow[fs.max_width], fast[fs.max_width];
    make_data(data, fs.max_width);

    // Do both fast and slow transforms
    fft_g1_slow(slow, data, 1, fs.expanded_roots_of_unity, 1, fs.max_width);
    fft_g1_fast(fast, data, 1, fs.expanded_roots_of_unity, 1, fs.max_width);

    // Verify the results are identical
    for (int i = 0; i < fs.max_width; i++) {
        TEST_CHECK(g1_equal(slow + i, fast + i));
    }

    free_fft_settings(&fs);
}

void roundtrip_fft(void) {
    // Initialise: arbitrary size
    unsigned int size = 10;
    FFTSettings fs;
    TEST_CHECK(new_fft_settings(&fs, size) == C_KZG_OK);
    g1_t expected[fs.max_width], data[fs.max_width], coeffs[fs.max_width];
    make_data(expected, fs.max_width);
    make_data(data, fs.max_width);

    // Forward and reverse FFT
    TEST_CHECK(fft_g1(coeffs, data, false, fs.max_width, &fs) == C_KZG_OK);
    TEST_CHECK(fft_g1(data, coeffs, true, fs.max_width, &fs) == C_KZG_OK);

    // Verify that the result is still ascending values of i
    for (int i = 0; i < fs.max_width; i++) {
        TEST_CHECK(g1_equal(expected + i, data + i));
    }

    free_fft_settings(&fs);
}

void stride_fft(void) {
    unsigned int size1 = 9, size2 = 12;
    uint64_t width = size1 < size2 ? (uint64_t)1 << size1 : (uint64_t)1 << size2;
    FFTSettings fs1, fs2;
    TEST_CHECK(new_fft_settings(&fs1, size1) == C_KZG_OK);
    TEST_CHECK(new_fft_settings(&fs2, size2) == C_KZG_OK);
    g1_t data[width], coeffs1[width], coeffs2[width];
    make_data(data, width);

    TEST_CHECK(fft_g1(coeffs1, data, false, width, &fs1) == C_KZG_OK);
    TEST_CHECK(fft_g1(coeffs2, data, false, width, &fs2) == C_KZG_OK);

    for (int i = 0; i < width; i++) {
        TEST_CHECK(g1_equal(coeffs1 + i, coeffs2 + i));
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

#endif // KZGTEST
