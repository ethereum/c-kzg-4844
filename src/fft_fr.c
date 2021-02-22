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
 * @file fft_fr.c
 *
 * Discrete fourier transforms over arrays of field elements.
 *
 * Also known as [number theoretic
 * transforms](https://en.wikipedia.org/wiki/Discrete_Fourier_transform_(general)#Number-theoretic_transform).
 *
 * @remark Functions here work only for lengths that are a power of two.
 */

#include "fft_fr.h"
#include "c_kzg_util.h"
#include "utility.h"

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
void fft_fr_slow(fr_t *out, const fr_t *in, uint64_t stride, const fr_t *roots, uint64_t roots_stride, uint64_t n) {
    fr_t v, last, jv, r;
    for (uint64_t i = 0; i < n; i++) {
        fr_mul(&last, &in[0], &roots[0]);
        for (uint64_t j = 1; j < n; j++) {
            jv = in[j * stride];
            r = roots[((i * j) % n) * roots_stride];
            fr_mul(&v, &jv, &r);
            fr_add(&last, &last, &v);
        }
        out[i] = last;
    }
}

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
void fft_fr_fast(fr_t *out, const fr_t *in, uint64_t stride, const fr_t *roots, uint64_t roots_stride, uint64_t n) {
    uint64_t half = n / 2;
    if (half > 0) { // Tunable parameter
        fft_fr_fast(out, in, stride * 2, roots, roots_stride * 2, half);
        fft_fr_fast(out + half, in + stride, stride * 2, roots, roots_stride * 2, half);
        for (uint64_t i = 0; i < half; i++) {
            fr_t y_times_root;
            fr_mul(&y_times_root, &out[i + half], &roots[i * roots_stride]);
            fr_sub(&out[i + half], &out[i], &y_times_root);
            fr_add(&out[i], &out[i], &y_times_root);
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
C_KZG_RET fft_fr(fr_t *out, const fr_t *in, bool inverse, uint64_t n, const FFTSettings *fs) {
    uint64_t stride = fs->max_width / n;
    CHECK(n <= fs->max_width);
    CHECK(is_power_of_two(n));
    if (inverse) {
        fr_t inv_len;
        fr_from_uint64(&inv_len, n);
        fr_inv(&inv_len, &inv_len);
        fft_fr_fast(out, in, 1, fs->reverse_roots_of_unity, stride, n);
        for (uint64_t i = 0; i < n; i++) {
            fr_mul(&out[i], &out[i], &inv_len);
        }
    } else {
        fft_fr_fast(out, in, 1, fs->expanded_roots_of_unity, stride, n);
    }
    return C_KZG_OK;
}

/**
 * Perform an in-place FFT by copying the results over the input.
 *
 * @remark This is almost as fast as #fft_fr. It is slower than #fft_fr_in_place_lomem, but, unlike that routine,
 * allocates a extra array the same size as the input data to copy the results.
 *
 * @param[in,out] data    The input data and output results (array of length @p n)
 * @param[in]     inverse `false` for forward transform, `true` for inverse transform
 * @param[in]     n       Length of the FFT, must be a power of two
 * @param[in]     fs      Pointer to previously initialised FFTSettings structure with `max_width` at least @p n.
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET fft_fr_in_place(fr_t *data, bool inverse, uint64_t n, const FFTSettings *fs) {
    fr_t *out;
    CHECK(n <= fs->max_width);
    CHECK(is_power_of_two(n));
    TRY(new_fr_array(&out, fs->max_width));
    TRY(fft_fr(out, data, inverse, n, fs));
    for (uint64_t i = 0; i < n; i++) {
        data[i] = out[i];
    }
    free(out);
    return C_KZG_OK;
}

/**
 * Perform an in-place FFT without allocating any extra memory.
 *
 * @remark This is about 25% slower than #fft_fr_in_place, but does not allocate any extra memory, whereas that routine
 * has a memory overhead the same size as the input array.
 *
 * @param[in,out] data    The input data and output results (array of length @p n)
 * @param[in]     inverse `false` for forward transform, `true` for inverse transform
 * @param[in]     n       Length of the FFT, must be a power of two
 * @param[in]     fs      Pointer to previously initialised FFTSettings structure with `max_width` at least @p n.
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 */
C_KZG_RET fft_fr_in_place_lomem(fr_t *data, bool inverse, uint64_t n, const FFTSettings *fs) {
    uint64_t stride = fs->max_width / n;
    CHECK(n <= fs->max_width);
    CHECK(is_power_of_two(n));

    fr_t *roots = inverse ? fs->reverse_roots_of_unity : fs->expanded_roots_of_unity;

    reverse_bit_order(data, sizeof data[0], n);

    uint64_t m = 1;
    while (m < n) {
        m <<= 1;
        for (uint64_t k = 0; k < n; k += m) {
            for (uint64_t j = 0; j < m / 2; j++) {
                fr_t t, w = roots[j * stride * n / m];
                fr_mul(&t, &w, &data[k + j + m / 2]);
                fr_sub(&data[k + j + m / 2], &data[k + j], &t);
                fr_add(&data[k + j], &data[k + j], &t);
            }
        }
    }

    if (inverse) {
        fr_t inv_len;
        fr_from_uint64(&inv_len, n);
        fr_inv(&inv_len, &inv_len);
        for (uint64_t i = 0; i < n; i++) {
            fr_mul(&data[i], &data[i], &inv_len);
        }
    }

    return C_KZG_OK;
}
