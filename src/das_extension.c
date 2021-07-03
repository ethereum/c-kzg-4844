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

#include "das_extension.h"
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