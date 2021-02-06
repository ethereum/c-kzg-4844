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

#include "fft_fr.h"
#include "blst_util.h"

// Slow Fourier Transform (simple, good for small sizes)
void fft_fr_slow(blst_fr *out, const blst_fr *in, uint64_t stride, const blst_fr *roots, uint64_t roots_stride, uint64_t l) {
    blst_fr v, last, jv, r;
    for (uint64_t i = 0; i < l; i++) {
        blst_fr_mul(&last, &in[0], &roots[0]);
        for (uint64_t j = 1; j < l; j++) {
            jv = in[j * stride];
            r = roots[((i * j) % l) * roots_stride];
            blst_fr_mul(&v, &jv, &r);
            blst_fr_add(&last, &last, &v);
        }
        out[i] = last;
    }
}

// Fast Fourier Transform
void fft_fr_fast(blst_fr *out, const blst_fr *in, uint64_t stride, const blst_fr *roots, uint64_t roots_stride, uint64_t l) {
    uint64_t half = l / 2;
    if (half > 2) { // TODO: Tunable parameter
        fft_fr_fast(out,        in,          stride * 2, roots, roots_stride * 2, half);
        fft_fr_fast(out + half, in + stride, stride * 2, roots, roots_stride * 2, half);
        for (uint64_t i = 0; i < half; i++) {
            blst_fr y_times_root;
            blst_fr_mul(&y_times_root, &out[i + half], &roots[i * roots_stride]);
            blst_fr_sub(&out[i + half], &out[i], &y_times_root);
            blst_fr_add(&out[i], &out[i], &y_times_root);
        }
    } else {
        fft_fr_slow(out, in, stride, roots, roots_stride, l);
    }
}

// The main entry point for forward and reverse FFTs
C_KZG_RET fft_fr (blst_fr *out, const blst_fr *in, const FFTSettings *fs, bool inv, uint64_t n) {
    uint64_t stride = fs->max_width / n;
    ASSERT(n <= fs->max_width, C_KZG_BADARGS);
    ASSERT(is_power_of_two(n), C_KZG_BADARGS);
    if (inv) {
        blst_fr inv_len;
        fr_from_uint64(&inv_len, n);
        blst_fr_eucl_inverse(&inv_len, &inv_len);
        fft_fr_fast(out, in, 1, fs->reverse_roots_of_unity, stride, fs->max_width);
        for (uint64_t i = 0; i < fs->max_width; i++) {
            blst_fr_mul(&out[i], &out[i], &inv_len);
        }
    } else {
        fft_fr_fast(out, in, 1, fs->expanded_roots_of_unity, stride, fs->max_width);
    }
    return C_KZG_OK;
}
