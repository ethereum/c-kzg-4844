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

// Slow Fourier Transform (simple, good for small sizes)
void slow_ft(blst_fr *out, blst_fr *in, uint64_t offset, uint64_t stride, blst_fr *roots, uint64_t roots_stride, uint64_t l) {
    blst_fr v, last, tmp;
    for (uint64_t i = 0; i < l; i++) {
        blst_fr jv = in[offset];
        blst_fr r = roots[0];
        blst_fr_mul(&v, &jv, &r);
        last = v;
        for (uint64_t j = 1; j < l; j++) {
            jv = in[offset + j * stride];
            r = roots[((i * j) % l) * roots_stride];
            blst_fr_mul(&v, &jv, &r);
            tmp = last;
            blst_fr_add(&last, &tmp, &v);
        }
        out[i] = last;
    }
}

// Fast Fourier Transform
void fast_ft(blst_fr *out, blst_fr *in, uint64_t offset, uint64_t stride, blst_fr *roots, uint64_t roots_stride, uint64_t l) {
    uint64_t half = l / 2;
    fft_helper(out, in, offset, stride * 2, roots, roots_stride * 2, l / 2);
    fft_helper(out + half, in, offset + stride, stride * 2, roots, roots_stride * 2, l / 2);
    for (uint64_t i = 0; i < half; i++) {
        blst_fr y_times_root;
        blst_fr x = out[i];
        blst_fr_mul(&y_times_root, &out[i + half], &roots[i * roots_stride]);
        blst_fr_add(&out[i], &x, &y_times_root);
        blst_fr_sub(&out[i + half], &x, &y_times_root);
    }
}

void fft_helper(blst_fr *out, blst_fr *in, uint64_t offset, uint64_t stride, blst_fr *roots, uint64_t roots_stride, uint64_t l) {
    // TODO: Tunable parameter
    if (l <= 4) {
        slow_ft(out, in, offset, stride, roots, roots_stride, l);
    } else {
        fast_ft(out, in, offset, stride, roots, roots_stride, l);
    }
}

// The main entry point for forward and reverse FFTs
void fft (blst_fr *out, blst_fr *in, FFTSettings *fs, bool inv, uint64_t n) {
    uint64_t stride = fs->max_width / n;
    assert(n <= fs->max_width);
    assert(is_power_of_two(n));
    if (inv) {
        blst_fr inv_len;
        fr_from_uint64(&inv_len, n);
        blst_fr_eucl_inverse(&inv_len, &inv_len);
        fft_helper(out, in, 0, 1, fs->reverse_roots_of_unity, stride, fs->max_width);
        for (uint64_t i = 0; i < fs->max_width; i++) {
            blst_fr_mul(&out[i], &out[i], &inv_len);
        }
    } else {
        fft_helper(out, in, 0, 1, fs->expanded_roots_of_unity, stride, fs->max_width);
    }
}
