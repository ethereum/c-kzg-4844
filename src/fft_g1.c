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

#include "fft_g1.h"
#include "test_util.h"

void p1_mul(blst_p1 *out, const blst_p1 *a, const blst_fr *b) {
    blst_scalar s;
    blst_scalar_from_fr(&s, b);
    blst_p1_mult(out, a, s.b, 8 * sizeof(blst_scalar));
}

void p1_sub(blst_p1 *out, const blst_p1 *a, const blst_p1 *b) {
    blst_p1 bneg = *b;
    blst_p1_cneg(&bneg, true);
    blst_p1_add_or_double(out, a, &bneg);
}

// Slow Fourier Transform (simple, good for small sizes)
void fft_g1_slow(blst_p1 *out, blst_p1 *in, uint64_t stride, blst_fr *roots, uint64_t roots_stride, uint64_t l) {
    blst_p1 v, last, jv;
    blst_fr r;
    for (uint64_t i = 0; i < l; i++) {
        p1_mul(&last, &in[0], &roots[0]);
        for (uint64_t j = 1; j < l; j++) {
            jv = in[j * stride];
            r = roots[((i * j) % l) * roots_stride];
            p1_mul(&v, &jv, &r);
            blst_p1_add_or_double(&last, &last, &v);
        }
        out[i] = last;
    }
}

// Fast Fourier Transform
void fft_g1_fast(blst_p1 *out, blst_p1 *in, uint64_t stride, blst_fr *roots, uint64_t roots_stride, uint64_t l) {
    uint64_t half = l / 2;
    if (half > 0) {
        fft_g1_helper(out,        in,          stride * 2, roots, roots_stride * 2, half);
        fft_g1_helper(out + half, in + stride, stride * 2, roots, roots_stride * 2, half);
        for (uint64_t i = 0; i < half; i++) {
            blst_p1 y_times_root;
            blst_p1 x = out[i];
            p1_mul(&y_times_root, &out[i + half], &roots[i * roots_stride]);
            blst_p1_add_or_double(&out[i], &x, &y_times_root);
            p1_sub(&out[i + half], &x, &y_times_root);
        }
    } else {
        p1_mul(out, in, roots);
    }
}

void fft_g1_helper(blst_p1 *out, blst_p1 *in, uint64_t stride, blst_fr *roots, uint64_t roots_stride, uint64_t l) {
    if (l <= 4) { // TODO: Tunable parameter
        fft_g1_slow(out, in, stride, roots, roots_stride, l);
    } else {
        fft_g1_fast(out, in, stride, roots, roots_stride, l);
    }
}

// The main entry point for forward and reverse FFTs
void fft_g1 (blst_p1 *out, blst_p1 *in, FFTSettings *fs, bool inv, uint64_t n) {
    uint64_t stride = fs->max_width / n;
    assert(n <= fs->max_width);
    assert(is_power_of_two(n));
    if (inv) {
        blst_fr inv_len;
        fr_from_uint64(&inv_len, n);
        blst_fr_eucl_inverse(&inv_len, &inv_len);
        fft_g1_helper(out, in, 1, fs->reverse_roots_of_unity, stride, fs->max_width);
        for (uint64_t i = 0; i < fs->max_width; i++) {
            p1_mul(&out[i], &out[i], &inv_len);
        }
    } else {
        fft_g1_helper(out, in, 1, fs->expanded_roots_of_unity, stride, fs->max_width);
    }
}
