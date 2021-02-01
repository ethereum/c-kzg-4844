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

void print_bytes_as_hex_le(byte *bytes, int start, int len) {
    for (int i = start + len - 1; i >= start; i--) {
        printf("%02x", bytes[i]);
    }
}

void print_fr(const blst_fr *a) {
    blst_scalar b;
    blst_scalar_from_fr(&b, a);
    print_bytes_as_hex_le(b.b, 0, 32);
}

bool is_one(const blst_fr *fr_p) {
    uint64_t a[4];
    blst_uint64_from_fr(a, fr_p);
    return a[0] == 1 && a[1] == 0 && a[2] == 0 && a[3] == 0;
}

bool is_power_of_two(uint64_t n) {
    return (n & (n - 1)) == 0;
}

bool fr_equal(blst_fr *aa, blst_fr *bb) {
    uint64_t a[4], b[4];
    blst_uint64_from_fr(a, aa);
    blst_uint64_from_fr(b, bb);
    return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3];
}

void fr_from_uint64(blst_fr *a, uint64_t n) {
    uint64_t vals[] = {n, 0, 0, 0};
    blst_fr_from_uint64(a, vals);
}

// Returns an array of powers of the root of unity
// Allocates space for the array that needs to be freed later
blst_fr *expand_root_of_unity(blst_fr *root_of_unity, uint64_t width) {
    blst_fr *roots = malloc((width + 1) * sizeof(blst_fr));
    roots[0] = one;
    roots[1] = *root_of_unity;

    for (int i = 2; !is_one(&roots[i - 1]); i++) {
        assert(i <= width);
        blst_fr_mul(&roots[i], &roots[i - 1], root_of_unity);
    }
    assert(is_one(&roots[width]));

    return roots;
}

// Return a reversed copy of the list of Fr provided
// `width` is one less than the length of `r`
// Allocates space for the array that needs to be freed later
blst_fr *reverse(blst_fr *r, uint64_t width) {
   blst_fr *rr = malloc((width + 1) * sizeof(blst_fr));
   for (int i = 0; i <= width; i++) {
       rr[i] = r[width - i];
   }
   return rr;
}

FFTSettings new_fft_settings(unsigned int max_scale) {
    FFTSettings s;
    s.max_width = (uint64_t)1 << max_scale;
    blst_fr_from_uint64(&s.root_of_unity, scale2_root_of_unity[max_scale]);
    s.expanded_roots_of_unity = expand_root_of_unity(&s.root_of_unity, s.max_width);
    s.reverse_roots_of_unity = reverse(s.expanded_roots_of_unity, s.max_width);
    return s;
}

void free_fft_settings(FFTSettings *s) {
    free(s->expanded_roots_of_unity);
    free(s->reverse_roots_of_unity);
}

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
