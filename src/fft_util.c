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

#include "fft_util.h"

bool is_one(const blst_fr *fr_p) {
    uint64_t a[4];
    blst_uint64_from_fr(a, fr_p);
    return a[0] == 1 && a[1] == 0 && a[2] == 0 && a[3] == 0;
}

bool is_power_of_two(uint64_t n) {
    return (n & (n - 1)) == 0;
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
