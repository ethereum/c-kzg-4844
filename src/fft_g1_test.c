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
#include "test_util.h"
#include "fft_g1.h"

// The G1 subgroup size minus 1
const uint64_t r_minus_1[] = {0xffffffff00000000L, 0x53bda402fffe5bfeL, 0x3339d80809a1d805L, 0x73eda753299d7d48L};

void make_data(blst_p1 *out, uint64_t n) {
    // Multiples of g1_gen
    assert(n > 0);
    blst_p1_from_affine(out + 0, &BLS12_381_G1);
    for (int i = 1; i < n; i++) {
        blst_p1_add_affine(out + i, out + i - 1, &BLS12_381_G1);
    }
}

void p1_mul_works(void) {
    blst_fr rm1;
    blst_p1 g1_gen, g1_gen_neg, res;

    // Multiply the generator by the group order minus one
    blst_p1_from_affine(&g1_gen, &BLS12_381_G1);
    blst_fr_from_uint64(&rm1, r_minus_1);
    p1_mul(&res, &g1_gen, &rm1);

    // We should end up with negative the generator
    blst_p1_from_affine(&g1_gen_neg, &BLS12_381_NEG_G1);

    TEST_CHECK(blst_p1_is_equal(&res, &g1_gen_neg));
}

void p1_sub_works(void) {
    blst_p1 g1_gen, g1_gen_neg;
    blst_p1 tmp, res;

    blst_p1_from_affine(&g1_gen, &BLS12_381_G1);
    blst_p1_from_affine(&g1_gen_neg, &BLS12_381_NEG_G1);

    // 2 * g1_gen = g1_gen - g1_gen_neg
    blst_p1_double(&tmp, &g1_gen);
    p1_sub(&res, &g1_gen, &g1_gen_neg);

    TEST_CHECK(blst_p1_is_equal(&tmp, &res));
}

void compare_sft_fft(void) {
    // Initialise: arbitrary size
    unsigned int size = 6;
    FFTSettings fs = new_fft_settings(size);
    blst_p1 data[fs.max_width], slow[fs.max_width], fast[fs.max_width];
    make_data(data, fs.max_width);
    
    // Do both fast and slow transforms
    fft_g1_slow(slow, data, 1, fs.expanded_roots_of_unity, 1, fs.max_width);
    fft_g1_fast(fast, data, 1, fs.expanded_roots_of_unity, 1, fs.max_width);

    // Verify the results are identical
    for (int i = 0; i < fs.max_width; i++) {
        TEST_CHECK(blst_p1_is_equal(slow + i, fast + i));
    }

    free_fft_settings(&fs);
}

void roundtrip_fft(void) {
    // Initialise: arbitrary size
    unsigned int size = 10;
    FFTSettings fs = new_fft_settings(size);
    blst_p1 expected[fs.max_width], data[fs.max_width], coeffs[fs.max_width];
    make_data(expected, fs.max_width);
    make_data(data, fs.max_width);
    
    // Forward and reverse FFT
    fft_g1(coeffs, data, &fs, false, fs.max_width);
    fft_g1(data, coeffs, &fs, true, fs.max_width);

    // Verify that the result is still ascending values of i
    for (int i = 0; i < fs.max_width; i++) {
        TEST_CHECK(blst_p1_is_equal(expected + i, data + i));
    }

    free_fft_settings(&fs);
}

TEST_LIST =
    {
     {"p1_mul_works", p1_mul_works},
     {"p1_sub_works", p1_sub_works},
     {"compare_sft_fft", compare_sft_fft},
     {"roundtrip_fft", roundtrip_fft},
     { NULL, NULL }     /* zero record marks the end of the list */
    };
