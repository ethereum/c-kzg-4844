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
#include "fft_fr.h"

#define NUM_ROOTS 32

const uint64_t inv_fft_expected[][4] =
    {
     {0x7fffffff80000008L, 0xa9ded2017fff2dffL, 0x199cec0404d0ec02L, 0x39f6d3a994cebea4L},
     {0x27325dd08ac4cee9L, 0xcbb94f168ddacca9L, 0x6843be68485784b1L, 0x5a6faf9039451673L},
     {0x16d00224dcf9382cL, 0xfee079062d1eaa93L, 0x3ce49204a2235046L, 0x163147176461030eL},
     {0x10d6917f04735deaL, 0x7e04a13731049a48L, 0x42cbd9ab89d7b1f7L, 0x60546bd624850b42L},
     {0x80007fff80000000L, 0x1fe05202bb00adffL, 0x6045d26b3fd26e6bL, 0x39f6d3a994cebea4L},
     {0xe3388d354a80ed91L, 0x5849af2fc2cd4521L, 0xe3a64f3f31971b0bL, 0x33f1dda75bc30526L},
     {0x16cf0224dcf9382cL, 0x12dd7903b71baa93L, 0xaf92c5362c204b76L, 0x163147176461030dL},
     {0xf9925986d0d25e90L, 0xcdf85d0a339d7782L, 0xee7a9a5f0410e423L, 0x2e0d216170831056L},
     {0x7fffffff80000000L, 0xa9ded2017fff2dffL, 0x199cec0404d0ec02L, 0x39f6d3a994cebea4L},
     {0x066da6782f2da170L, 0x85c546f8cc60e47cL, 0x44bf3da90590f3e1L, 0x45e085f1b91a6cf1L},
     {0xe930fdda2306c7d4L, 0x40e02aff48e2b16bL, 0x83a712d1dd818c8fL, 0x5dbc603bc53c7a3aL},
     {0x1cc772c9b57f126fL, 0xfb73f4d33d3116ddL, 0x4f9388c8d80abcf9L, 0x3ffbc9abcdda7821L},
     {0x7fff7fff80000000L, 0x33dd520044fdadffL, 0xd2f4059cc9cf699aL, 0x39f6d3a994cebea3L},
     {0xef296e7ffb8ca216L, 0xd5b902cbcef9c1b6L, 0xf06dfe5c7fca260dL, 0x13993b7d05187205L},
     {0xe92ffdda2306c7d4L, 0x54dd2afcd2dfb16bL, 0xf6554603677e87beL, 0x5dbc603bc53c7a39L},
     {0xd8cda22e753b3117L, 0x880454ec72238f55L, 0xcaf6199fc14a5353L, 0x197df7c2f05866d4L}
    };

void is_one_works(void) {
    TEST_CHECK(true == is_one(&one));
}

void roots_of_unity_is_the_expected_size(void) {
    TEST_CHECK(NUM_ROOTS ==
               sizeof(scale2_root_of_unity) / sizeof(scale2_root_of_unity[0]));
}

void roots_of_unity_are_plausible(void) {
    blst_fr r;
    for (unsigned int i = 0; i < NUM_ROOTS; i++) {
        blst_fr_from_uint64(&r, scale2_root_of_unity[i]);
        for (unsigned int j = 0; j < i; j++) {
            blst_fr_sqr(&r, &r);
        }
        TEST_CHECK(true == is_one(&r));
        TEST_MSG("Root %d failed", i);
    }
}

void reverse_works(void) {
    int n = 24;
    blst_fr arr[n + 1];
    blst_fr *rev, diff;

    // Initialise - increasing values
    arr[0] = one;
    for (int i = 1; i <= n; i++) {
        blst_fr_add(arr + i, arr + i - 1, &one);
    }

    // Reverse
    rev = reverse(arr, n);

    // Verify - decreasing values
    for (int i = 0; i < n; i++) {
        blst_fr_sub(&diff, rev + i, rev + i + 1);
        TEST_CHECK(true == is_one(&diff));
    }
    TEST_CHECK(true == is_one(rev + n));

    free(rev);
}

void expand_roots_is_plausible(void) {
    // Just test one (largeish) value of scale
    unsigned int scale = 20;
    unsigned int width = 1 << scale;
    blst_fr root, *expanded, prod;

    // Initialise
    blst_fr_from_uint64(&root, scale2_root_of_unity[scale]);
    expanded = expand_root_of_unity(&root, width);

    // Verify - each pair should multiply to one
    TEST_CHECK(true == is_one(expanded + 0));
    TEST_CHECK(true == is_one(expanded + width));
    for (unsigned int i = 1; i <= width / 2; i++) {
        blst_fr_mul(&prod, expanded + i, expanded + width - i);
        TEST_CHECK(true == is_one(&prod));
    }

    free(expanded);
}

void new_fft_settings_is_plausible(void) {
    // Just test one (largeish) value of scale
    unsigned int scale = 21;
    unsigned int width = 1 << scale;
    blst_fr prod;
    FFTSettings s = new_fft_settings(scale);

    // Verify - each pair should multiply to one
    for (unsigned int i = 1; i <= width; i++) {
        blst_fr_mul(&prod, s.expanded_roots_of_unity + i, s.reverse_roots_of_unity + i);
        TEST_CHECK(true == is_one(&prod));
    }

    free_fft_settings(&s);
}

void is_power_of_two_works(void) {
    // All actual powers of two
    for (int i = 0; i <=63; i++) {
        TEST_CHECK(true == is_power_of_two((uint64_t)1 << i));
        TEST_MSG("Case %d", i);
    }

    // This is a bit weird
    TEST_CHECK(true == is_power_of_two(0));

    // Not powers of two
    TEST_CHECK(false == is_power_of_two(123));
    TEST_CHECK(false == is_power_of_two(1234567));
}

void fr_from_uint64_works(void) {
    blst_fr a;
    fr_from_uint64(&a, 1);
    TEST_CHECK(true == is_one(&a));
}

void fr_equal_works(void) {
    blst_fr a, b;
    blst_fr_from_uint64(&a, scale2_root_of_unity[15]);
    blst_fr_from_uint64(&b, scale2_root_of_unity[16]);
    TEST_CHECK(true == fr_equal(&a, &a));
    TEST_CHECK(false == fr_equal(&a, &b));
}

void compare_sft_fft(void) {
    // Initialise: ascending values of i (could be anything), and arbitrary size
    unsigned int size = 8;
    FFTSettings fs = new_fft_settings(size);
    blst_fr data[fs.max_width], out0[fs.max_width], out1[fs.max_width];
    for (int i = 0; i < fs.max_width; i++) {
        fr_from_uint64(data + i, i);
    }

    // Do both fast and slow transforms
    slow_ft(out0, data, 0, 1, fs.expanded_roots_of_unity, 1, fs.max_width);
    fast_ft(out1, data, 0, 1, fs.expanded_roots_of_unity, 1, fs.max_width);

    // Verify the results are identical
    for (int i = 0; i < fs.max_width; i++) {
        TEST_CHECK(fr_equal(out0 + i, out1 + i));
    }

    free_fft_settings(&fs);
}

void roundtrip_fft(void) {
    // Initialise: ascending values of i, and arbitrary size
    unsigned int size = 12;
    FFTSettings fs = new_fft_settings(size);
    blst_fr data[fs.max_width], coeffs[fs.max_width];
    for (int i = 0; i < fs.max_width; i++) {
        fr_from_uint64(data + i, i);
    }

    // Forward and reverse FFT
    fft(coeffs, data, &fs, false, fs.max_width);
    fft(data, coeffs, &fs, true, fs.max_width);

    // Verify that the result is still ascending values of i
    for (int i = 0; i < fs.max_width; i++) {
        blst_fr tmp;
        fr_from_uint64(&tmp, i);
        TEST_CHECK(fr_equal(&tmp, data + i));
    }

    free_fft_settings(&fs);
}

void inverse_fft(void) {
    // Initialise: ascending values of i
    FFTSettings fs = new_fft_settings(4);
    blst_fr data[fs.max_width], out[fs.max_width];
    for (int i = 0; i < fs.max_width; i++) {
        fr_from_uint64(&data[i], i);
    }

    // Inverst FFT
    fft(out, data, &fs, true, fs.max_width);

    // Verify against the known result, `inv_fft_expected`
    int n = sizeof(inv_fft_expected) / sizeof(inv_fft_expected[0]);
    TEST_CHECK(n == fs.max_width);
    for (int i = 0; i < n; i++) {
        blst_fr expected;
        blst_fr_from_uint64(&expected, inv_fft_expected[i]);
        TEST_CHECK(fr_equal(&expected, &out[i]));
    }

    free_fft_settings(&fs);
}

TEST_LIST =
    {
     {"is_one_works", is_one_works },
     {"roots_of_unity_is_the_expected_size", roots_of_unity_is_the_expected_size},
     {"roots_of_unity_are_plausible", roots_of_unity_are_plausible},
     {"reverse_works", reverse_works},
     {"expand_roots_is_plausible", expand_roots_is_plausible},
     {"new_fft_settings_is_plausible", new_fft_settings_is_plausible},
     {"is_power_of_two_works", is_power_of_two_works},
     {"fr_from_uint64_works", fr_from_uint64_works},
     {"fr_equal_works", fr_equal_works},
     {"compare_sft_fft", compare_sft_fft},
     {"roundtrip_fft", roundtrip_fft},
     {"inverse_fft", inverse_fft},
     { NULL, NULL }     /* zero record marks the end of the list */
    };
