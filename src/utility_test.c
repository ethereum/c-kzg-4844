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
#include "utility.h"

void is_power_of_two_works(void) {
    // All actual powers of two
    for (int i = 0; i <= 63; i++) {
        TEST_CHECK(true == is_power_of_two((uint64_t)1 << i));
        TEST_MSG("Case %d", i);
    }

    // This is a bit weird
    TEST_CHECK(true == is_power_of_two(0));

    // Not powers of two
    TEST_CHECK(false == is_power_of_two(123));
    TEST_CHECK(false == is_power_of_two(1234567));
}

void test_reverse_bits_macros(void) {
    TEST_CHECK(128 == rev_byte(1));
    TEST_CHECK(128 == rev_byte(257));
    TEST_CHECK((uint32_t)1 << 31 == rev_4byte(1));
    TEST_CHECK(0x1e6a2c48 == rev_4byte(0x12345678));
    TEST_CHECK(0x00000000 == rev_4byte(0x00000000));
    TEST_CHECK(0xffffffff == rev_4byte(0xffffffff));
}

void test_reverse_bits_0(void) {
    uint32_t actual, expected;
    for (int i = 0; i < 32; i++) {
        expected = (uint32_t)1 << (31 - i);
        actual = reverse_bits((uint32_t)1 << i);
        TEST_CHECK(expected == actual);
    }
}

void test_reverse_bits_1(void) {
    TEST_CHECK(0x84c2a6e1 == reverse_bits(0x87654321));
}

void test_log2_pow2(void) {
    int actual, expected;
    for (int i = 0; i < 32; i++) {
        expected = i;
        actual = log2_pow2((uint32_t)1 << i);
        TEST_CHECK(expected == actual);
    }
}

void test_reverse_bit_order_g1(void) {
    int size = 10, n = 1 << size;
    g1_t a[n], b[n];
    fr_t tmp;

    for (int i = 0; i < n; i++) {
        fr_from_uint64(&tmp, i);
        g1_mul(&a[i], &g1_generator, &tmp);
        b[i] = a[i];
    }

    TEST_CHECK(C_KZG_OK == reverse_bit_order(a, sizeof(g1_t), n));
    for (int i = 0; i < n; i++) {
        TEST_CHECK(true == g1_equal(&b[reverse_bits(i) >> (32 - size)], &a[i]));
    }

    // Hand check a few select values
    TEST_CHECK(true == g1_equal(&b[0], &a[0]));
    TEST_CHECK(false == g1_equal(&b[1], &a[1]));
    TEST_CHECK(true == g1_equal(&b[n - 1], &a[n - 1]));
}

void test_reverse_bit_order_fr(void) {
    int size = 12, n = 1 << size;
    fr_t a[n], b[n];

    for (int i = 0; i < n; i++) {
        fr_from_uint64(&a[i], i);
        b[i] = a[i];
    }

    TEST_CHECK(C_KZG_OK == reverse_bit_order(a, sizeof(fr_t), n));
    for (int i = 0; i < n; i++) {
        TEST_CHECK(true == fr_equal(&b[reverse_bits(i) >> (32 - size)], &a[i]));
    }

    // Hand check a few select values
    TEST_CHECK(true == fr_equal(&b[0], &a[0]));
    TEST_CHECK(false == fr_equal(&b[1], &a[1]));
    TEST_CHECK(true == fr_equal(&b[n - 1], &a[n - 1]));
}

TEST_LIST = {
    {"UTILITY_TEST", title},
    {"is_power_of_two_works", is_power_of_two_works},
    {"test_reverse_bits_macros", test_reverse_bits_macros},
    {"test_reverse_bits_0", test_reverse_bits_0},
    {"test_reverse_bits_1", test_reverse_bits_1},
    {"test_log2_pow2", test_log2_pow2},
    {"test_reverse_bit_order_g1", test_reverse_bit_order_g1},
    {"test_reverse_bit_order_fr", test_reverse_bit_order_fr},
    {NULL, NULL} /* zero record marks the end of the list */
};
