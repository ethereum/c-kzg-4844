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
 *  @file utility.c
 *
 * A collection of useful functions used in various places throughout the library.
 */

#include <string.h> // memcpy()
#include "control.h"
#include "utility.h"
#include "c_kzg_alloc.h"

/**
 * Utility function to test whether the argument is a power of two.
 *
 * @remark This method returns `true` for `is_power_of_two(0)` which is a bit weird, but not an issue in the contexts in
 * which we use it.
 *
 * @param[in] n The number to test
 * @retval true  if @p n is a power of two or zero
 * @retval false otherwise
 */
bool is_power_of_two(uint64_t n) {
    return (n & (n - 1)) == 0;
}

/**
 * Calculate log base two of a power of two.
 *
 * In other words, the bit index of the one bit.
 *
 * @remark Works only for n a power of two, and only for n up to 2^31.
 *
 * @param[in] n The power of two
 * @return the log base two of n
 */
int log2_pow2(uint32_t n) {
    const uint32_t b[] = {0xAAAAAAAA, 0xCCCCCCCC, 0xF0F0F0F0, 0xFF00FF00, 0xFFFF0000};
    register uint32_t r;
    r = (n & b[0]) != 0;
    r |= ((n & b[1]) != 0) << 1;
    r |= ((n & b[2]) != 0) << 2;
    r |= ((n & b[3]) != 0) << 3;
    r |= ((n & b[4]) != 0) << 4;
    return r;
}

/**
 * Calculate log base two of a power of two.
 *
 * In other words, the bit index of the highest one bit.
 *
 * @param[in] n The 64 bit unsigned integer to take the logarithm of
 * @return the log base two of n
 */
int log2_u64(uint64_t n) {
    int r = 0;
    while (n >>= 1) r++;
    return r;
}

/**
 * Return the next highest power of two.
 *
 * If @p v is already a power of two, it is returned as-is.
 *
 * Adapted from https://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
 *
 * @param[in] v A 64-bit unsigned integer <= 2^31
 * @return      The lowest power of two equal or larger than @p v
 */
uint64_t next_power_of_two(uint64_t v) {
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v |= v >> 32;
    v++;
    return v += (v == 0);
}

/**
 * Reverse the bit order in a 32 bit integer.
 *
 * @remark This simply wraps the macro to enforce the type check.
 *
 * @param[in] a The integer to be reversed
 * @return An integer with the bits of @p a reversed
 */
uint32_t reverse_bits(uint32_t a) {
    return rev_4byte(a);
}

/**
 * Reverse the low-order bits in a 32 bit integer.
 *
 * The lowest log_base_two(@p n) bits of @p value are returned reversed. @p n must be a power of two.
 *
 * @param[in] n     To reverse `b` bits, set `n = 2 ^ b`
 * @param[in] value The bits to be reversed
 * @return The reversal of the lowest log_2(@p n) bits of the input @p value
 */
uint32_t reverse_bits_limited(uint32_t n, uint32_t value) {
    int unused_bit_len = 32 - log2_pow2(n);
    return reverse_bits(value) >> unused_bit_len;
}

/**
 * Reorder an array in reverse bit order of its indices.
 *
 * @remark Operates in-place on the array.
 * @remark Can handle arrays of any type: provide the element size in @p size.
 *
 * @param[in,out] values The array, which is re-ordered in-place
 * @param[in]     size   The size in bytes of an element of the array
 * @param[in]     n      The length of the array, must be a power of two less that 2^32
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 */
C_KZG_RET reverse_bit_order(void *values, size_t size, uint64_t n) {
    CHECK(n >> 32 == 0);
    CHECK(is_power_of_two(n));

    // Pointer arithmetic on `void *` is naughty, so cast to something definite
    byte *v = values;
    byte tmp[size];
    int unused_bit_len = 32 - log2_pow2(n);
    for (uint32_t i = 0; i < n; i++) {
        uint32_t r = reverse_bits(i) >> unused_bit_len;
        if (r > i) {
            // Swap the two elements
            memcpy(tmp, v + (i * size), size);
            memcpy(v + (i * size), v + (r * size), size);
            memcpy(v + (r * size), tmp, size);
        }
    }

    return C_KZG_OK;
}

/**
 * Montgomery batch inversion in finite field
 *
 * @param[out] out The inverses of @p a, length @p len
 * @param[in]  a   A vector of field elements, length @p len
 * @param[in]  len Length
 */
C_KZG_RET fr_batch_inv(fr_t *out, const fr_t *a, size_t len) {
    fr_t *prod;
    fr_t inv;
    size_t i;

    TRY(new_fr_array(&prod, len));

    prod[0] = a[0];

    for(i = 1; i < len; i++) {
        fr_mul(&prod[i], &a[i], &prod[i - 1]);
    }

    blst_fr_eucl_inverse(&inv, &prod[len - 1]);

    for(i = len - 1; i > 0; i--) {
        fr_mul(&out[i], &inv, &prod[i - 1]);
        fr_mul(&inv, &a[i], &inv);
    }
    out[0] = inv;

    free(prod);

    return C_KZG_OK;
}

#ifdef KZGTEST

#include "../inc/acutest.h"
#include "test_util.h"
#include "c_kzg_alloc.h"

static uint32_t rev_bits_slow(uint32_t a) {
    uint32_t ret = 0;
    for (int i = 0; i < 32; i++) {
        ret <<= 1;
        ret |= a & 1;
        a >>= 1;
    }
    return ret;
}

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

void test_batch_inv(void) {
    fr_t *inputs, *actual, *expected;
    int i;

    TEST_CHECK(C_KZG_OK == new_fr_array(&inputs, 32));
    TEST_CHECK(C_KZG_OK == new_fr_array(&actual, 32));
    TEST_CHECK(C_KZG_OK == new_fr_array(&expected, 32));

    for (i = 0; i < 32; i++) {
        inputs[i] = rand_fr();
        fr_inv(&expected[i], &inputs[i]);
    }
    fr_batch_inv(actual, inputs, 32);
    for (i = 0; i < 32; i++) {
        TEST_CHECK(fr_equal(&expected[i], &actual[i]));
    }

    free(inputs);
    free(actual);
    free(expected);
}

void test_log2_pow2(void) {
    int actual, expected;
    for (int i = 0; i < 32; i++) {
        expected = i;
        actual = log2_pow2((uint32_t)1 << i);
        TEST_CHECK(expected == actual);
    }
}

void test_next_power_of_two_powers(void) {
    for (int i = 0; i <= 63; i++) {
        uint64_t expected = (uint64_t)1 << i;
        uint64_t actual = next_power_of_two(expected);
        TEST_CHECK(expected == actual);
    }
}

void test_next_power_of_two_random(void) {
    for (int i = 0; i < 32768; i++) {
        uint64_t a = 1 + (rand_uint64() >> 1); // It's not expected to work for a > 2^63
        uint64_t higher = next_power_of_two(a);
        uint64_t lower = higher >> 1;
        if (!(TEST_CHECK(is_power_of_two(higher)) && TEST_CHECK(higher >= a) && TEST_CHECK(lower < a))) {
            TEST_MSG("Failed for %lu", a);
        }
    }
}

void test_reverse_bits_macros(void) {
    TEST_CHECK(128 == rev_byte(1));
    TEST_CHECK(128 == rev_byte(257));
    TEST_CHECK((uint32_t)1 << 31 == rev_4byte(1));
    TEST_CHECK(0x1e6a2c48 == rev_4byte(0x12345678));
    TEST_CHECK(0x00000000 == rev_4byte(0x00000000));
    TEST_CHECK(0xffffffff == rev_4byte(0xffffffff));
}

void test_reverse_bits_powers(void) {
    uint32_t actual, expected;
    for (int i = 0; i < 32; i++) {
        expected = (uint32_t)1 << (31 - i);
        actual = reverse_bits((uint32_t)1 << i);
        TEST_CHECK(expected == actual);
    }
}

void test_reverse_bits_random(void) {
    for (int i = 0; i < 32768; i++) {
        uint32_t a = (uint32_t)(rand_uint64() & 0xffffffffL);
        TEST_CHECK(rev_bits_slow(a) == reverse_bits(a));
        TEST_MSG("Failed for %08x. Expected %08x, got %08x.", a, rev_bits_slow(a), reverse_bits(a));
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

void test_reverse_bit_order_fr_large(void) {
    int size = 22, n = 1 << size;
    fr_t *a, *b;

    TEST_CHECK(C_KZG_OK == new_fr_array(&a, n));
    TEST_CHECK(C_KZG_OK == new_fr_array(&b, n));

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

    free(a);
    free(b);
}

TEST_LIST = {
    {"UTILITY_TEST", title},
    {"test_batch_inv", test_batch_inv},
    {"is_power_of_two_works", is_power_of_two_works},
    {"test_log2_pow2", test_log2_pow2},
    {"test_next_power_of_two_powers", test_next_power_of_two_powers},
    {"test_next_power_of_two_random", test_next_power_of_two_random},
    {"test_reverse_bits_macros", test_reverse_bits_macros},
    {"test_reverse_bits_powers", test_reverse_bits_powers},
    {"test_reverse_bits_random", test_reverse_bits_random},
    {"test_reverse_bit_order_g1", test_reverse_bit_order_g1},
    {"test_reverse_bit_order_fr", test_reverse_bit_order_fr},
    {"test_reverse_bit_order_fr_large", test_reverse_bit_order_fr_large},
    {NULL, NULL} /* zero record marks the end of the list */
};

#endif // KZGTEST
