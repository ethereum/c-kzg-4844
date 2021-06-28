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
#include "utility.h"

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
