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
 *  @file utility.h
 *
 * A collection of useful functions used in various places throughout the library.
 */

#include "c_kzg.h"

/**
 * Reverse the bits in a byte.
 *
 * From https://graphics.stanford.edu/~seander/bithacks.html#ReverseByteWith64BitsDiv
 *
 * @param a A byte
 * @return A byte that is bit-reversed with respect to @p a
 *
 * @todo Benchmark some of the other bit-reversal options in the list. Maybe.
 */
#define rev_byte(a) ((((a)&0xff) * 0x0202020202ULL & 0x010884422010ULL) % 1023)

/**
 * Reverse the bits in a 32 bit word.
 *
 * @param a A 32 bit unsigned integer
 * @return A 32 bit unsigned integer that is bit-reversed with respect to @p a
 */
#define rev_4byte(a) (rev_byte(a) << 24 | rev_byte((a) >> 8) << 16 | rev_byte((a) >> 16) << 8 | rev_byte((a) >> 24))

bool is_power_of_two(uint64_t n);
int log2_pow2(uint32_t n);
int log2_u64(uint64_t n);
uint64_t next_power_of_two(uint64_t v);
uint32_t reverse_bits(uint32_t a);
uint32_t reverse_bits_limited(uint32_t n, uint32_t value);
C_KZG_RET reverse_bit_order(void *values, size_t size, uint64_t n);
