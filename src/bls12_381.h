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
 * @file bls12_381.h
 *
 * Interface for cryptographic library functions, allowing different libraries to be supported.
 */

#ifndef BLS12_381_H
#define BLS12_381_H

#include <stdint.h>
#include <stdbool.h>

// BLST is our only option for now
#ifndef BLST
#define BLST
#endif

// Settings for linking with the BLST library
#ifdef BLST

#include "blst.h"

typedef blst_scalar scalar_t; /**< Internal scalar type */
typedef blst_fr fr_t;         /**< Internal Fr field element type */
typedef blst_fp fp_t;         /**< Internal Fp field element type (used only for debugging) */
typedef blst_fp2 fp2_t;       /**< Internal Fp2 field element type (used only for debugging) */
typedef blst_p1 g1_t;         /**< Internal G1 group element type */
typedef blst_p2 g2_t;         /**< Internal G2 group element type */

/** The zero field element */
static const fr_t fr_zero = {0L, 0L, 0L, 0L};

/** This is 1 in Blst's `blst_fr` limb representation. Crazy but true. */
static const fr_t fr_one = {0x00000001fffffffeL, 0x5884b7fa00034802L, 0x998c4fefecbc4ff5L, 0x1824b159acc5056fL};

/** Defines a NULL value for fr_t. */
static const fr_t fr_null = {0xffffffffffffffffL, 0xffffffffffffffffL, 0xffffffffffffffffL, 0xffffffffffffffffL};

/** The G1 identity/infinity */
static const g1_t g1_identity = {{0L, 0L, 0L, 0L, 0L, 0L}, {0L, 0L, 0L, 0L, 0L, 0L}, {0L, 0L, 0L, 0L, 0L, 0L}};

/** The G1 generator */
static const g1_t g1_generator = {{0x5cb38790fd530c16L, 0x7817fc679976fff5L, 0x154f95c7143ba1c1L, 0xf0ae6acdf3d0e747L,
                                   0xedce6ecc21dbf440L, 0x120177419e0bfb75L},
                                  {0xbaac93d50ce72271L, 0x8c22631a7918fd8eL, 0xdd595f13570725ceL, 0x51ac582950405194L,
                                   0x0e1c8c3fad0059c0L, 0x0bbc3efc5008a26aL},
                                  {0x760900000002fffdL, 0xebf4000bc40c0002L, 0x5f48985753c758baL, 0x77ce585370525745L,
                                   0x5c071a97a256ec6dL, 0x15f65ec3fa80e493L}};

/** The inverse of the G1 generator */
static const g1_t g1_negative_generator = {{0x5cb38790fd530c16L, 0x7817fc679976fff5L, 0x154f95c7143ba1c1L,
                                            0xf0ae6acdf3d0e747L, 0xedce6ecc21dbf440L, 0x120177419e0bfb75L},
                                           {0xff526c2af318883aL, 0x92899ce4383b0270L, 0x89d7738d9fa9d055L,
                                            0x12caf35ba344c12aL, 0x3cff1b76964b5317L, 0x0e44d2ede9774430L},
                                           {0x760900000002fffdL, 0xebf4000bc40c0002L, 0x5f48985753c758baL,
                                            0x77ce585370525745L, 0x5c071a97a256ec6dL, 0x15f65ec3fa80e493L}};

/** The G2 generator */
static const g2_t g2_generator = {{{{0xf5f28fa202940a10L, 0xb3f5fb2687b4961aL, 0xa1a893b53e2ae580L, 0x9894999d1a3caee9L,
                                     0x6f67b7631863366bL, 0x058191924350bcd7L},
                                    {0xa5a9c0759e23f606L, 0xaaa0c59dbccd60c3L, 0x3bb17e18e2867806L, 0x1b1ab6cc8541b367L,
                                     0xc2b6ed0ef2158547L, 0x11922a097360edf3L}}},
                                  {{{0x4c730af860494c4aL, 0x597cfa1f5e369c5aL, 0xe7e6856caa0a635aL, 0xbbefb5e96e0d495fL,
                                     0x07d3a975f0ef25a2L, 0x0083fd8e7e80dae5L},
                                    {0xadc0fc92df64b05dL, 0x18aa270a2b1461dcL, 0x86adac6a3be4eba0L, 0x79495c4ec93da33aL,
                                     0xe7175850a43ccaedL, 0x0b2bc2a163de1bf2L}}},
                                  {{{0x760900000002fffdL, 0xebf4000bc40c0002L, 0x5f48985753c758baL, 0x77ce585370525745L,
                                     0x5c071a97a256ec6dL, 0x15f65ec3fa80e493L},
                                    {0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L,
                                     0x0000000000000000L, 0x0000000000000000L}}}};

/** The inverse of the G2 generator */
static const g2_t g2_negative_generator = {{{{0xf5f28fa202940a10L, 0xb3f5fb2687b4961aL, 0xa1a893b53e2ae580L,
                                              0x9894999d1a3caee9L, 0x6f67b7631863366bL, 0x058191924350bcd7L},
                                             {0xa5a9c0759e23f606L, 0xaaa0c59dbccd60c3L, 0x3bb17e18e2867806L,
                                              0x1b1ab6cc8541b367L, 0xc2b6ed0ef2158547L, 0x11922a097360edf3L}}},
                                           {{{0x6d8bf5079fb65e61L, 0xc52f05df531d63a5L, 0x7f4a4d344ca692c9L,
                                              0xa887959b8577c95fL, 0x4347fe40525c8734L, 0x197d145bbaff0bb5L},
                                             {0x0c3e036d209afa4eL, 0x0601d8f4863f9e23L, 0xe0832636bacc0a84L,
                                              0xeb2def362a476f84L, 0x64044f659f0ee1e9L, 0x0ed54f48d5a1caa7L}}},
                                           {{{0x760900000002fffdL, 0xebf4000bc40c0002L, 0x5f48985753c758baL,
                                              0x77ce585370525745L, 0x5c071a97a256ec6dL, 0x15f65ec3fa80e493L},
                                             {0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L,
                                              0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L}}}};

#endif // BLST

// All the functions in the interface
bool fr_is_zero(const fr_t *p);
bool fr_is_one(const fr_t *p);
bool fr_is_null(const fr_t *p);
void fr_from_scalar(fr_t *out, const scalar_t *a);
void fr_from_uint64s(fr_t *out, const uint64_t vals[4]);
void fr_from_uint64(fr_t *out, uint64_t n);
void fr_to_uint64s(uint64_t out[4], const fr_t *fr);
bool fr_equal(const fr_t *aa, const fr_t *bb);
void fr_negate(fr_t *out, const fr_t *in);
void fr_add(fr_t *out, const fr_t *a, const fr_t *b);
void fr_sub(fr_t *out, const fr_t *a, const fr_t *b);
void fr_mul(fr_t *out, const fr_t *a, const fr_t *b);
void fr_inv(fr_t *out, const fr_t *a);
void fr_div(fr_t *out, const fr_t *a, const fr_t *b);
void fr_sqr(fr_t *out, const fr_t *a);
void fr_pow(fr_t *out, const fr_t *a, uint64_t n);
bool g1_is_inf(const g1_t *a);
void g1_dbl(g1_t *out, const g1_t *a);
void g1_add_or_dbl(g1_t *out, const g1_t *a, const g1_t *b);
bool g1_equal(const g1_t *a, const g1_t *b);
void g1_mul(g1_t *out, const g1_t *a, const fr_t *b);
void g1_sub(g1_t *out, const g1_t *a, const g1_t *b);
bool g2_equal(const g2_t *a, const g2_t *b);
void g2_mul(g2_t *out, const g2_t *a, const fr_t *b);
void g2_add_or_dbl(g2_t *out, const g2_t *a, const g2_t *b);
void g2_sub(g2_t *out, const g2_t *a, const g2_t *b);
void g2_dbl(g2_t *out, const g2_t *a);
void g1_linear_combination(g1_t *out, const g1_t *p, const fr_t *coeffs, const uint64_t len);
bool pairings_verify(const g1_t *a1, const g2_t *a2, const g1_t *b1, const g2_t *b2);

#endif // BLS12_381_H