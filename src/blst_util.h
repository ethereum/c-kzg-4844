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

/** @file blst_util.h */

#include "c_kzg.h"

static const blst_fr fr_zero = {0L, 0L, 0L, 0L};

// This is 1 in Blst's `blst_fr` limb representation. Crazy but true.
static const blst_fr fr_one = {0x00000001fffffffeL, 0x5884b7fa00034802L, 0x998c4fefecbc4ff5L, 0x1824b159acc5056fL};

// The G1 identity/infinity in affine representation
static const blst_p1_affine g1_identity_affine = {{0L, 0L, 0L, 0L, 0L, 0L}, {0L, 0L, 0L, 0L, 0L, 0L}};

// The G1 identity/infinity
static const blst_p1 g1_identity = {{0L, 0L, 0L, 0L, 0L, 0L}, {0L, 0L, 0L, 0L, 0L, 0L}, {0L, 0L, 0L, 0L, 0L, 0L}};

bool fr_is_zero(const blst_fr *p);
bool fr_is_one(const blst_fr *p);
void fr_from_uint64(blst_fr *out, uint64_t n);
bool fr_equal(const blst_fr *aa, const blst_fr *bb);
void fr_negate(blst_fr *out, const blst_fr *in);
void fr_pow(blst_fr *out, const blst_fr *a, const uint64_t n);
void fr_div(blst_fr *out, const blst_fr *a, const blst_fr *b);
void p1_mul(blst_p1 *out, const blst_p1 *a, const blst_fr *b);
void p1_sub(blst_p1 *out, const blst_p1 *a, const blst_p1 *b);
void p2_mul(blst_p2 *out, const blst_p2 *a, const blst_fr *b);
void p2_sub(blst_p2 *out, const blst_p2 *a, const blst_p2 *b);
void linear_combination_g1(blst_p1 *out, const blst_p1 *p, const blst_fr *coeffs, const uint64_t len);
bool pairings_verify(const blst_p1 *a1, const blst_p2 *a2, const blst_p1 *b1, const blst_p2 *b2);
