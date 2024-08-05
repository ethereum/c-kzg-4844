/*
 * Copyright 2024 Benjamin Edgington
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

#pragma once

#include "types.h"

#include <stdbool.h> /* For bool */

#ifdef __cplusplus
extern "C" {
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////
// Public Functions
////////////////////////////////////////////////////////////////////////////////////////////////////

/*
 * General Helper Functions:
 */
bool is_power_of_two(uint64_t n);
int log2_pow2(uint32_t n);
uint32_t reverse_bits(uint32_t n);
C_KZG_RET bit_reversal_permutation(void *values, size_t size, uint64_t n);

/*
 * Conversion and Validation:
 */
void bytes_from_g1(Bytes48 *out, const g1_t *in);
void bytes_from_bls_field(Bytes32 *out, const fr_t *in);
void bytes_from_uint64(uint8_t out[8], uint64_t n);
C_KZG_RET bytes_to_bls_field(fr_t *out, const Bytes32 *b);
C_KZG_RET bytes_to_kzg_commitment(g1_t *out, const Bytes48 *b);
C_KZG_RET bytes_to_kzg_proof(g1_t *out, const Bytes48 *b);
void fr_from_uint64(fr_t *out, uint64_t n);
void hash_to_bls_field(fr_t *out, const Bytes32 *b);
C_KZG_RET blob_to_polynomial(fr_t *p, const Blob *blob);

/*
 * Field Operations:
 */
void compute_powers(fr_t *out, const fr_t *x, uint64_t n);

/*
 * Point Operations:
 */
void g1_sub(g1_t *out, const g1_t *a, const g1_t *b);
void g1_mul(g1_t *out, const g1_t *a, const fr_t *b);
bool pairings_verify(const g1_t *a1, const g2_t *a2, const g1_t *b1, const g2_t *b2);
void g1_lincomb_naive(g1_t *out, const g1_t *p, const fr_t *coeffs, uint64_t len);
C_KZG_RET g1_lincomb_fast(g1_t *out, const g1_t *p, const fr_t *coeffs, size_t len);

#ifdef __cplusplus
}
#endif
