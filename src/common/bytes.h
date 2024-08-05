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

#include "fr.h"
#include "g1.h"
#include "ret.h"

#include <inttypes.h> /* For uint*_t */

////////////////////////////////////////////////////////////////////////////////////////////////////
// Types
////////////////////////////////////////////////////////////////////////////////////////////////////

/** An array of 32 bytes. Represents an untrusted (potentially invalid) field element. */
typedef struct {
    uint8_t bytes[32];
} Bytes32;

/** An array of 48 bytes. Represents an untrusted (potentially invalid) commitment/proof. */
typedef struct {
    uint8_t bytes[48];
} Bytes48;

////////////////////////////////////////////////////////////////////////////////////////////////////
// Public Functions
////////////////////////////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

void bytes_from_uint64(uint8_t out[8], uint64_t n);
void bytes_from_g1(Bytes48 *out, const g1_t *in);
void bytes_from_bls_field(Bytes32 *out, const fr_t *in);
C_KZG_RET bytes_to_bls_field(fr_t *out, const Bytes32 *b);
C_KZG_RET bytes_to_kzg_commitment(g1_t *out, const Bytes48 *b);
C_KZG_RET bytes_to_kzg_proof(g1_t *out, const Bytes48 *b);
void hash_to_bls_field(fr_t *out, const Bytes32 *b);

#ifdef __cplusplus
}
#endif