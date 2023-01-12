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
 * @file c_kzg_4844.h
 *
 * Minimal interface required for EIP-4844.
 */

#ifndef C_KZG_4844_H
#define C_KZG_4844_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "blst.h"

// Allow a library built from this code to be used from C++
#ifdef __cplusplus
extern "C" {
#endif

#define BYTES_PER_COMMITMENT 48
#define BYTES_PER_PROOF 48
#define BYTES_PER_FIELD_ELEMENT 32
#define BYTES_PER_BLOB FIELD_ELEMENTS_PER_BLOB * BYTES_PER_FIELD_ELEMENT
static const char *FIAT_SHAMIR_PROTOCOL_DOMAIN = "FSBLOBVERIFY_V1_";

typedef blst_p1 g1_t;         /**< Internal G1 group element type */
typedef blst_p2 g2_t;         /**< Internal G2 group element type */
typedef blst_fr fr_t;         /**< Internal Fr field element type */

typedef struct { uint8_t bytes[BYTES_PER_COMMITMENT]; } KZGCommitment;
typedef struct { uint8_t bytes[BYTES_PER_PROOF]; } KZGProof;
typedef struct { uint8_t bytes[BYTES_PER_FIELD_ELEMENT]; } BLSFieldElement;
typedef uint8_t Blob[BYTES_PER_BLOB];

/**
 * The common return type for all routines in which something can go wrong.
 */
typedef enum {
    C_KZG_OK = 0,  /**< Success! */
    C_KZG_BADARGS, /**< The supplied data is invalid in some way */
    C_KZG_ERROR,   /**< Internal error - this should never occur and may indicate a bug in the library */
    C_KZG_MALLOC,  /**< Could not allocate memory */
} C_KZG_RET;

/**
 * Stores the setup and parameters needed for performing FFTs.
 */
typedef struct {
    uint64_t max_width;            /**< The maximum size of FFT these settings support, a power of 2. */
    fr_t *expanded_roots_of_unity; /**< Ascending powers of the root of unity, size `width + 1`. */
    fr_t *reverse_roots_of_unity;  /**< Descending powers of the root of unity, size `width + 1`. */
    fr_t *roots_of_unity;          /**< Powers of the root of unity in bit-reversal permutation, size `width`. */
} FFTSettings;

/**
 * Stores the setup and parameters needed for computing KZG proofs.
 */
typedef struct {
    const FFTSettings *fs; /**< The corresponding settings for performing FFTs */
    g1_t *g1_values;       /**< G1 group elements from the trusted setup, in Lagrange form bit-reversal permutation */
    g2_t *g2_values;       /**< G2 group elements from the trusted setup; both arrays have FIELD_ELEMENTS_PER_BLOB elements */
} KZGSettings;

/**
 * Interface functions
 */

C_KZG_RET load_trusted_setup(KZGSettings *out,
                             const uint8_t g1_bytes[], /* n1 * 48 bytes */
                             size_t n1,
                             const uint8_t g2_bytes[], /* n2 * 96 bytes */
                             size_t n2);

C_KZG_RET load_trusted_setup_file(KZGSettings *out,
                                  FILE *in);

void free_trusted_setup(
    KZGSettings *s);

C_KZG_RET compute_aggregate_kzg_proof(KZGProof *out,
                                      const Blob blobs[],
                                      size_t n,
                                      const KZGSettings *s);

C_KZG_RET verify_aggregate_kzg_proof(bool *out,
                                     const Blob blobs[],
                                     const KZGCommitment expected_kzg_commitments[],
                                     size_t n,
                                     const KZGProof *kzg_aggregated_proof,
                                     const KZGSettings *s);

C_KZG_RET blob_to_kzg_commitment(KZGCommitment *out,
                                 const Blob blob,
                                 const KZGSettings *s);

C_KZG_RET verify_kzg_proof(bool *out,
                           const KZGCommitment *polynomial_kzg,
                           const BLSFieldElement *z,
                           const BLSFieldElement *y,
                           const KZGProof *kzg_proof,
                           const KZGSettings *s);

#ifdef __cplusplus
}
#endif

#endif // C_KZG_4844_H
