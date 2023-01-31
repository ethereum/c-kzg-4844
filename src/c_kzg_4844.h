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
#define BYTES_PER_BLOB (FIELD_ELEMENTS_PER_BLOB * BYTES_PER_FIELD_ELEMENT)
static const char *FIAT_SHAMIR_PROTOCOL_DOMAIN = "FSBLOBVERIFY_V1_";

typedef blst_p1 g1_t;         /**< Internal G1 group element type */
typedef blst_p2 g2_t;         /**< Internal G2 group element type */
typedef blst_fr fr_t;         /**< Internal Fr field element type */

typedef struct { uint8_t bytes[32]; } Bytes32;
typedef struct { uint8_t bytes[48]; } Bytes48;
typedef struct { uint8_t bytes[BYTES_PER_BLOB]; } Blob;

typedef Bytes48 KZGCommitment;
typedef Bytes48 KZGProof;

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
                             const uint8_t *g1_bytes, /* n1 * 48 bytes */
                             size_t n1,
                             const uint8_t *g2_bytes, /* n2 * 96 bytes */
                             size_t n2);

C_KZG_RET load_trusted_setup_file(KZGSettings *out,
                                  FILE *in);

void free_trusted_setup(
    KZGSettings *s);

C_KZG_RET compute_aggregate_kzg_proof(KZGProof *out,
                                      const Blob *blobs,
                                      size_t n,
                                      const KZGSettings *s);

C_KZG_RET verify_aggregate_kzg_proof(bool *out,
                                     const Blob *blobs,
                                     const Bytes48 *commitments_bytes,
                                     size_t n,
                                     const Bytes48 *aggregated_proof_bytes,
                                     const KZGSettings *s);

C_KZG_RET blob_to_kzg_commitment(KZGCommitment *out,
                                 const Blob *blob,
                                 const KZGSettings *s);

C_KZG_RET verify_kzg_proof(bool *out,
                           const Bytes48 *commitment_bytes,
                           const Bytes32 *z_bytes,
                           const Bytes32 *y_bytes,
                           const Bytes48 *proof_bytes,
                           const KZGSettings *s);

C_KZG_RET compute_kzg_proof(KZGProof *out,
                            const Blob *blob,
                            const Bytes32 *z_bytes,
                            const KZGSettings *s);

typedef struct { fr_t evals[FIELD_ELEMENTS_PER_BLOB]; } Polynomial;

#ifdef UNIT_TESTS

void hash_to_bls_field(fr_t *out, const Bytes32 *b);
void bytes_from_bls_field(Bytes32 *out, const fr_t *in);
C_KZG_RET validate_kzg_g1(g1_t *out, const Bytes48 *b);
void bytes_from_g1(Bytes48 *out, const g1_t *in);
C_KZG_RET evaluate_polynomial_in_evaluation_form(fr_t *out, const Polynomial *p, const fr_t *x, const KZGSettings *s);
C_KZG_RET blob_to_polynomial(Polynomial *p, const Blob *blob);
C_KZG_RET bytes_to_bls_field(fr_t *out, const Bytes32 *b);
uint32_t reverse_bits(uint32_t a);

#endif

#ifdef __cplusplus
}
#endif

#endif // C_KZG_4844_H
