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

typedef blst_p1 g1_t;         /**< Internal G1 group element type */
typedef blst_p2 g2_t;         /**< Internal G2 group element type */
typedef blst_fr fr_t;         /**< Internal Fr field element type */

typedef g1_t KZGCommitment;
typedef g1_t KZGProof;
typedef fr_t BLSFieldElement;

/**
 * KZGCommitment and KZGProof can be recovered as 48 bytes
 */
void bytes_from_g1(uint8_t out[48], const g1_t*);
void bytes_to_g1(g1_t* out, const uint8_t[48]);

/**
 * BLSFieldElements are communicated directly to/from clients,
 * so we need to expose the functions for translating between this
 * type and uint256. BLST represents uint256 as uint64[4].
 * TODO: we should perhaps just used bytes[32] for this too.
 * For conversion to BLSFieldElement use bytes_to_bls_field.
 */
void uint64s_from_BLSFieldElement(uint64_t out[4], const BLSFieldElement*);

/**
 * The common return type for all routines in which something can go wrong.
 *
 * @warning In the case of @p C_KZG_OK or @p C_KZG_BADARGS, the caller can assume that all memory allocated by the
 * called routines has been deallocated. However, in the case of @p C_KZG_ERROR or @p C_KZG_MALLOC being returned, these
 * are unrecoverable and memory may have been leaked.
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
    g2_t *g2_values;       /**< G2 group elements from the trusted setup */
    uint64_t length;       /**< The number of elements in g1_values */
} KZGSettings;

/**
 * Lagrange form polynomial, with values under the bit-reversal permutation
 */
typedef struct {
    fr_t *values;    /**< `values[i]` is value of the polynomial at `ω^brp(i)` */
    uint64_t length; /**< One more than the polynomial's degree */
} PolynomialEvalForm;

C_KZG_RET alloc_polynomial(PolynomialEvalForm *out, uint64_t length);
void free_polynomial(PolynomialEvalForm *p);


/**
 * Interface functions
 */

C_KZG_RET load_trusted_setup(KZGSettings *out, FILE *in);

void free_trusted_setup(KZGSettings *s);

void bytes_to_bls_field(BLSFieldElement *out, const uint8_t bytes[32]);

void vector_lincomb(BLSFieldElement out[], const BLSFieldElement* vectors[], const BLSFieldElement* scalars[], uint64_t num_vectors, uint64_t vector_len);

void g1_lincomb(KZGCommitment *out, const KZGCommitment points[], const BLSFieldElement scalars[], uint64_t num_points);

void blob_to_kzg_commitment(KZGCommitment *out, const BLSFieldElement blob[], const KZGSettings *s);

C_KZG_RET verify_kzg_proof(bool *out, const KZGCommitment *polynomial_kzg, const BLSFieldElement *z, const BLSFieldElement *y, const KZGProof *kzg_proof, const KZGSettings *s);

C_KZG_RET compute_kzg_proof(KZGProof *out, const PolynomialEvalForm *polynomial, const BLSFieldElement *z, const KZGSettings *s);

C_KZG_RET evaluate_polynomial_in_evaluation_form(BLSFieldElement *out, const PolynomialEvalForm *polynomial, const BLSFieldElement *z, const KZGSettings *s);

void compute_powers(BLSFieldElement out[], const BLSFieldElement *x, uint64_t n);

#endif // C_KZG_4844_H
