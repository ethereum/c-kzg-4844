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

#include "blst.h"
#include "constants.h"

////////////////////////////////////////////////////////////////////////////////////////////////////
// Types
////////////////////////////////////////////////////////////////////////////////////////////////////

/** The common return type for all routines in which something can go wrong. */
typedef enum {
    C_KZG_OK = 0,  /**< Success! */
    C_KZG_BADARGS, /**< The supplied data is invalid in some way. */
    C_KZG_ERROR,   /**< Internal error - this should never occur. */
    C_KZG_MALLOC,  /**< Could not allocate memory. */
} C_KZG_RET;

typedef blst_p1 g1_t; /**< Internal G1 group element type. */
typedef blst_p2 g2_t; /**< Internal G2 group element type. */
typedef blst_fr fr_t; /**< Internal Fr field element type. */

/** An array of 32 bytes. Represents an untrusted (potentially invalid) field element. */
typedef struct {
    uint8_t bytes[32];
} Bytes32;

/** An array of 48 bytes. Represents an untrusted (potentially invalid) commitment/proof. */
typedef struct {
    uint8_t bytes[48];
} Bytes48;

/** A basic blob data. */
typedef struct {
    uint8_t bytes[BYTES_PER_BLOB];
} Blob;

/** A trusted (valid) KZG commitment. */
typedef Bytes48 KZGCommitment;

/** A trusted (valid) KZG proof. */
typedef Bytes48 KZGProof;

/** Stores the setup and parameters needed for computing KZG proofs. */
typedef struct {
    /**
     * Roots of unity for the subgroup of size `domain_size`.
     *
     * The array contains `domain_size + 1` elements, it starts and ends with Fr::one().
     */
    fr_t *roots_of_unity;
    /**
     * Roots of unity for the subgroup of size `domain_size` in bit-reversed order.
     *
     * This array is derived by applying a bit-reversal permutation to `roots_of_unity`
     * excluding the last element. Essentially:
     *   `brp_roots_of_unity = bit_reversal_permutation(roots_of_unity[:-1])`
     *
     * The array contains `domain_size` elements.
     */
    fr_t *brp_roots_of_unity;
    /**
     * Roots of unity for the subgroup of size `domain_size` in reversed order.
     *
     * It is the reversed version of `roots_of_unity`. Essentially:
     *    `reverse_roots_of_unity = reverse(roots_of_unity)`
     *
     * This array is primarily used in FFTs.
     * The array contains `domain_size + 1` elements, it starts and ends with Fr::one().
     */
    fr_t *reverse_roots_of_unity;
    /** G1 group elements from the trusted setup in monomial form. */
    g1_t *g1_values_monomial;
    /** G1 group elements from the trusted setup in Lagrange form and bit-reversed order. */
    g1_t *g1_values_lagrange_brp;
    /** G2 group elements from the trusted setup in monomial form. */
    g2_t *g2_values_monomial;
    /** Data used during FK20 proof generation. */
    g1_t **x_ext_fft_columns;
    /** The precomputed tables for fixed-base MSM. */
    blst_p1_affine **tables;
    /** The window size for the fixed-base MSM. */
    size_t wbits;
    /** The scratch size for the fixed-base MSM. */
    size_t scratch_size;
} KZGSettings;
