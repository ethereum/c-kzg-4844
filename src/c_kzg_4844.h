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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "blst.h"

#ifdef __cplusplus
extern "C" {
#endif

///////////////////////////////////////////////////////////////////////////////
// Macros
///////////////////////////////////////////////////////////////////////////////

/** The number of bytes in a KZG commitment. */
#define BYTES_PER_COMMITMENT 48

/** The number of bytes in a KZG proof. */
#define BYTES_PER_PROOF 48

/** The number of bytes in a BLS scalar field element. */
#define BYTES_PER_FIELD_ELEMENT 32

/** The number of bits in a BLS scalar field element. */
#define BITS_PER_FIELD_ELEMENT 255

/** The number of field elements in a blob. */
#define FIELD_ELEMENTS_PER_BLOB 4096

/** The number of bytes in a blob. */
#define BYTES_PER_BLOB (FIELD_ELEMENTS_PER_BLOB * BYTES_PER_FIELD_ELEMENT)

/** The number of field elements in an extended blob */
#define FIELD_ELEMENTS_PER_EXT_BLOB (FIELD_ELEMENTS_PER_BLOB * 2)

/** The number of field elements in a cell. */
#define FIELD_ELEMENTS_PER_CELL 64

/** The number of cells in an extended blob. */
#define CELLS_PER_EXT_BLOB \
    (FIELD_ELEMENTS_PER_EXT_BLOB / FIELD_ELEMENTS_PER_CELL)

/** The number of bytes in a single cell. */
#define BYTES_PER_CELL (BYTES_PER_FIELD_ELEMENT * FIELD_ELEMENTS_PER_CELL)

///////////////////////////////////////////////////////////////////////////////
// Types
///////////////////////////////////////////////////////////////////////////////

typedef blst_p1 g1_t; /**< Internal G1 group element type. */
typedef blst_p2 g2_t; /**< Internal G2 group element type. */
typedef blst_fr fr_t; /**< Internal Fr field element type. */

/**
 * An array of 32 bytes. Represents an untrusted
 * (potentially invalid) field element.
 */
typedef struct {
    uint8_t bytes[32];
} Bytes32;

/**
 * An array of 48 bytes. Represents an untrusted
 * (potentially invalid) commitment/proof.
 */
typedef struct {
    uint8_t bytes[48];
} Bytes48;

/**
 * A basic blob data.
 */
typedef struct {
    uint8_t bytes[BYTES_PER_BLOB];
} Blob;

/**
 * A trusted (valid) KZG commitment.
 */
typedef Bytes48 KZGCommitment;

/**
 * A trusted (valid) KZG proof.
 */
typedef Bytes48 KZGProof;

/**
 * A single cell for a blob.
 */
typedef struct {
    Bytes32 data[FIELD_ELEMENTS_PER_CELL];
} Cell;

/**
 * The common return type for all routines in which something can go wrong.
 */
typedef enum {
    C_KZG_OK = 0,  /**< Success! */
    C_KZG_BADARGS, /**< The supplied data is invalid in some way. */
    C_KZG_ERROR,   /**< Internal error - this should never occur. */
    C_KZG_MALLOC,  /**< Could not allocate memory. */
} C_KZG_RET;

/**
 * Stores the setup and parameters needed for computing KZG proofs.
 */
typedef struct {
    /** The length of `roots_of_unity`, a power of 2. */
    uint64_t max_width;
    /** Powers of the primitive root of unity determined by
     * `SCALE2_ROOT_OF_UNITY` in bit-reversal permutation order,
     * length `max_width`. */
    fr_t *roots_of_unity;
    /** The expanded roots of unity */
    fr_t *expanded_roots_of_unity;
    /** The bit-reversal permuted roots of unity. */
    fr_t *reverse_roots_of_unity;
    /** G1 group elements from the trusted setup,
     * in monomial form. */
    g1_t *g1_values;
    /** G1 group elements from the trusted setup,
     * in Lagrange form bit-reversal permutation. */
    g1_t *g1_values_lagrange;
    /** G2 group elements from the trusted setup,
     * in monomial form. */
    g2_t *g2_values;
    /** Data used during FK20 proof generation. */
    g1_t **x_ext_fft_columns;
    /** The precomputed tables for fixed-base MSM */
    blst_p1_affine **tables;
    /** The window size for the fixed-base MSM */
    size_t wbits;
    /** The scratch size for the fixed-base MSM */
    size_t scratch_size;
} KZGSettings;

///////////////////////////////////////////////////////////////////////////////
// Interface functions
///////////////////////////////////////////////////////////////////////////////

C_KZG_RET load_trusted_setup(
    KZGSettings *out,
    const uint8_t *g1_bytes, /* n1 * 48 bytes */
    size_t n1,
    const uint8_t *g2_bytes, /* n2 * 96 bytes */
    size_t n2
);

C_KZG_RET load_trusted_setup_file(KZGSettings *out, FILE *in);

void free_trusted_setup(KZGSettings *s);

C_KZG_RET blob_to_kzg_commitment(
    KZGCommitment *out, const Blob *blob, const KZGSettings *s
);

C_KZG_RET compute_kzg_proof(
    KZGProof *proof_out,
    Bytes32 *y_out,
    const Blob *blob,
    const Bytes32 *z_bytes,
    const KZGSettings *s
);

C_KZG_RET compute_blob_kzg_proof(
    KZGProof *out,
    const Blob *blob,
    const Bytes48 *commitment_bytes,
    const KZGSettings *s
);

C_KZG_RET verify_kzg_proof(
    bool *ok,
    const Bytes48 *commitment_bytes,
    const Bytes32 *z_bytes,
    const Bytes32 *y_bytes,
    const Bytes48 *proof_bytes,
    const KZGSettings *s
);

C_KZG_RET verify_blob_kzg_proof(
    bool *ok,
    const Blob *blob,
    const Bytes48 *commitment_bytes,
    const Bytes48 *proof_bytes,
    const KZGSettings *s
);

C_KZG_RET verify_blob_kzg_proof_batch(
    bool *ok,
    const Blob *blobs,
    const Bytes48 *commitments_bytes,
    const Bytes48 *proofs_bytes,
    size_t n,
    const KZGSettings *s
);

C_KZG_RET compute_cells_and_kzg_proofs(
    Cell *cells, KZGProof *proofs, const Blob *blob, const KZGSettings *s
);

C_KZG_RET verify_cell_kzg_proof(
    bool *ok,
    const Bytes48 *commitment_bytes,
    uint64_t cell_id,
    const Cell *cell,
    const Bytes48 *proof_bytes,
    const KZGSettings *s
);

C_KZG_RET verify_cell_kzg_proof_batch(
    bool *ok,
    const Bytes48 *commitments_bytes,
    size_t num_commitments,
    const uint64_t *row_indices,
    const uint64_t *column_indices,
    const Cell *cells,
    const Bytes48 *proofs_bytes,
    size_t num_cells,
    const KZGSettings *s
);

C_KZG_RET recover_all_cells(
    Cell *recovered,
    const uint64_t *cell_ids,
    const Cell *cells,
    size_t num_cells,
    const KZGSettings *s
);

C_KZG_RET cells_to_blob(Blob *blob, const Cell *cells);

#ifdef __cplusplus
}
#endif

#endif /* C_KZG_4844_H */
