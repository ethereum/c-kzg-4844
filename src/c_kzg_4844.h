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

/*
 * Helper function for when LIB_PREFIX is defined.
 */
#ifdef LIB_PREFIX
#define CONCAT_IMPL(a, b) a##_##b
#define CONCAT(a, b) CONCAT_IMPL(a, b)
#define PREFIX_FUNCNAME(name) CONCAT(LIB_PREFIX, name)
#else
#define PREFIX_FUNCNAME(name) name
#endif /* LIB_PREFIX */

/*
 * If LIB_PREFIX is defined, the following functions will prepend `LIB_PREFIX`
 * to all public methods of this library. If LIB_PREFIX is undefined,
 * everything stays as is.
 */
#define BLOB_TO_KZG_COMMITMENT PREFIX_FUNCNAME(blob_to_kzg_commitment)
#define COMPUTE_KZG_PROOF PREFIX_FUNCNAME(compute_kzg_proof)
#define COMPUTE_BLOB_KZG_PROOF PREFIX_FUNCNAME(compute_blob_kzg_proof)
#define VERIFY_KZG_PROOF PREFIX_FUNCNAME(verify_kzg_proof)
#define VERIFY_BLOB_KZG_PROOF PREFIX_FUNCNAME(verify_blob_kzg_proof)
#define VERIFY_BLOB_KZG_PROOF_BATCH PREFIX_FUNCNAME(verify_blob_kzg_proof_batch)
#define LOAD_TRUSTED_SETUP PREFIX_FUNCNAME(load_trusted_setup)
#define LOAD_TRUSTED_SETUP_FILE PREFIX_FUNCNAME(load_trusted_setup_file)
#define FREE_TRUSTED_SETUP PREFIX_FUNCNAME(free_trusted_setup)

/*
 * This value represents the number of field elements in a blob. It must be
 * supplied externally. It is expected to be 4096 for mainnet and 4 for minimal.
 */
#ifndef FIELD_ELEMENTS_PER_BLOB
#error FIELD_ELEMENTS_PER_BLOB must be defined
#endif /* FIELD_ELEMENTS_PER_BLOB */

/*
 * There are only 1<<32 2-adic roots of unity in the field, limiting the
 * possible values of FIELD_ELEMENTS_PER_BLOB. The restriction to 1<<31 is a
 * current implementation limitation. Notably, the size of the FFT setup would
 * overflow uint32_t, which would cause issues.
 */
#if FIELD_ELEMENTS_PER_BLOB <= 0 || FIELD_ELEMENTS_PER_BLOB > (1UL << 31)
#error FIELD_ELEMENTS_PER_BLOB must be between 1 and 2^31
#endif /* FIELD_ELEMENTS_PER_BLOB */

/*
 * If FIELD_ELEMENTS_PER_BLOB is not a power of 2, the size of the FFT domain
 * should be chosen as the the next-largest power of two and polynomials
 * represented by their evaluations at a subset of the 2^i'th roots of unity.
 * While the code in this library tries to take this into account, we do not
 * need the case where FIELD_ELEMENTS_PER_BLOB is not a power of 2. As this
 * case is neither maintained nor tested, we prefer to not support it.
 */
#if (FIELD_ELEMENTS_PER_BLOB & (FIELD_ELEMENTS_PER_BLOB - 1)) != 0
#error FIELD_ELEMENTS_PER_BLOB must be a power of two
#endif /* FIELD_ELEMENTS_PER_BLOB */

/** The number of bytes in a KZG commitment. */
#define BYTES_PER_COMMITMENT 48

/** The number of bytes in a KZG proof. */
#define BYTES_PER_PROOF 48

/** The number of bytes in a BLS scalar field element. */
#define BYTES_PER_FIELD_ELEMENT 32

/** The number of bytes in a blob. */
#define BYTES_PER_BLOB (FIELD_ELEMENTS_PER_BLOB * BYTES_PER_FIELD_ELEMENT)

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
    /** G1 group elements from the trusted setup,
     * in Lagrange form bit-reversal permutation. */
    g1_t *g1_values;
    /** G2 group elements from the trusted setup. */
    g2_t *g2_values;
} KZGSettings;

///////////////////////////////////////////////////////////////////////////////
// Interface functions
///////////////////////////////////////////////////////////////////////////////

C_KZG_RET
LOAD_TRUSTED_SETUP(
    KZGSettings *out,
    const uint8_t *g1_bytes, /* n1 * 48 bytes */
    size_t n1,
    const uint8_t *g2_bytes, /* n2 * 96 bytes */
    size_t n2
);

C_KZG_RET LOAD_TRUSTED_SETUP_FILE(KZGSettings *out, FILE *in);

void FREE_TRUSTED_SETUP(KZGSettings *s);

C_KZG_RET
BLOB_TO_KZG_COMMITMENT(
    KZGCommitment *out, const Blob *blob, const KZGSettings *s
);

C_KZG_RET
COMPUTE_KZG_PROOF(
    KZGProof *proof_out,
    Bytes32 *y_out,
    const Blob *blob,
    const Bytes32 *z_bytes,
    const KZGSettings *s
);

C_KZG_RET
COMPUTE_BLOB_KZG_PROOF(
    KZGProof *out,
    const Blob *blob,
    const Bytes48 *commitment_bytes,
    const KZGSettings *s
);

C_KZG_RET
VERIFY_KZG_PROOF(
    bool *ok,
    const Bytes48 *commitment_bytes,
    const Bytes32 *z_bytes,
    const Bytes32 *y_bytes,
    const Bytes48 *proof_bytes,
    const KZGSettings *s
);

C_KZG_RET
VERIFY_BLOB_KZG_PROOF(
    bool *ok,
    const Blob *blob,
    const Bytes48 *commitment_bytes,
    const Bytes48 *proof_bytes,
    const KZGSettings *s
);

C_KZG_RET
VERIFY_BLOB_KZG_PROOF_BATCH(
    bool *ok,
    const Blob *blobs,
    const Bytes48 *commitments_bytes,
    const Bytes48 *proofs_bytes,
    size_t n,
    const KZGSettings *s
);

#ifdef __cplusplus
}
#endif

#endif /* C_KZG_4844_H */
