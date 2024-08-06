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

#include "eip7594/eip7594.h"
#include "common/alloc.h"
#include "common/fr.h"
#include "common/lincomb.h"
#include "common/utils.h"
#include "eip7594/fft.h"
#include "eip7594/fk20.h"
#include "eip7594/poly.h"
#include "eip7594/recovery.h"

#include <assert.h> /* For assert */
#include <string.h> /* For memcpy */

////////////////////////////////////////////////////////////////////////////////////////////////////
// Macros
////////////////////////////////////////////////////////////////////////////////////////////////////

/** Length of the domain string. */
#define DOMAIN_STR_LENGTH 16

////////////////////////////////////////////////////////////////////////////////////////////////////
// Constants
////////////////////////////////////////////////////////////////////////////////////////////////////

/** The domain separator for verify_cell_kzg_proof_batch's random challenge. */
static const char *RANDOM_CHALLENGE_DOMAIN_VERIFY_CELL_KZG_PROOF_BATCH = "RCKZGCBATCH__V1_";

////////////////////////////////////////////////////////////////////////////////////////////////////
// Helper Functions for Batch Cell Verification
////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Compute random linear combination challenge scalars for verify_cell_kzg_proof_batch. In this, we
 * must hash EVERYTHING that the prover can control.
 *
 * @param[out]  r_powers_out        The output challenges
 * @param[in]   commitments_bytes   The input commitments
 * @param[in]   num_commitments     The number of commitments
 * @param[in]   commitment_indices  The cell commitment indices
 * @param[in]   cell_indices        The cell indices
 * @param[in]   cells               The cell
 * @param[in]   proofs_bytes        The cell proof
 * @param[in]   num_cells           The number of cells
 */
static C_KZG_RET compute_r_powers_for_verify_cell_kzg_proof_batch(
    fr_t *r_powers_out,
    const Bytes48 *commitments_bytes,
    size_t num_commitments,
    const uint64_t *commitment_indices,
    const uint64_t *cell_indices,
    const Cell *cells,
    const Bytes48 *proofs_bytes,
    size_t num_cells
) {
    C_KZG_RET ret;
    uint8_t *bytes = NULL;
    Bytes32 r_bytes;
    fr_t r;

    /* Calculate the size of the data we're going to hash */
    size_t input_size = DOMAIN_STR_LENGTH                          /* The domain separator */
                        + sizeof(uint64_t)                         /* FIELD_ELEMENTS_PER_CELL */
                        + sizeof(uint64_t)                         /* num_commitments */
                        + sizeof(uint64_t)                         /* num_cells */
                        + (num_commitments * BYTES_PER_COMMITMENT) /* comms */
                        + (num_cells * sizeof(uint64_t))           /* commitment_indices */
                        + (num_cells * sizeof(uint64_t))           /* cell_indices */
                        + (num_cells * BYTES_PER_CELL)             /* cells */
                        + (num_cells * BYTES_PER_PROOF);           /* proofs_bytes */

    /* Allocate space to copy this data into */
    ret = c_kzg_malloc((void **)&bytes, input_size);
    if (ret != C_KZG_OK) goto out;

    /* Pointer tracking `bytes` for writing on top of it */
    uint8_t *offset = bytes;

    /* Copy domain separator */
    memcpy(offset, RANDOM_CHALLENGE_DOMAIN_VERIFY_CELL_KZG_PROOF_BATCH, DOMAIN_STR_LENGTH);
    offset += DOMAIN_STR_LENGTH;

    /* Copy field elements per cell */
    bytes_from_uint64(offset, FIELD_ELEMENTS_PER_CELL);
    offset += sizeof(uint64_t);

    /* Copy number of commitments */
    bytes_from_uint64(offset, num_commitments);
    offset += sizeof(uint64_t);

    /* Copy number of cells */
    bytes_from_uint64(offset, num_cells);
    offset += sizeof(uint64_t);

    for (size_t i = 0; i < num_commitments; i++) {
        /* Copy commitment */
        memcpy(offset, &commitments_bytes[i], BYTES_PER_COMMITMENT);
        offset += BYTES_PER_COMMITMENT;
    }

    for (size_t i = 0; i < num_cells; i++) {
        /* Copy row id */
        bytes_from_uint64(offset, commitment_indices[i]);
        offset += sizeof(uint64_t);

        /* Copy column id */
        bytes_from_uint64(offset, cell_indices[i]);
        offset += sizeof(uint64_t);

        /* Copy cell */
        memcpy(offset, &cells[i], BYTES_PER_CELL);
        offset += BYTES_PER_CELL;

        /* Copy proof */
        memcpy(offset, &proofs_bytes[i], BYTES_PER_PROOF);
        offset += BYTES_PER_PROOF;
    }

    /* Now let's create the challenge! */
    blst_sha256(r_bytes.bytes, bytes, input_size);
    hash_to_bls_field(&r, &r_bytes);

    /* Raise power of r for each cell */
    compute_powers(r_powers_out, &r, num_cells);

    /* Make sure we wrote the entire buffer */
    assert(offset == bytes + input_size);

out:
    c_kzg_free(bytes);
    return ret;
}

/**
 * Helper function to compare two commitments.
 *
 * @param[in]   a   The first commitment
 * @param[in]   b   The second commitment
 *
 * @return True if the commitments are the same, otherwise false.
 */
static bool commitments_equal(const Bytes48 *a, const Bytes48 *b) {
    return memcmp(a->bytes, b->bytes, BYTES_PER_COMMITMENT) == 0;
}

/**
 * Helper function to copy one commitment's bytes to another.
 *
 * @param[in]   dst   The destination commitment
 * @param[in]   src   The source commitment
 */
static void commitments_copy(Bytes48 *dst, const Bytes48 *src) {
    memcpy(dst->bytes, src->bytes, BYTES_PER_COMMITMENT);
}

/**
 * Convert a list of commitments with potential duplicates to a list of unique commitments. Also
 * returns a list of indices which point to those new unique commitments.
 *
 * @param[in,out]   commitments_out Updated to only contain unique commitments
 * @param[out]      indices_out     Used as map between old/new commitments
 * @param[in,out]   count_out       Number of commitments before and after
 *
 * @remark The input arrays are re-used.
 * @remark The number of commitments/indices must be the same.
 * @remark The length of `indices_out` is unchanged.
 * @remark `count_out` is updated to be the number of unique commitments.
 */
static void deduplicate_commitments(
    Bytes48 *commitments_out, uint64_t *indices_out, size_t *count_out
) {
    /* Bail early if there are no commitments */
    if (*count_out == 0) return;

    /* The first commitment is always new */
    indices_out[0] = 0;
    size_t new_count = 1;

    /* Create list of unique commitments & indices to them */
    for (size_t i = 1; i < *count_out; i++) {
        bool exist = false;
        for (size_t j = 0; j < new_count; j++) {
            if (commitments_equal(&commitments_out[i], &commitments_out[j])) {
                /* This commitment already exists */
                indices_out[i] = j;
                exist = true;
                break;
            }
        }
        if (!exist) {
            /* This is a new commitment */
            commitments_copy(&commitments_out[new_count], &commitments_out[i]);
            indices_out[i] = new_count;
            new_count++;
        }
    }

    /* Update the count */
    *count_out = new_count;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Functions for EIP-7594
////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Given a blob, get all of its cells and proofs.
 *
 * @param[out]  cells   An array of CELLS_PER_EXT_BLOB cells
 * @param[out]  proofs  An array of CELLS_PER_EXT_BLOB proofs
 * @param[in]   blob    The blob to get cells/proofs for
 * @param[in]   s       The trusted setup
 *
 * @remark Up to half of these cells may be lost.
 * @remark Use recover_cells_and_kzg_proofs for recovery.
 * @remark If cells is NULL, they won't be computed.
 * @remark If proofs is NULL, they won't be computed.
 * @remark Will return an error if both cells & proofs are NULL.
 */
C_KZG_RET compute_cells_and_kzg_proofs(
    Cell *cells, KZGProof *proofs, const Blob *blob, const KZGSettings *s
) {
    C_KZG_RET ret;
    fr_t *poly_monomial = NULL;
    fr_t *poly_lagrange = NULL;
    fr_t *data_fr = NULL;
    g1_t *proofs_g1 = NULL;

    /* If both of these are null, something is wrong */
    if (cells == NULL && proofs == NULL) {
        return C_KZG_BADARGS;
    }

    /* Allocate space fr-form arrays */
    ret = new_fr_array(&poly_monomial, FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&poly_lagrange, FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;

    /*
     * Convert the blob to a polynomial in lagrange form. Note that only the first 4096 fields of
     * the polynomial will be set. The upper 4096 fields will remain zero. This is required because
     * the polynomial will be evaluated with 8192 roots of unity.
     */
    ret = blob_to_polynomial(poly_lagrange, blob);
    if (ret != C_KZG_OK) goto out;

    /* We need the polynomial to be in monomial form */
    ret = poly_lagrange_to_monomial(poly_monomial, poly_lagrange, FIELD_ELEMENTS_PER_BLOB, s);
    if (ret != C_KZG_OK) goto out;

    if (cells != NULL) {
        /* Allocate space for our data points */
        ret = new_fr_array(&data_fr, FIELD_ELEMENTS_PER_EXT_BLOB);
        if (ret != C_KZG_OK) goto out;

        /* Get the data points via forward transformation */
        ret = fr_fft(data_fr, poly_monomial, FIELD_ELEMENTS_PER_EXT_BLOB, s);
        if (ret != C_KZG_OK) goto out;

        /* Bit-reverse the data points */
        ret = bit_reversal_permutation(data_fr, sizeof(fr_t), FIELD_ELEMENTS_PER_EXT_BLOB);
        if (ret != C_KZG_OK) goto out;

        /* Convert all of the cells to byte-form */
        for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
            for (size_t j = 0; j < FIELD_ELEMENTS_PER_CELL; j++) {
                size_t index = i * FIELD_ELEMENTS_PER_CELL + j;
                size_t offset = j * BYTES_PER_FIELD_ELEMENT;
                bytes_from_bls_field((Bytes32 *)&cells[i].bytes[offset], &data_fr[index]);
            }
        }
    }

    if (proofs != NULL) {
        /* Allocate space for our proofs in g1-form */
        ret = new_g1_array(&proofs_g1, CELLS_PER_EXT_BLOB);
        if (ret != C_KZG_OK) goto out;

        /* Compute the proofs, provide only the first half */
        ret = compute_fk20_proofs(proofs_g1, poly_monomial, FIELD_ELEMENTS_PER_BLOB, s);
        if (ret != C_KZG_OK) goto out;

        /* Bit-reverse the proofs */
        ret = bit_reversal_permutation(proofs_g1, sizeof(g1_t), CELLS_PER_EXT_BLOB);
        if (ret != C_KZG_OK) goto out;

        /* Convert all of the proofs to byte-form */
        for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
            bytes_from_g1(&proofs[i], &proofs_g1[i]);
        }
    }

out:
    c_kzg_free(poly_monomial);
    c_kzg_free(poly_lagrange);
    c_kzg_free(data_fr);
    c_kzg_free(proofs_g1);
    return ret;
}

/**
 * Given some cells for a blob, recover all cells/proofs.
 *
 * @param[out]  recovered_cells     An array of CELLS_PER_EXT_BLOB cells
 * @param[out]  recovered_proofs    An array of CELLS_PER_EXT_BLOB proofs
 * @param[in]   cell_indices        The cell indices for the cells
 * @param[in]   cells               The cells to check
 * @param[in]   num_cells           The number of cells provided
 * @param[in]   s                   The trusted setup
 *
 * @remark Recovery is faster if there are fewer missing cells.
 * @remark If recovered_proofs is NULL, they will not be recomputed.
 */
C_KZG_RET recover_cells_and_kzg_proofs(
    Cell *recovered_cells,
    KZGProof *recovered_proofs,
    const uint64_t *cell_indices,
    const Cell *cells,
    size_t num_cells,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    fr_t *recovered_cells_fr = NULL;
    g1_t *recovered_proofs_g1 = NULL;
    Blob *blob = NULL;

    /* Ensure only one blob's worth of cells was provided */
    if (num_cells > CELLS_PER_EXT_BLOB) {
        ret = C_KZG_BADARGS;
        goto out;
    }

    /* Check if it's possible to recover */
    if (num_cells < CELLS_PER_EXT_BLOB / 2) {
        ret = C_KZG_BADARGS;
        goto out;
    }

    /* Check that cell indices are valid */
    for (size_t i = 0; i < num_cells; i++) {
        if (cell_indices[i] >= CELLS_PER_EXT_BLOB) {
            ret = C_KZG_BADARGS;
            goto out;
        }
    }

    /* Do allocations */
    ret = new_fr_array(&recovered_cells_fr, FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = new_g1_array(&recovered_proofs_g1, CELLS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = c_kzg_malloc((void **)&blob, BYTES_PER_BLOB);
    if (ret != C_KZG_OK) goto out;

    /* Initialize all cells as missing */
    for (size_t i = 0; i < FIELD_ELEMENTS_PER_EXT_BLOB; i++) {
        recovered_cells_fr[i] = FR_NULL;
    }

    /* Update with existing cells */
    for (size_t i = 0; i < num_cells; i++) {
        size_t index = cell_indices[i] * FIELD_ELEMENTS_PER_CELL;
        for (size_t j = 0; j < FIELD_ELEMENTS_PER_CELL; j++) {
            fr_t *field = &recovered_cells_fr[index + j];

            /*
             * Check if the field has already been set. If it has, there was a duplicate cell index
             * and we can return an error. The compiler will optimize this and the overhead is
             * practically zero.
             */
            if (!fr_is_null(field)) {
                ret = C_KZG_BADARGS;
                goto out;
            }

            /* Convert the untrusted bytes to a field element */
            size_t offset = j * BYTES_PER_FIELD_ELEMENT;
            ret = bytes_to_bls_field(field, (Bytes32 *)&cells[i].bytes[offset]);
            if (ret != C_KZG_OK) goto out;
        }
    }

    if (num_cells == CELLS_PER_EXT_BLOB) {
        /* Nothing to recover, copy the cells */
        memcpy(recovered_cells, cells, CELLS_PER_EXT_BLOB * sizeof(Cell));
    } else {
        /* Perform cell recovery */
        ret = recover_cells(recovered_cells_fr, cell_indices, num_cells, recovered_cells_fr, s);
        if (ret != C_KZG_OK) goto out;

        /* Convert the recovered data points to byte-form */
        for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
            for (size_t j = 0; j < FIELD_ELEMENTS_PER_CELL; j++) {
                size_t index = i * FIELD_ELEMENTS_PER_CELL + j;
                size_t offset = j * BYTES_PER_FIELD_ELEMENT;
                bytes_from_bls_field(
                    (Bytes32 *)&recovered_cells[i].bytes[offset], &recovered_cells_fr[index]
                );
            }
        }
    }

    if (recovered_proofs != NULL) {
        /*
         * Instead of converting the cells to a blob and back, we can just treat the cells as a
         * polynomial. We are done with the fr-form recovered cells and we can safely mutate the
         * array.
         */
        ret = poly_lagrange_to_monomial(
            recovered_cells_fr, recovered_cells_fr, FIELD_ELEMENTS_PER_EXT_BLOB, s
        );
        if (ret != C_KZG_OK) goto out;

        /* Compute the proofs, provide only the first half */
        ret = compute_fk20_proofs(
            recovered_proofs_g1, recovered_cells_fr, FIELD_ELEMENTS_PER_BLOB, s
        );
        if (ret != C_KZG_OK) goto out;

        /* Bit-reverse the proofs */
        ret = bit_reversal_permutation(recovered_proofs_g1, sizeof(g1_t), CELLS_PER_EXT_BLOB);
        if (ret != C_KZG_OK) goto out;

        /* Convert all of the proofs to byte-form */
        for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
            bytes_from_g1(&recovered_proofs[i], &recovered_proofs_g1[i]);
        }
    }

out:
    c_kzg_free(recovered_cells_fr);
    c_kzg_free(recovered_proofs_g1);
    c_kzg_free(blob);
    return ret;
}

/**
 * Given some cells, verify that their proofs are valid.
 *
 * @param[out]  ok                  True if the proofs are valid
 * @param[in]   commitments_bytes   The commitments for the cells
 * @param[in]   cell_indices        The cell indices for the cells
 * @param[in]   cells               The cells to check
 * @param[in]   proofs_bytes        The proofs for the cells
 * @param[in]   num_cells           The number of cells provided
 * @param[in]   s                   The trusted setup
 *
 * @remark cells[i] is associated with commitments_bytes[commitment_indices[i]].
 */
C_KZG_RET verify_cell_kzg_proof_batch(
    bool *ok,
    const Bytes48 *commitments_bytes,
    const uint64_t *cell_indices,
    const Cell *cells,
    const Bytes48 *proofs_bytes,
    size_t num_cells,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    g1_t evaluation;
    g1_t final_g1_sum;
    g1_t proof_lincomb;
    g1_t weighted_proof_lincomb;
    g2_t power_of_s = s->g2_values_monomial[FIELD_ELEMENTS_PER_CELL];
    size_t num_commitments;

    /* Arrays */
    Bytes48 *unique_commitments = NULL;
    uint64_t *commitment_indices = NULL;
    bool *is_cell_used = NULL;
    fr_t *aggregated_column_cells = NULL;
    fr_t *aggregated_interpolation_poly = NULL;
    fr_t *column_interpolation_poly = NULL;
    fr_t *commitment_weights = NULL;
    fr_t *r_powers = NULL;
    fr_t *weighted_powers_of_r = NULL;
    fr_t *weights = NULL;
    g1_t *commitments_g1 = NULL;
    g1_t *proofs_g1 = NULL;

    *ok = false;

    /* Exit early if we are given zero cells */
    if (num_cells == 0) {
        *ok = true;
        return C_KZG_OK;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Sanity checks
    ////////////////////////////////////////////////////////////////////////////////////////////////

    for (size_t i = 0; i < num_cells; i++) {
        /* Make sure column index is valid */
        if (cell_indices[i] >= CELLS_PER_EXT_BLOB) return C_KZG_BADARGS;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Deduplicate Commitments
    ////////////////////////////////////////////////////////////////////////////////////////////////

    ret = c_kzg_calloc((void **)&unique_commitments, num_cells, sizeof(Bytes48));
    if (ret != C_KZG_OK) goto out;
    ret = c_kzg_calloc((void **)&commitment_indices, num_cells, sizeof(uint64_t));
    if (ret != C_KZG_OK) goto out;

    /*
     * Convert the array of cell commitments to an array of unique commitments and an array of
     * indices to those unique commitments. We do this before the array allocations section below
     * because we need to know how many commitment weights there will be.
     */
    num_commitments = num_cells;
    memcpy(unique_commitments, commitments_bytes, num_cells * sizeof(Bytes48));
    deduplicate_commitments(unique_commitments, commitment_indices, &num_commitments);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Array allocations
    ////////////////////////////////////////////////////////////////////////////////////////////////

    ret = new_bool_array(&is_cell_used, FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&aggregated_column_cells, FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&aggregated_interpolation_poly, FIELD_ELEMENTS_PER_CELL);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&column_interpolation_poly, FIELD_ELEMENTS_PER_CELL);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&commitment_weights, num_commitments);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&r_powers, num_cells);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&weighted_powers_of_r, num_cells);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&weights, num_cells);
    if (ret != C_KZG_OK) goto out;
    ret = new_g1_array(&commitments_g1, num_commitments);
    if (ret != C_KZG_OK) goto out;
    ret = new_g1_array(&proofs_g1, num_cells);
    if (ret != C_KZG_OK) goto out;

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Compute random linear combination of the proofs
    ////////////////////////////////////////////////////////////////////////////////////////////////

    /*
     * Derive random factors for the linear combination. The exponents start with 0. That is, they
     * are r^0, r^1, r^2, r^3, and so on.
     */
    ret = compute_r_powers_for_verify_cell_kzg_proof_batch(
        r_powers,
        unique_commitments,
        num_commitments,
        commitment_indices,
        cell_indices,
        cells,
        proofs_bytes,
        num_cells
    );
    if (ret != C_KZG_OK) goto out;

    /* There should be a proof for each cell */
    for (size_t i = 0; i < num_cells; i++) {
        ret = bytes_to_kzg_proof(&proofs_g1[i], &proofs_bytes[i]);
        if (ret != C_KZG_OK) goto out;
    }

    /* Do the linear combination */
    ret = g1_lincomb_fast(&proof_lincomb, proofs_g1, r_powers, num_cells);
    if (ret != C_KZG_OK) goto out;

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Compute sum of the commitments
    ////////////////////////////////////////////////////////////////////////////////////////////////

    for (size_t i = 0; i < num_commitments; i++) {
        /* Convert & validate commitment */
        ret = bytes_to_kzg_commitment(&commitments_g1[i], &unique_commitments[i]);
        if (ret != C_KZG_OK) goto out;

        /* Initialize the weight to zero */
        commitment_weights[i] = FR_ZERO;
    }

    /* Update commitment weights */
    for (size_t i = 0; i < num_cells; i++) {
        blst_fr_add(
            &commitment_weights[commitment_indices[i]],
            &commitment_weights[commitment_indices[i]],
            &r_powers[i]
        );
    }

    /* Compute commitment sum */
    ret = g1_lincomb_fast(&final_g1_sum, commitments_g1, commitment_weights, num_commitments);
    if (ret != C_KZG_OK) goto out;

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Compute aggregated columns
    ////////////////////////////////////////////////////////////////////////////////////////////////

    /* Start with zeroed out columns */
    for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
        for (size_t j = 0; j < FIELD_ELEMENTS_PER_CELL; j++) {
            size_t index = i * FIELD_ELEMENTS_PER_CELL + j;
            aggregated_column_cells[index] = FR_ZERO;
        }
    }

    /* Scale each cell's data points */
    for (size_t i = 0; i < num_cells; i++) {
        for (size_t j = 0; j < FIELD_ELEMENTS_PER_CELL; j++) {
            fr_t field, scaled;
            size_t offset = j * BYTES_PER_FIELD_ELEMENT;
            ret = bytes_to_bls_field(&field, (Bytes32 *)&cells[i].bytes[offset]);
            if (ret != C_KZG_OK) goto out;
            blst_fr_mul(&scaled, &field, &r_powers[i]);
            size_t index = cell_indices[i] * FIELD_ELEMENTS_PER_CELL + j;
            blst_fr_add(&aggregated_column_cells[index], &aggregated_column_cells[index], &scaled);

            /* Mark the cell as being used */
            is_cell_used[index] = true;
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Compute sum of the interpolation polynomials
    ////////////////////////////////////////////////////////////////////////////////////////////////

    /* Start with a zeroed out poly */
    for (size_t i = 0; i < FIELD_ELEMENTS_PER_CELL; i++) {
        aggregated_interpolation_poly[i] = FR_ZERO;
    }

    /* Interpolate each column */
    for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
        /* Offset to the first cell for this column */
        size_t index = i * FIELD_ELEMENTS_PER_CELL;

        /* We only care about initialized cells */
        if (!is_cell_used[index]) continue;

        /* We don't need to copy this because it's not used again */
        ret = bit_reversal_permutation(
            &aggregated_column_cells[index], sizeof(fr_t), FIELD_ELEMENTS_PER_CELL
        );
        if (ret != C_KZG_OK) goto out;

        /*
         * Get interpolation polynomial for this column. To do so we first do an IDFT over the roots
         * of unity and then we scale by the coset factor.  We can't do an IDFT directly over the
         * coset because it's not a subgroup.
         */
        ret = fr_ifft(
            column_interpolation_poly, &aggregated_column_cells[index], FIELD_ELEMENTS_PER_CELL, s
        );
        if (ret != C_KZG_OK) goto out;

        /*
         * To unscale, divide by the coset. It's faster to multiply with the inverse. We can skip
         * the first iteration because its dividing by one.
         */
        uint32_t pos = reverse_bits_limited(CELLS_PER_EXT_BLOB, i);
        fr_t inv_coset_factor;
        blst_fr_eucl_inverse(&inv_coset_factor, &s->roots_of_unity[pos]);
        shift_poly(column_interpolation_poly, FIELD_ELEMENTS_PER_CELL, &inv_coset_factor);

        /* Update the aggregated poly */
        for (size_t k = 0; k < FIELD_ELEMENTS_PER_CELL; k++) {
            blst_fr_add(
                &aggregated_interpolation_poly[k],
                &aggregated_interpolation_poly[k],
                &column_interpolation_poly[k]
            );
        }
    }

    /* Commit to the final aggregated interpolation polynomial */
    ret = g1_lincomb_fast(
        &evaluation, s->g1_values_monomial, aggregated_interpolation_poly, FIELD_ELEMENTS_PER_CELL
    );
    if (ret != C_KZG_OK) goto out;

    blst_p1_cneg(&evaluation, true);
    blst_p1_add(&final_g1_sum, &final_g1_sum, &evaluation);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Compute sum of the proofs scaled by the coset factors
    ////////////////////////////////////////////////////////////////////////////////////////////////

    for (size_t i = 0; i < num_cells; i++) {
        uint32_t pos = reverse_bits_limited(CELLS_PER_EXT_BLOB, cell_indices[i]);
        fr_t coset_factor = s->roots_of_unity[pos];
        fr_pow(&weights[i], &coset_factor, FIELD_ELEMENTS_PER_CELL);
        blst_fr_mul(&weighted_powers_of_r[i], &r_powers[i], &weights[i]);
    }

    ret = g1_lincomb_fast(&weighted_proof_lincomb, proofs_g1, weighted_powers_of_r, num_cells);
    if (ret != C_KZG_OK) goto out;

    blst_p1_add(&final_g1_sum, &final_g1_sum, &weighted_proof_lincomb);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Do the final pairing check
    ////////////////////////////////////////////////////////////////////////////////////////////////

    *ok = pairings_verify(&final_g1_sum, blst_p2_generator(), &proof_lincomb, &power_of_s);

out:
    c_kzg_free(unique_commitments);
    c_kzg_free(commitment_indices);
    c_kzg_free(is_cell_used);
    c_kzg_free(aggregated_column_cells);
    c_kzg_free(aggregated_interpolation_poly);
    c_kzg_free(column_interpolation_poly);
    c_kzg_free(commitment_weights);
    c_kzg_free(r_powers);
    c_kzg_free(weighted_powers_of_r);
    c_kzg_free(weights);
    c_kzg_free(commitments_g1);
    c_kzg_free(proofs_g1);
    return ret;
}
