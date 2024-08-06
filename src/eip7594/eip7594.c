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
#include "eip7594/poly.h"

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
// Helper Functions
////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Reverse the low-order bits in a 32-bit integer.
 *
 * @param[in]   n       To reverse `b` bits, set `n = 2 ^ b`
 * @param[in]   value   The bits to be reversed
 *
 * @return The reversal of the lowest log_2(n) bits of the input value.
 *
 * @remark n must be a power of two.
 */
static uint32_t reverse_bits_limited(uint32_t n, uint32_t value) {
    size_t unused_bit_len = 32 - log2_pow2(n);
    return reverse_bits(value) >> unused_bit_len;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Vanishing Polynomial
////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Calculates the minimal polynomial that evaluates to zero for each root.
 *
 * Uses straightforward long multiplication to calculate the product of `(x - r_i)` where `r_i` is
 * the i'th root. This results in a poly of degree roots_len.
 *
 * @param[in,out]   poly         The zero polynomial for roots
 * @param[in,out]   poly_len     The length of poly
 * @param[in]       roots        The array of roots
 * @param[in]       roots_len    The number of roots
 * @param[in]       s            The trusted setup
 *
 * @remark These do not have to be roots of unity. They are roots of a polynomial.
 * @remark `poly_len` must be at least `roots_len + 1` in length.
 */
static C_KZG_RET compute_vanishing_polynomial_from_roots(
    fr_t *poly, size_t *poly_len, const fr_t *roots, size_t roots_len
) {
    fr_t neg_root;

    if (roots_len == 0) {
        return C_KZG_BADARGS;
    }

    /* Initialize with -root[0] */
    blst_fr_cneg(&poly[0], &roots[0], true);

    for (size_t i = 1; i < roots_len; i++) {
        blst_fr_cneg(&neg_root, &roots[i], true);

        poly[i] = neg_root;
        blst_fr_add(&poly[i], &poly[i], &poly[i - 1]);

        for (size_t j = i - 1; j > 0; j--) {
            blst_fr_mul(&poly[j], &poly[j], &neg_root);
            blst_fr_add(&poly[j], &poly[j], &poly[j - 1]);
        }
        blst_fr_mul(&poly[0], &poly[0], &neg_root);
    }

    poly[roots_len] = FR_ONE;
    *poly_len = roots_len + 1;

    return C_KZG_OK;
}

/**
 * Computes the minimal polynomial that evaluates to zero at equally spaced chosen roots of unity in
 * the domain of size `FIELD_ELEMENTS_PER_BLOB`.
 *
 * The roots of unity are chosen based on the missing cell indices. If the i'th cell is missing,
 * then the i'th root of unity from `roots_of_unity` will be zero on the polynomial
 * computed, along with every `CELLS_PER_EXT_BLOB` spaced root of unity in the domain.
 *
 * @param[in,out]   vanishing_poly          The vanishing polynomial
 * @param[in]       missing_cell_indices    The array of missing cell indices
 * @param[in]       len_missing_cells       The number of missing cell indices
 * @param[in]       s                       The trusted setup
 *
 * @remark When all of the cells are missing, this algorithm has an edge case. We return
 * C_KZG_BADARGS in that case.
 * @remark When none of the cells are missing, recovery is trivial. We expect the caller to handle
 * this case, and return C_KZG_BADARGS if not.
 * @remark `missing_cell_indices` are assumed to be less than `CELLS_PER_EXT_BLOB`.
 */
static C_KZG_RET vanishing_polynomial_for_missing_cells(
    fr_t *vanishing_poly,
    const uint64_t *missing_cell_indices,
    size_t len_missing_cells,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    fr_t *roots = NULL;
    fr_t *short_vanishing_poly = NULL;
    size_t short_vanishing_poly_len = 0;

    /* Return early if none or all of the cells are missing */
    if (len_missing_cells == 0 || len_missing_cells == CELLS_PER_EXT_BLOB) {
        ret = C_KZG_BADARGS;
        goto out;
    }

    /* Allocate arrays */
    ret = new_fr_array(&roots, len_missing_cells);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&short_vanishing_poly, (len_missing_cells + 1));
    if (ret != C_KZG_OK) goto out;

    /*
     * For each missing cell index, choose the corresponding root of unity from the subgroup of
     * size `CELLS_PER_EXT_BLOB`.
     *
     * In other words, if the missing index is `i`, then we add \omega^i to the roots array, where
     * \omega is a primitive `CELLS_PER_EXT_BLOB` root of unity.
     */
    size_t stride = FIELD_ELEMENTS_PER_EXT_BLOB / CELLS_PER_EXT_BLOB;
    for (size_t i = 0; i < len_missing_cells; i++) {
        roots[i] = s->roots_of_unity[missing_cell_indices[i] * stride];
    }

    /* Compute the polynomial that evaluates to zero on the roots */
    ret = compute_vanishing_polynomial_from_roots(
        short_vanishing_poly, &short_vanishing_poly_len, roots, len_missing_cells
    );
    if (ret != C_KZG_OK) goto out;

    /*
     * For each root \omega^i in `short_vanishing_poly`, we compute a polynomial that has roots at
     *
     *  H = {
     *      \omega^i * \gamma^0,
     *      \omega^i * \gamma^1,
     *      ...,
     *      \omega^i * \gamma^{FIELD_ELEMENTS_PER_CELL-1}
     *  }
     *
     * where \gamma is a primitive `FIELD_ELEMENTS_PER_EXT_BLOB`-th root of unity.
     *
     * This is done by shifting the degree of all coefficients in `short_vanishing_poly` up by
     * `FIELD_ELEMENTS_PER_CELL` amount.
     */
    for (size_t i = 0; i < short_vanishing_poly_len; i++) {
        vanishing_poly[i * FIELD_ELEMENTS_PER_CELL] = short_vanishing_poly[i];
    }

out:
    c_kzg_free(roots);
    c_kzg_free(short_vanishing_poly);
    return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Cell Recovery
////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Helper function to check if a uint64 value is in an array.
 *
 * @param[in]   arr         The array
 * @param[in]   arr_size    The size of the array
 * @param[in]   value       The value we want to search
 *
 * @return True if the value is in the array, otherwise false.
 */
static bool is_in_array(const uint64_t *arr, size_t arr_size, uint64_t value) {
    for (size_t i = 0; i < arr_size; i++) {
        if (arr[i] == value) {
            return true;
        }
    }
    return false;
}

/**
 * Given a dataset with up to half the entries missing, return the reconstructed original. Assumes
 * that the inverse FFT of the original data has the upper half of its values equal to zero.
 *
 * @param[out]  reconstructed_data_out   Preallocated array for recovered cells
 * @param[in]   cell_indices             The cell indices you have
 * @param[in]   num_cells                The number of cells that you have
 * @param[in]   cells                    The cells that you have
 * @param[in]   s                        The trusted setup
 *
 * @remark `recovered` and `cells` can point to the same memory.
 * @remark The array of cells must be 2n length and in the correct order.
 * @remark Missing cells should be equal to FR_NULL.
 */
static C_KZG_RET recover_cells_impl(
    fr_t *reconstructed_data_out,
    const uint64_t *cell_indices,
    size_t num_cells,
    fr_t *cells,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    uint64_t *missing_cell_indices = NULL;
    fr_t *vanishing_poly_eval = NULL;
    fr_t *vanishing_poly_coeff = NULL;
    fr_t *extended_evaluation_times_zero = NULL;
    fr_t *extended_evaluation_times_zero_coeffs = NULL;
    fr_t *extended_evaluations_over_coset = NULL;
    fr_t *vanishing_poly_over_coset = NULL;
    fr_t *reconstructed_poly_coeff = NULL;
    fr_t *cells_brp = NULL;

    /* Allocate space for arrays */
    ret = c_kzg_calloc(
        (void **)&missing_cell_indices, FIELD_ELEMENTS_PER_EXT_BLOB, sizeof(uint64_t)
    );
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&vanishing_poly_eval, FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&vanishing_poly_coeff, FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&extended_evaluation_times_zero, FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&extended_evaluation_times_zero_coeffs, FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&extended_evaluations_over_coset, FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&vanishing_poly_over_coset, FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&reconstructed_poly_coeff, FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&cells_brp, FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;

    /* Bit-reverse the data points, stored in new array */
    memcpy(cells_brp, cells, FIELD_ELEMENTS_PER_EXT_BLOB * sizeof(fr_t));
    ret = bit_reversal_permutation(cells_brp, sizeof(fr_t), FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;

    /* Identify missing cells */
    size_t len_missing = 0;
    for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
        /* Iterate over each cell index and check if we have received it */
        if (!is_in_array(cell_indices, num_cells, i)) {
            /*
             * If the cell is missing, bit reverse the index and add it to the
             * missing array.
             */
            uint32_t brp_i = reverse_bits_limited(CELLS_PER_EXT_BLOB, i);
            missing_cell_indices[len_missing++] = brp_i;
        }
    }

    /* Check that we have enough cells */
    assert(len_missing <= CELLS_PER_EXT_BLOB / 2);

    /* Compute Z(x) in monomial form */
    ret = vanishing_polynomial_for_missing_cells(
        vanishing_poly_coeff, missing_cell_indices, len_missing, s
    );
    if (ret != C_KZG_OK) goto out;

    /* Convert Z(x) to evaluation form */
    ret = fr_fft(vanishing_poly_eval, vanishing_poly_coeff, FIELD_ELEMENTS_PER_EXT_BLOB, s);
    if (ret != C_KZG_OK) goto out;

    /* Compute (E*Z)(x) = E(x) * Z(x) in evaluation form over the FFT domain */
    for (size_t i = 0; i < FIELD_ELEMENTS_PER_EXT_BLOB; i++) {
        if (fr_is_null(&cells_brp[i])) {
            extended_evaluation_times_zero[i] = FR_ZERO;
        } else {
            blst_fr_mul(&extended_evaluation_times_zero[i], &cells_brp[i], &vanishing_poly_eval[i]);
        }
    }

    /* Convert (E*Z)(x) to monomial form  */
    ret = fr_ifft(
        extended_evaluation_times_zero_coeffs,
        extended_evaluation_times_zero,
        FIELD_ELEMENTS_PER_EXT_BLOB,
        s
    );
    if (ret != C_KZG_OK) goto out;

    /*
     * Polynomial division by convolution: Q3 = Q1 / Q2 where
     *   Q1 = (D * Z_r,I)(k * x)
     *   Q2 = Z_r,I(k * x)
     *   Q3 = D(k * x)
     */
    ret = coset_fft(
        extended_evaluations_over_coset,
        extended_evaluation_times_zero_coeffs,
        FIELD_ELEMENTS_PER_EXT_BLOB,
        s
    );
    if (ret != C_KZG_OK) goto out;

    ret = coset_fft(
        vanishing_poly_over_coset, vanishing_poly_coeff, FIELD_ELEMENTS_PER_EXT_BLOB, s
    );
    if (ret != C_KZG_OK) goto out;

    /* The result of the division is Q3 */
    for (size_t i = 0; i < FIELD_ELEMENTS_PER_EXT_BLOB; i++) {
        fr_div(
            &extended_evaluations_over_coset[i],
            &extended_evaluations_over_coset[i],
            &vanishing_poly_over_coset[i]
        );
    }

    /*
     * Note: After the above polynomial division, extended_evaluations_over_coset is the same
     * polynomial as reconstructed_poly_over_coset in the spec.
     */

    /* Convert the evaluations back to coefficents */
    ret = coset_ifft(
        reconstructed_poly_coeff, extended_evaluations_over_coset, FIELD_ELEMENTS_PER_EXT_BLOB, s
    );
    if (ret != C_KZG_OK) goto out;

    /*
     * After unscaling the reconstructed polynomial, we have D(x) which evaluates to our original
     * data at the roots of unity. Next, we evaluate the polynomial to get the original data.
     */
    ret = fr_fft(reconstructed_data_out, reconstructed_poly_coeff, FIELD_ELEMENTS_PER_EXT_BLOB, s);
    if (ret != C_KZG_OK) goto out;

    /* Bit-reverse the recovered data points */
    ret = bit_reversal_permutation(
        reconstructed_data_out, sizeof(fr_t), FIELD_ELEMENTS_PER_EXT_BLOB
    );
    if (ret != C_KZG_OK) goto out;

out:
    c_kzg_free(missing_cell_indices);
    c_kzg_free(vanishing_poly_eval);
    c_kzg_free(extended_evaluation_times_zero);
    c_kzg_free(extended_evaluation_times_zero_coeffs);
    c_kzg_free(extended_evaluations_over_coset);
    c_kzg_free(vanishing_poly_over_coset);
    c_kzg_free(reconstructed_poly_coeff);
    c_kzg_free(vanishing_poly_coeff);
    c_kzg_free(cells_brp);
    return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Cell Proofs
////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Reorder and extend polynomial coefficients for the toeplitz method, strided version.
 *
 * @param[out]  out     The reordered polynomial, size `n * 2 / stride`
 * @param[in]   in      The input polynomial, size `n`
 * @param[in]   n       The size of the input polynomial
 * @param[in]   offset  The offset
 * @param[in]   stride  The stride
 */
static C_KZG_RET toeplitz_coeffs_stride(
    fr_t *out, const fr_t *in, size_t n, uint64_t offset, uint64_t stride
) {
    uint64_t k, k2;

    if (stride == 0) return C_KZG_BADARGS;

    k = n / stride;
    k2 = k * 2;

    out[0] = in[n - 1 - offset];
    for (uint64_t i = 1; i <= k + 1 && i < k2; i++) {
        out[i] = FR_ZERO;
    }
    for (uint64_t i = k + 2, j = 2 * stride - offset - 1; i < k2; i++, j += stride) {
        out[i] = in[j];
    }

    return C_KZG_OK;
}

/**
 * Compute FK20 cell-proofs for a polynomial.
 *
 * @param[out]  out An array of CELLS_PER_EXT_BLOB proofs
 * @param[in]   p   The polynomial, an array of coefficients
 * @param[in]   n   The length of the polynomial
 * @param[in]   s   The trusted setup
 *
 * @remark The polynomial should have FIELD_ELEMENTS_PER_BLOB coefficients. Only the lower half of
 * the extended polynomial is supplied because the upper half is assumed to be zero.
 */
static C_KZG_RET compute_fk20_proofs(g1_t *out, const fr_t *p, size_t n, const KZGSettings *s) {
    C_KZG_RET ret;
    uint64_t k, k2;

    blst_scalar *scalars = NULL;
    fr_t **coeffs = NULL;
    fr_t *toeplitz_coeffs = NULL;
    fr_t *toeplitz_coeffs_fft = NULL;
    g1_t *h = NULL;
    g1_t *h_ext_fft = NULL;
    void *scratch = NULL;
    bool precompute = s->wbits != 0;

    /* Initialize length variables */
    k = n / FIELD_ELEMENTS_PER_CELL;
    k2 = k * 2;

    /* Do allocations */
    ret = new_fr_array(&toeplitz_coeffs, k2);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&toeplitz_coeffs_fft, k2);
    if (ret != C_KZG_OK) goto out;
    ret = new_g1_array(&h_ext_fft, k2);
    if (ret != C_KZG_OK) goto out;
    ret = new_g1_array(&h, k2);
    if (ret != C_KZG_OK) goto out;

    if (precompute) {
        /* Allocations for fixed-base MSM */
        ret = c_kzg_malloc(&scratch, s->scratch_size);
        if (ret != C_KZG_OK) goto out;
        ret = c_kzg_calloc((void **)&scalars, FIELD_ELEMENTS_PER_CELL, sizeof(blst_scalar));
        if (ret != C_KZG_OK) goto out;
    }

    /* Allocate 2d array for coefficients by column */
    ret = c_kzg_calloc((void **)&coeffs, k2, sizeof(void *));
    if (ret != C_KZG_OK) goto out;
    for (uint64_t i = 0; i < k2; i++) {
        ret = new_fr_array(&coeffs[i], k);
        if (ret != C_KZG_OK) goto out;
    }

    /* Initialize values to zero */
    for (uint64_t i = 0; i < k2; i++) {
        h_ext_fft[i] = G1_IDENTITY;
    }

    /* Compute toeplitz coefficients and organize by column */
    for (uint64_t i = 0; i < FIELD_ELEMENTS_PER_CELL; i++) {
        ret = toeplitz_coeffs_stride(toeplitz_coeffs, p, n, i, FIELD_ELEMENTS_PER_CELL);
        if (ret != C_KZG_OK) goto out;
        ret = fr_fft(toeplitz_coeffs_fft, toeplitz_coeffs, k2, s);
        if (ret != C_KZG_OK) goto out;
        for (uint64_t j = 0; j < k2; j++) {
            coeffs[j][i] = toeplitz_coeffs_fft[j];
        }
    }

    /* Compute h_ext_fft via MSM */
    for (uint64_t i = 0; i < k2; i++) {
        if (precompute) {
            /* Transform the field elements to 255-bit scalars */
            for (uint64_t j = 0; j < FIELD_ELEMENTS_PER_CELL; j++) {
                blst_scalar_from_fr(&scalars[j], &coeffs[i][j]);
            }
            const byte *scalars_arg[2] = {(byte *)scalars, NULL};

            /* A fixed-base MSM with precomputation */
            blst_p1s_mult_wbits(
                &h_ext_fft[i],
                s->tables[i],
                s->wbits,
                FIELD_ELEMENTS_PER_CELL,
                scalars_arg,
                BITS_PER_FIELD_ELEMENT,
                scratch
            );
        } else {
            /* A pretty fast MSM without precomputation */
            ret = g1_lincomb_fast(
                &h_ext_fft[i], s->x_ext_fft_columns[i], coeffs[i], FIELD_ELEMENTS_PER_CELL
            );
            if (ret != C_KZG_OK) goto out;
        }
    }

    ret = g1_ifft(h, h_ext_fft, k2, s);
    if (ret != C_KZG_OK) goto out;

    /* Zero the second half of h */
    for (uint64_t i = k; i < k2; i++) {
        h[i] = G1_IDENTITY;
    }

    ret = g1_fft(out, h, k2, s);
    if (ret != C_KZG_OK) goto out;

out:
    c_kzg_free(scalars);
    if (coeffs != NULL) {
        for (uint64_t i = 0; i < k2; i++) {
            c_kzg_free(coeffs[i]);
        }
        c_kzg_free(coeffs);
    }
    c_kzg_free(toeplitz_coeffs);
    c_kzg_free(toeplitz_coeffs_fft);
    c_kzg_free(h);
    c_kzg_free(h_ext_fft);
    c_kzg_free(scratch);
    return ret;
}

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
        ret = recover_cells_impl(
            recovered_cells_fr, cell_indices, num_cells, recovered_cells_fr, s
        );
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
