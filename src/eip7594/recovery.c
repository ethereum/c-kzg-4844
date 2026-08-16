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

#include "eip7594/recovery.h"
#include "common/alloc.h"
#include "common/fr.h"
#include "common/utils.h"
#include "eip7594/cell.h"
#include "eip7594/fft.h"
#include "eip7594/poly.h"

#include <assert.h> /* For assert */
#include <stdlib.h> /* For NULL */
#include <string.h> /* For memcpy */

////////////////////////////////////////////////////////////////////////////////////////////////////
// Vanishing Polynomial
////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Calculates the minimal polynomial that evaluates to zero for each root.
 *
 * Uses straightforward long multiplication to calculate the product of `(x - r_i)` where `r_i` is
 * the i'th root. This results in a poly of degree roots_len.
 *
 * @param[in,out]   poly        The zero polynomial for roots, length `poly_len`
 * @param[in,out]   poly_len    The length of poly
 * @param[in]       roots       The array of roots, length `roots_len`
 * @param[in]       roots_len   The number of roots
 *
 * @remark These do not have to be roots of unity. They are roots of a polynomial.
 * @remark The `poly` array must be at least `roots_len + 1` in length.
 */
static C_KZG_RET compute_vanishing_polynomial_from_roots(
    fr_t *poly, size_t *poly_len, const fr_t *roots, size_t roots_len
) {
    fr_t neg_root;

    if (roots_len == 0) {
        return C_KZG_BADARGS;
    }

    /* Initialize with -root[0] */
    fr_neg(&poly[0], &roots[0]);

    for (size_t i = 1; i < roots_len; i++) {
        fr_neg(&neg_root, &roots[i]);

        poly[i] = neg_root;
        fr_add(&poly[i], &poly[i], &poly[i - 1]);

        for (size_t j = i - 1; j > 0; j--) {
            fr_mul(&poly[j], &poly[j], &neg_root);
            fr_add(&poly[j], &poly[j], &poly[j - 1]);
        }
        fr_mul(&poly[0], &poly[0], &neg_root);
    }

    poly[roots_len] = FR_ONE;
    *poly_len = roots_len + 1;

    return C_KZG_OK;
}

/**
 * Computes the short factor of the vanishing polynomial for the missing cells.
 *
 * The polynomial that vanishes on the missing evaluations is
 *
 *   Z(x) = Zhat(x^FIELD_ELEMENTS_PER_CELL)
 *
 * where Zhat vanishes on the roots of unity of order CELLS_PER_EXT_BLOB corresponding to the
 * missing cell indices. This returns Zhat, which has degree `len_missing_cells` -- at most 64 --
 * rather than Z, which is spread over FIELD_ELEMENTS_PER_EXT_BLOB coefficients of which all but
 * `len_missing_cells + 1` are zero.
 *
 * @param[out]  short_vanishing_poly        Zhat, length `len_missing_cells + 1`
 * @param[out]  short_vanishing_poly_len    The length of Zhat
 * @param[in]   missing_cell_indices        The array of missing cell indices
 * @param[in]   len_missing_cells           The number of missing cell indices
 * @param[in]   s                           The trusted setup
 *
 * @remark If no cells are missing, recovery is trivial; we expect the caller to handle this.
 * @remark If all cells are missing, we return C_KZG_BADARGS; the algorithm has an edge case.
 */
static C_KZG_RET short_vanishing_polynomial_for_missing_cells(
    fr_t *short_vanishing_poly,
    size_t *short_vanishing_poly_len,
    const uint64_t *missing_cell_indices,
    size_t len_missing_cells,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    fr_t *roots = NULL;

    /* Return early if none or all of the cells are missing */
    if (len_missing_cells == 0 || len_missing_cells >= CELLS_PER_EXT_BLOB) {
        ret = C_KZG_BADARGS;
        goto out;
    }

    ret = new_fr_array(&roots, len_missing_cells);
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

    ret = compute_vanishing_polynomial_from_roots(
        short_vanishing_poly, short_vanishing_poly_len, roots, len_missing_cells
    );
    if (ret != C_KZG_OK) goto out;

out:
    c_kzg_free(roots);
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
 * Given a set of cells with up to half the entries missing, return the reconstructed
 * original. Assumes that the inverse FFT of the original data has the upper half of its values
 * equal to zero.
 *
 * @param[out]  reconstructed_data_out  Array of size FIELD_ELEMENTS_PER_EXT_BLOB to recover cells
 * @param[in]   cell_indices            An array with the available cell indices, length `num_cells`
 * @param[in]   num_cells               The size of the `cell_indices` array
 * @param[in]   cells                   An array of size FIELD_ELEMENTS_PER_EXT_BLOB with the cells
 * @param[in]   s                       The trusted setup
 *
 * @remark `reconstructed_data_out` and `cells` can point to the same memory.
 * @remark The array `cells` must be in the correct order (according to cell_indices).
 */
C_KZG_RET recover_cells(
    fr_t *reconstructed_data_out,
    const uint64_t *cell_indices,
    size_t num_cells,
    fr_t *cells,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    uint64_t *missing_cell_indices = NULL;
    fr_t *short_vanishing_poly = NULL;
    fr_t *short_vanishing_poly_eval = NULL;
    fr_t *vanishing_poly_over_coset = NULL;
    fr_t *inv_vanishing_poly_over_coset = NULL;
    fr_t *extended_evaluation_times_zero = NULL;
    fr_t *extended_evaluation_times_zero_coeffs = NULL;
    fr_t *reconstructed_poly_coeff = NULL;

    /*
     * Sizes of the reduced problem.
     *
     * Z(x) = Zhat(x^FIELD_ELEMENTS_PER_CELL), so its evaluations over the FFT domain repeat with
     * period CELLS_PER_EXT_BLOB: Z(w^j) = Zhat(v^(j mod CELLS_PER_EXT_BLOB)) where v = w^64 has
     * order CELLS_PER_EXT_BLOB. The full-domain transform of Z is therefore a transform of size
     * CELLS_PER_EXT_BLOB, tiled.
     *
     * The recovered polynomial has degree below FIELD_ELEMENTS_PER_BLOB, so the coset round trip
     * that performs the division needs only that many points. Over the smaller coset the period
     * of Z halves again, to CELLS_PER_BLOB.
     */
    const size_t half = FIELD_ELEMENTS_PER_EXT_BLOB / 2;
    const size_t z_period = CELLS_PER_EXT_BLOB;
    const size_t z_period_over_coset = CELLS_PER_BLOB;

    /* Allocate space for arrays */
    ret = c_kzg_calloc(
        (void **)&missing_cell_indices, FIELD_ELEMENTS_PER_EXT_BLOB, sizeof(uint64_t)
    );
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&short_vanishing_poly, z_period);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&short_vanishing_poly_eval, z_period);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&vanishing_poly_over_coset, z_period_over_coset);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&inv_vanishing_poly_over_coset, z_period_over_coset);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&extended_evaluation_times_zero, FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&extended_evaluation_times_zero_coeffs, FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&reconstructed_poly_coeff, FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;

    /* Bit-reverse the data points, stored in new array */
    memcpy(extended_evaluation_times_zero, cells, FIELD_ELEMENTS_PER_EXT_BLOB * sizeof(fr_t));
    ret = bit_reversal_permutation(
        extended_evaluation_times_zero, sizeof(fr_t), FIELD_ELEMENTS_PER_EXT_BLOB
    );
    if (ret != C_KZG_OK) goto out;

    /* Identify missing cells */
    size_t len_missing = 0;
    for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
        /* Iterate over each cell index and check if we have received it */
        if (!is_in_array(cell_indices, num_cells, i)) {
            /* If the cell is missing, bit reverse the index and add it to the missing array */
            uint64_t brp_i = reverse_bits_limited(CELLS_PER_EXT_BLOB, i);
            missing_cell_indices[len_missing++] = brp_i;
        }
    }

    /*
     * Check that we have enough cells to recover.
     * Concretely, we need to have at least CELLS_PER_BLOB many cells.
     */
    assert(CELLS_PER_EXT_BLOB - len_missing >= CELLS_PER_BLOB);

    /*
     * Compute Zhat(x) in monomial form, the short factor of the polynomial which vanishes on all
     * of the evaluations which are missing. Its degree is len_missing, so it fits in z_period
     * coefficients with the remainder zero.
     */
    for (size_t i = 0; i < z_period; i++) {
        short_vanishing_poly[i] = FR_ZERO;
    }
    size_t short_vanishing_poly_len = 0;
    ret = short_vanishing_polynomial_for_missing_cells(
        short_vanishing_poly, &short_vanishing_poly_len, missing_cell_indices, len_missing, s
    );
    if (ret != C_KZG_OK) goto out;

    /*
     * Convert Zhat(x) to evaluation form over the subgroup of order z_period. These are all the
     * distinct values Z takes over the full FFT domain.
     */
    ret = fr_fft(short_vanishing_poly_eval, short_vanishing_poly, z_period, s);
    if (ret != C_KZG_OK) goto out;

    /*
     * Compute (E*Z)(x) = E(x) * Z(x) in evaluation form over the FFT domain.
     *
     * Note: over the FFT domain, the polynomials (E*Z)(x) and (P*Z)(x) agree, where
     * P(x) is the polynomial we want to reconstruct (degree FIELD_ELEMENTS_PER_BLOB - 1).
     */
    for (size_t i = 0; i < FIELD_ELEMENTS_PER_EXT_BLOB; i++) {
        fr_mul(
            &extended_evaluation_times_zero[i],
            &extended_evaluation_times_zero[i],
            &short_vanishing_poly_eval[i % z_period]
        );
    }

    /*
     * Convert (E*Z)(x) to monomial form.
     *
     * We know that (E*Z)(x) and (P*Z)(x) agree over the FFT domain,
     * and we know that (P*Z)(x) has degree at most FIELD_ELEMENTS_PER_EXT_BLOB - 1.
     * Thus, an inverse FFT of the evaluations of (E*Z)(x) (= evaluations of (P*Z)(x))
     * yields the coefficient form of (P*Z)(x).
     */
    ret = fr_ifft(
        extended_evaluation_times_zero_coeffs,
        extended_evaluation_times_zero,
        FIELD_ELEMENTS_PER_EXT_BLOB,
        s
    );
    if (ret != C_KZG_OK) goto out;

    /*
     * Next step is to divide the polynomial (P*Z)(x) by polynomial Z(x) to get P(x).
     * We do this in evaluation form over a coset of the FFT domain to avoid division by 0.
     *
     * P(x) has degree below `half`, so the round trip only needs `half` points, over the coset
     * {h * u^j} where u has order `half`. Every point of that coset satisfies x^half = h^half, so
     * (P*Z)(x) reduces exactly to `half` coefficients first. This is a fold, not a truncation.
     */
    fr_t shift_pow_half;
    fr_pow(&shift_pow_half, &RECOVERY_SHIFT_FACTOR, half);
    for (size_t i = 0; i < half; i++) {
        fr_t tmp;
        fr_mul(&tmp, &extended_evaluation_times_zero_coeffs[i + half], &shift_pow_half);
        fr_add(
            &extended_evaluation_times_zero_coeffs[i],
            &extended_evaluation_times_zero_coeffs[i],
            &tmp
        );
    }

    /* Convert (P*Z)(x) to evaluation form over the coset */
    ret = coset_fft(extended_evaluation_times_zero, extended_evaluation_times_zero_coeffs, half, s);
    if (ret != C_KZG_OK) goto out;

    /*
     * Convert Z(x) to evaluation form over the same coset.
     *
     * For x = h * u^j the argument of Zhat is x^FIELD_ELEMENTS_PER_CELL = c * m^j, where
     * c = h^FIELD_ELEMENTS_PER_CELL and m has order z_period_over_coset. So this is Zhat over a
     * coset of the order-z_period_over_coset subgroup, with shift c -- and, as above, every point
     * of it satisfies y^z_period_over_coset = c^z_period_over_coset, so Zhat folds down first.
     * Note c^z_period_over_coset = h^half, the constant already computed.
     */
    fr_t cell_shift;
    fr_pow(&cell_shift, &RECOVERY_SHIFT_FACTOR, FIELD_ELEMENTS_PER_CELL);
    for (size_t i = z_period_over_coset; i < short_vanishing_poly_len; i++) {
        fr_t tmp;
        fr_mul(&tmp, &short_vanishing_poly[i], &shift_pow_half);
        fr_add(
            &short_vanishing_poly[i - z_period_over_coset],
            &short_vanishing_poly[i - z_period_over_coset],
            &tmp
        );
        short_vanishing_poly[i] = FR_ZERO;
    }
    shift_poly(short_vanishing_poly, z_period_over_coset, &cell_shift);
    ret = fr_fft(vanishing_poly_over_coset, short_vanishing_poly, z_period_over_coset, s);
    if (ret != C_KZG_OK) goto out;

    /*
     * Compute P(x) = (P*Z)(x) / Z(x) in evaluation form over the coset.
     *
     * The divisors are inverted as a batch rather than one at a time: Montgomery's trick costs one
     * inversion and three multiplications per element, where fr_div costs a full inversion each.
     * Only z_period_over_coset of them are distinct. Z has no zeros on the coset -- which is the
     * reason the division is done there -- so the batch cannot fail, but it is still checked.
     */
    ret = fr_batch_inv(
        inv_vanishing_poly_over_coset, vanishing_poly_over_coset, z_period_over_coset
    );
    if (ret != C_KZG_OK) goto out;
    for (size_t i = 0; i < half; i++) {
        fr_mul(
            &extended_evaluation_times_zero[i],
            &extended_evaluation_times_zero[i],
            &inv_vanishing_poly_over_coset[i % z_period_over_coset]
        );
    }

    /* Convert P(x) to coefficient form */
    ret = coset_ifft(reconstructed_poly_coeff, extended_evaluation_times_zero, half, s);
    if (ret != C_KZG_OK) goto out;

    /* P(x) has degree below `half`; the rest of the domain is zero */
    for (size_t i = half; i < FIELD_ELEMENTS_PER_EXT_BLOB; i++) {
        reconstructed_poly_coeff[i] = FR_ZERO;
    }

    /*
     * After unscaling the reconstructed polynomial, we have P(x) which evaluates to our original
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
    c_kzg_free(short_vanishing_poly);
    c_kzg_free(short_vanishing_poly_eval);
    c_kzg_free(vanishing_poly_over_coset);
    c_kzg_free(inv_vanishing_poly_over_coset);
    c_kzg_free(extended_evaluation_times_zero);
    c_kzg_free(extended_evaluation_times_zero_coeffs);
    c_kzg_free(reconstructed_poly_coeff);
    return ret;
}
