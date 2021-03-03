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
 *  @file zero_poly.c
 *
 *  Methods for constructing polynomials that evaluate to zero for given lists of powers of roots of unity.
 */

#include "zero_poly.h"
#include "c_kzg_util.h"
#include "fft_fr.h"
#include "utility.h"

/**
 * Calculates the minimal polynomial that evaluates to zero for powers of roots of unity at the given indices.
 *
 * Uses straightforward multiplication to calculate the product of `(x - r^i)` where `r` is a root of unity and the `i`s
 * are the indices at which it must evaluate to zero. This results in a polynomial of degree @p len_indices.
 *
 * @param[out] dst         The resulting leaf, length @p len_dst
 * @param[in]  len_dst     Length of the output leaf, @p dst
 * @param[in]  indices     Array of missing indices of length @p len_indices
 * @param[in]  len_indices Length of the missing indices array, @p indices
 * @param[in]  stride      Stride length through the powers of the root of unity
 * @param[in]  fs          The FFT settings previously initialised with #new_fft_settings
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 */
C_KZG_RET do_zero_poly_mul_leaf(fr_t *dst, uint64_t len_dst, const uint64_t *indices, uint64_t len_indices,
                                uint64_t stride, const FFTSettings *fs) {

    CHECK(len_dst >= len_indices + 1);

    for (uint64_t i = 0; i < len_indices; i++) {
        fr_t neg_di;
        fr_negate(&neg_di, &fs->expanded_roots_of_unity[indices[i] * stride]);
        dst[i] = neg_di;
        if (i > 0) {
            fr_add(&dst[i], &dst[i], &dst[i - 1]);
            for (uint64_t j = i - 1; j > 0; j--) {
                fr_mul(&dst[j], &dst[j], &neg_di);
                fr_add(&dst[j], &dst[j], &dst[j - 1]);
            }
            fr_mul(&dst[0], &dst[0], &neg_di);
        }
    }

    dst[len_indices] = fr_one;

    for (uint64_t i = len_indices + 1; i < len_dst; i++) {
        dst[i] = fr_zero;
    }

    return C_KZG_OK;
}

/**
 * Copy @p p to @p out, padding to length @p p_len with zeros.
 *
 * @param[out] out     A copy of @p p padded to length @p n with zeros
 * @param[in]  out_len The length of the desired output data, @p out
 * @param[in]  p       The data to be copied and padded, length @p p_len
 * @param[in]  p_len   The length of the data to be copied and padded
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 */
C_KZG_RET pad_p(fr_t *out, uint64_t out_len, const fr_t *p, uint64_t p_len) {
    CHECK(out_len >= p_len);
    for (uint64_t i = 0; i < p_len; i++) {
        out[i] = p[i];
    }
    for (uint64_t i = p_len; i < out_len; i++) {
        out[i] = fr_zero;
    }
    return C_KZG_OK;
}

/**
 * Calculate the product of the input polynomials via convolution.
 *
 * Pad the polynomials in @p ps, perform FFTs, point-wise multiply the results together, and apply an inverse FFT to the
 * result.
 *
 * @param[out] dst         The result of the convolution
 * @param[in]  len_dst     Length of the output, a power of two
 * @param      scratch     Scratch space of size at least 3 times the output size
 * @param[in]  len_scratch Length of @p scratch, at least 3 x @p len_dst
 * @param[in]  ps          Array of polynomial coefficients ps[@p len_ps][@p len_p]
 * @param[in]  len_ps      The number of polynomials
 * @param[in]  len_p       Array of lengths of each polynomial, size @p len_ps
 * @param[in]  fs          The FFT settings previously initialised with #new_fft_settings
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_ERROR   An internal error occurred
 *
 * @todo Check if we can make `ps` a proper 2d array rather than an array of pointers to arrays.
 */
C_KZG_RET reduce_leaves(fr_t *dst, uint64_t len_dst, fr_t *scratch, uint64_t len_scratch, blst_fr **ps, uint64_t len_ps,
                        const uint64_t *len_p, const FFTSettings *fs) {
    CHECK(is_power_of_two(len_dst));
    CHECK(len_scratch >= 3 * len_dst);
    CHECK(len_ps > 0);
    // The degree of the output is the sum of the degrees of the input polynomials.
    // TODO A more relaxed check should be ok: `len_ps * (len_p[0] - 1) < len_dst` (or even sum up the lengths)
    // CHECK(len_ps * len_p[0] <= len_dst);
    uint64_t total_length = 0;
    for (int i = 0; i < len_ps; i++) {
        total_length += len_p[i] - 1;
    }
    if (total_length + 1 > len_dst) {
        printf("Total length: %lu, len dest: %lu\n", total_length, len_dst);
        printf("\n");
        for (int i = 0; i < len_ps; i++) {
            printf("Len %d = %lu\n", i, len_p[i]);
        }
    }
    CHECK(total_length + 1 <= len_dst);

    // Split `scratch` up into three equally sized working arrays
    fr_t *p_padded = scratch;
    fr_t *mul_eval_ps = scratch + len_dst;
    fr_t *p_eval = scratch + 2 * len_dst;

    // Do the last leaf first: it may be shorter than the others and the padding can remain in place for the rest.
    TRY(pad_p(p_padded, len_dst, ps[len_ps - 1], len_p[len_ps - 1]));
    TRY(fft_fr(mul_eval_ps, p_padded, false, len_dst, fs));

    for (uint64_t i = 0; i < len_ps - 1; i++) {
        TRY(pad_p(p_padded, len_p[i], ps[i], len_p[i]));
        TRY(fft_fr(p_eval, p_padded, false, len_dst, fs));
        for (uint64_t j = 0; j < len_dst; j++) {
            fr_mul(&mul_eval_ps[j], &mul_eval_ps[j], &p_eval[j]);
        }
    }

    TRY(fft_fr(dst, mul_eval_ps, true, len_dst, fs));

    return C_KZG_OK;
}

/**
 * Calculate the minimal polynomial that evaluates to zero for powers of roots of unity that correspond to missing
 * indices.
 *
 * This is done by simply multiplying together `(x - r^i)` for all the `i` that are missing indices, using a combination
 * of direct multiplication (#do_zero_poly_mul_leaf) and multiplication via convolution (#reduce_leaves).
 *
 * Also calculates the FFT (the "evaluation polynomial").
 *
 * @remark Fails for very high numbers of missing indices. For example, with `fs.max_width = 256` and `length = 256`,
 * this will fail for len_missing = 253 or more. In this case, `length` (and maybe `fs.max_width`) needs to be doubled.
 * But this failure is probably OK for our use case.
 *
 * @remark Note that @p zero_poly is used as workspace during calculation.
 *
 * @param[out] zero_eval Array length @p length (TODO: description)
 * @param[out] zero_poly Array length @p length (TODO: description)
 * @param[out] zero_poly_len The length of the resulting @p zero_poly
 * @param[in]  length Length of the output arrays
 * @param[in]  missing_indices Array length @p len_missing (TODO: description)
 * @param[in]  len_missing Length of @p missing_indices
 * @param[in]  fs     The FFT settings previously initialised with #new_fft_settings
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_ERROR   An internal error occurred
 * @retval C_CZK_MALLOC  Memory allocation failed
 *
 * @todo What is the performance impact of tuning `per_leaf_poly` and `reduction factor`?
 */
C_KZG_RET zero_polynomial_via_multiplication(fr_t *zero_eval, fr_t *zero_poly, uint64_t *zero_poly_len, uint64_t length,
                                             const uint64_t *missing_indices, uint64_t len_missing,
                                             const FFTSettings *fs) {
    if (len_missing == 0) {
        *zero_poly_len = 0;
        for (uint64_t i = 0; i < length; i++) {
            zero_eval[i] = fr_zero;
            zero_poly[i] = fr_zero;
        }
        return C_KZG_OK;
    }
    CHECK(len_missing < length); // The output would be larger than length otherwise
    CHECK(length <= fs->max_width);
    CHECK(is_power_of_two(length));

    uint64_t per_leaf_poly = 64; // Tunable parameter. Must be a power of two.
    uint64_t per_leaf = per_leaf_poly - 1;
    uint64_t domain_stride = fs->max_width / length;
    uint64_t leaf_count = (len_missing + per_leaf - 1) / per_leaf;
    uint64_t n = next_power_of_two(leaf_count * per_leaf_poly);
    if (n > length) n = length;

    if (len_missing <= per_leaf) {
        TRY(do_zero_poly_mul_leaf(zero_poly, length, missing_indices, len_missing, domain_stride, fs));
        TRY(fft_fr(zero_eval, zero_poly, false, length, fs));
        *zero_poly_len = len_missing + 1;
    } else {
        // Work space for reducing the leaves - `zero_poly` is large enough due to the above check, so use that.
        // fr_t *work = zero_poly;
        fr_t *work;
        TRY(new_fr_array(&work, next_power_of_two(leaf_count * per_leaf_poly)));

        // Build the leaves.

        // Just allocate pointers here since we're re-using `work` for the leaf processing
        // Combining leaves can be done mostly in-place, using a scratchpad.
        fr_t **leaves, *scratch, *reduced;
        uint64_t *leaf_lengths;
        TRY(new_fr_array_2(&leaves, leaf_count));
        TRY(new_uint64_array(&leaf_lengths, leaf_count));
        uint64_t offset = 0, out_offset = 0, max = len_missing;
        for (int i = 0; i < leaf_count; i++) {
            uint64_t end = offset + per_leaf;
            if (end > max) end = max;
            leaves[i] = &work[out_offset];
            leaf_lengths[i] = per_leaf_poly;
            TRY(do_zero_poly_mul_leaf(leaves[i], per_leaf_poly, &missing_indices[offset], end - offset, domain_stride,
                                      fs));
            offset += per_leaf;
            out_offset += per_leaf_poly;
        }
        // Adjust the length of the last leaf
        // leaf_lengths[leaf_count - 1] = 1 + len_missing % per_leaf;
        leaf_lengths[leaf_count - 1] = 1 + len_missing - (leaf_count - 1) * per_leaf;

        // Now reduce all the leaves to a single poly

        int reduction_factor = 4; // must be a power of 2 (why?)
        TRY(new_fr_array(&scratch, n * 3));
        while (leaf_count > 1) {
            uint64_t reduced_count = (leaf_count + reduction_factor - 1) / reduction_factor;
            // All the leaves are the same length, except possibly the last leaf, but that's ok.
            uint64_t leaf_size = next_power_of_two(leaf_lengths[0]);
            for (uint64_t i = 0; i < reduced_count; i++) {
                uint64_t start = i * reduction_factor;
                uint64_t end = start + reduction_factor;
                // E.g. if we *started* with 2 leaves, we won't have more than that since it is already a power
                // of 2. If we had 3, it would have been rounded up anyway. So just pick the end
                uint64_t out_end = end * leaf_size;
                if (out_end > n) {
                    out_end = n;
                }
                reduced = work + start * leaf_size;
                uint64_t reduced_len = out_end - start * leaf_size;
                if (reduced_len > length) reduced_len = length;
                if (end > leaf_count) {
                    end = leaf_count;
                }
                uint64_t leaves_slice_len = end - start;
                if (leaves_slice_len > 1) {
                    TRY(reduce_leaves(reduced, reduced_len, scratch, n * 3, &leaves[start], leaves_slice_len,
                                      &leaf_lengths[start], fs));
                    // leaf_lengths[i] = reduced_len;
                    // } else {
                    //     leaf_lengths[i] = leaf_lengths[start];
                }
                leaves[i] = reduced;
                uint64_t total_length = 0;
                for (int j = start; j < end; j++) {
                    total_length += leaf_lengths[j] - 1;
                }
                leaf_lengths[i] = total_length + 1;
            }
            leaf_count = reduced_count;
        }

        *zero_poly_len = leaf_lengths[0];
        for (uint64_t i = 0; i < length; i++) {
            zero_poly[i] = i < *zero_poly_len ? leaves[0][i] : fr_zero;
        }
        TRY(fft_fr(zero_eval, zero_poly, false, length, fs));

        free(work);
        free(leaves);
        free(leaf_lengths);
        free(scratch);
    }

    return C_KZG_OK;
}
