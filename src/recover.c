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
 *  @file recover.c
 *
 * Recover polynomials from samples.
 */

#include "recover.h"
#include "c_kzg_util.h"
#include "fft_fr.h"
#include "utility.h"
#include "zero_poly.h"

/**
 * Shift a polynomial in place.
 *
 * Multiplies each coefficient by 1 / shift_factor ^ i.
 *
 * @param[out,in] p The polynomial coefficients to be shifted
 * @param[in] len_p Length of the polynomial coefficients
 */
void shift_poly(fr_t *p, uint64_t len_p) {
    fr_t shift_factor, factor_power, inv_factor;
    fr_from_uint64(&shift_factor, 5); // primitive root of unity
    fr_inv(&inv_factor, &shift_factor);
    factor_power = fr_one;

    for (uint64_t i = 1; i < len_p; i++) {
        fr_mul(&factor_power, &factor_power, &inv_factor);
        fr_mul(&p[i], &p[i], &factor_power);
    }
}

/**
 * Unshift a polynomial in place.
 *
 * Multiplies each coefficient by shift_factor ^ i.
 *
 * @param[out,in] p The polynomial coefficients to be unshifted
 * @param[in] len_p Length of the polynomial coefficients
 */
void unshift_poly(fr_t *p, uint64_t len_p) {
    fr_t shift_factor, factor_power;
    fr_from_uint64(&shift_factor, 5); // primitive root of unity
    factor_power = fr_one;

    for (uint64_t i = 1; i < len_p; i++) {
        fr_mul(&factor_power, &factor_power, &shift_factor);
        fr_mul(&p[i], &p[i], &factor_power);
    }
}

/**
 * Given a dataset with up to half the entries missing, return the reconstructed original.
 *
 * Assumes that the inverse FFT of the original data has the upper half of its values equal to zero.
 *
 * @param[out] reconstructed_data An attempted reconstruction of the original data
 * @param[in]  samples            The data to be reconstructed, with `fr_null` set for missing values
 * @param[in]  len_samples        The length of @p samples and @p reconstructed_data
 * @param[in]  fs                 The FFT settings previously initialised with #new_fft_settings
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_ERROR   An internal error occurred
 * @retval C_CZK_MALLOC  Memory allocation failed
 *
 * @todo Could probably reuse some memory here.
 */
C_KZG_RET recover_poly_from_samples(fr_t *reconstructed_data, fr_t *samples, uint64_t len_samples, FFTSettings *fs) {

    CHECK(is_power_of_two(len_samples));

    uint64_t *missing;
    TRY(new_uint64_array(&missing, len_samples));

    uint64_t len_missing = 0;
    for (uint64_t i = 0; i < len_samples; i++) {
        if (fr_is_null(&samples[i])) {
            missing[len_missing++] = i;
        }
    }

    fr_t *zero_eval, *zero_poly;
    uint64_t zero_poly_len;
    TRY(new_fr_array(&zero_eval, len_samples));
    TRY(new_fr_array(&zero_poly, len_samples));
    TRY(zero_polynomial_via_multiplication(zero_eval, zero_poly, &zero_poly_len, len_samples, missing, len_missing,
                                           fs));

    // Check all is well
    for (uint64_t i = 0; i < len_samples; i++) {
        TRY(fr_is_null(&samples[i]) == fr_is_zero(&zero_eval[i]) ? C_KZG_OK : C_KZG_ERROR);
    }

    // TODO: Could just modify zero_eval in place?
    fr_t *poly_evaluations_with_zero, *poly_with_zero;
    TRY(new_fr_array(&poly_evaluations_with_zero, len_samples));
    for (uint64_t i = 0; i < len_samples; i++) {
        if (fr_is_null(&samples[i])) {
            poly_evaluations_with_zero[i] = fr_zero;
        } else {
            fr_mul(&poly_evaluations_with_zero[i], &samples[i], &zero_eval[i]);
        }
    }
    TRY(new_fr_array(&poly_with_zero, len_samples));
    TRY(fft_fr(poly_with_zero, poly_evaluations_with_zero, true, len_samples, fs));

    shift_poly(poly_with_zero, len_samples);
    shift_poly(zero_poly, zero_poly_len); // The rest of zero_poly is 0s

    // renamings:
    fr_t *shifted_poly_with_zero = poly_with_zero;
    fr_t *shifted_zero_poly = zero_poly;

    fr_t *eval_shifted_poly_with_zero, *eval_shifted_zero_poly;
    TRY(new_fr_array(&eval_shifted_poly_with_zero, len_samples));
    TRY(new_fr_array(&eval_shifted_zero_poly, len_samples));
    TRY(fft_fr(eval_shifted_poly_with_zero, shifted_poly_with_zero, false, len_samples, fs));
    TRY(fft_fr(eval_shifted_zero_poly, shifted_zero_poly, false, len_samples, fs));

    fr_t *eval_shifted_reconstructed_poly = eval_shifted_poly_with_zero;
    for (uint64_t i = 0; i < len_samples; i++) {
        fr_div(&eval_shifted_reconstructed_poly[i], &eval_shifted_poly_with_zero[i], &eval_shifted_zero_poly[i]);
    }

    fr_t *shifted_reconstructed_poly;
    TRY(new_fr_array(&shifted_reconstructed_poly, len_samples));
    TRY(fft_fr(shifted_reconstructed_poly, eval_shifted_reconstructed_poly, true, len_samples, fs));

    unshift_poly(shifted_reconstructed_poly, len_samples);

    // renaming:
    fr_t *reconstructed_poly = shifted_reconstructed_poly;

    TRY(fft_fr(reconstructed_data, reconstructed_poly, false, len_samples, fs));

    // Check all is well
    for (uint64_t i = 0; i < len_samples; i++) {
        TRY(fr_is_null(&samples[i]) || fr_equal(&reconstructed_data[i], &samples[i]) ? C_KZG_OK : C_KZG_ERROR);
    }

    free(shifted_reconstructed_poly);
    free(eval_shifted_poly_with_zero);
    free(eval_shifted_zero_poly);
    free(poly_with_zero);
    free(poly_evaluations_with_zero);
    free(zero_eval);
    free(zero_poly);
    free(missing);

    return C_KZG_OK;
}