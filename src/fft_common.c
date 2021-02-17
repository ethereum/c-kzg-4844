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
 * @file fft_common.c
 *
 * Code shared between the FFTs over field elements and FFTs over G1 group elements.
 */

#include "fft_common.h"
#include "c_kzg_util.h"

/**
 * Utility function to test whether the argument is a power of two.
 *
 * @remark This method returns `true` for `is_power_of_two(0)` which is a bit weird, but not an issue in the contexts in
 * which we use it.
 *
 * @param[in] n The number to test
 * @retval true  if @p n is a power of two or zero
 * @retval false otherwise
 */
bool is_power_of_two(uint64_t n) {
    return (n & (n - 1)) == 0;
}

/**
 * Generate powers of a root of unity in the field for use in the FFTs.
 *
 * @remark @p root must be such that @p root ^ @p width is equal to one, but no smaller power of @p root is equal to
 * one.
 *
 * @param[out] out   The generated powers of the root of unity (array size @p width + 1)
 * @param[in]  root  A root of unity
 * @param[in]  width One less than the size of @p out
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 */
C_KZG_RET expand_root_of_unity(fr_t *out, const fr_t *root, uint64_t width) {
    out[0] = fr_one;
    out[1] = *root;

    for (uint64_t i = 2; !fr_is_one(&out[i - 1]); i++) {
        CHECK(i <= width);
        fr_mul(&out[i], &out[i - 1], root);
    }
    CHECK(fr_is_one(&out[width]));

    return C_KZG_OK;
}

/**
 * Initialise an FFTSettings structure.
 *
 * Space is allocated for, and arrays are populated with, powers of the roots of unity. The two arrays contain the same
 * values in reverse order for convenience in inverse FFTs.
 *
 * `max_width` is the maximum size of FFT that can be calculated with these settings, and is a power of two by
 * construction. The same settings may be used to calculated FFTs of smaller power sizes.
 *
 * @remark As with all functions prefixed `new_`, this allocates memory that needs to be reclaimed by calling the
 * corresponding `free_` function. In this case, #free_fft_settings.
 * @remark These settings may be used for FFTs on both field elements and G1 group elements.
 *
 * @param[out] fs        The new settings
 * @param[in]  max_scale Log base 2 of the max FFT size to be used with these settings
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_ERROR   An internal error occurred
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET new_fft_settings(FFTSettings *fs, unsigned int max_scale) {
    fs->max_width = (uint64_t)1 << max_scale;

    CHECK((max_scale < sizeof scale2_root_of_unity / sizeof scale2_root_of_unity[0]));
    fr_from_uint64s(&fs->root_of_unity, scale2_root_of_unity[max_scale]);

    // Allocate space for the roots of unity
    TRY(new_fr(&fs->expanded_roots_of_unity, fs->max_width + 1));
    TRY(new_fr(&fs->reverse_roots_of_unity, fs->max_width + 1));

    // Populate the roots of unity
    TRY(expand_root_of_unity(fs->expanded_roots_of_unity, &fs->root_of_unity, fs->max_width));

    // Populate reverse roots of unity
    for (uint64_t i = 0; i <= fs->max_width; i++) {
        fs->reverse_roots_of_unity[i] = fs->expanded_roots_of_unity[fs->max_width - i];
    }

    return C_KZG_OK;
}

/**
 * Free the memory that was previously allocated by #new_fft_settings.
 *
 * @param fs The settings to be freed
 */
void free_fft_settings(FFTSettings *fs) {
    free(fs->expanded_roots_of_unity);
    free(fs->reverse_roots_of_unity);
    fs->max_width = 0;
}
