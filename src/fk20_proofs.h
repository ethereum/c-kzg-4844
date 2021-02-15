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

/** @file fk20_proofs.h */

#include "c_kzg.h"
#include "kzg_proofs.h"

/**
 * Reverse the bits in a byte.
 *
 * From https://graphics.stanford.edu/~seander/bithacks.html#ReverseByteWith64BitsDiv
 *
 * @param a A byte
 * @return A byte that is bit-reversed with respect to @p a
 *
 * @todo Benchmark some of the other bit-reversal options in the list. Maybe.
 */
#define rev_byte(a) ((((a)&0xff) * 0x0202020202ULL & 0x010884422010ULL) % 1023)

/**
 * Reverse the bits in a 32 bit word.
 *
 * @param a A 32 bit unsigned integer
 * @return A 32 bit unsigned integer that is bit-reversed with respect to @p a
 */
#define rev_4byte(a) (rev_byte(a) << 24 | rev_byte((a) >> 8) << 16 | rev_byte((a) >> 16) << 8 | rev_byte((a) >> 24))

/**
 * Stores the setup and parameters needed for computing FK20 single proofs.
 *
 * Initialise with #new_fk20_single_settings. Free after use with #free_fk20_single_settings.
 */
typedef struct {
    const KZGSettings *ks;  /**< The corresponding settings for performing KZG proofs */
    blst_p1 *x_ext_fft;     /**< The output of the first part of the Toeplitz process */
    uint64_t x_ext_fft_len; /**< The length of the `x_ext_fft_len` array (TODO - do we need this?)*/
} FK20SingleSettings;

/**
 * Stores the setup and parameters needed for computing FK20 multi proofs.
 */
typedef struct {
    const KZGSettings *ks;     /**< The corresponding settings for performing KZG proofs */
    uint64_t chunk_len;        /**< TODO */
    blst_p1 **x_ext_fft_files; /**< TODO */
    uint64_t length;           /**< TODO */
} FK20MultiSettings;

int log2_pow2(uint32_t n);
uint32_t reverse_bits(uint32_t a);
uint32_t reverse_bits_limited(uint32_t n, uint32_t value);
C_KZG_RET reverse_bit_order(void *values, size_t size, uint64_t n);
C_KZG_RET toeplitz_part_1(blst_p1 *out, const blst_p1 *x, uint64_t n, const FFTSettings *fs);
C_KZG_RET toeplitz_part_2(blst_p1 *out, const poly *toeplitz_coeffs, const blst_p1 *x_ext_fft, const FFTSettings *fs);
C_KZG_RET toeplitz_part_3(blst_p1 *out, const blst_p1 *h_ext_fft, uint64_t n2, const FFTSettings *fs);
C_KZG_RET toeplitz_coeffs_stride(poly *out, const poly *in, uint64_t offset, uint64_t stride);
C_KZG_RET toeplitz_coeffs_step(poly *out, const poly *in);
C_KZG_RET fk20_single_da_opt(blst_p1 *out, const poly *p, const FK20SingleSettings *fk);
C_KZG_RET da_using_fk20_single(blst_p1 *out, const poly *p, const FK20SingleSettings *fk);
C_KZG_RET fk20_multi_da_opt(blst_p1 *out, const poly *p, const FK20MultiSettings *fk);
C_KZG_RET da_using_fk20_multi(blst_p1 *out, const poly *p, const FK20MultiSettings *fk);
C_KZG_RET new_fk20_single_settings(FK20SingleSettings *fk, uint64_t n2, const KZGSettings *ks);
C_KZG_RET new_fk20_multi_settings(FK20MultiSettings *fk, uint64_t n2, uint64_t chunk_len, const KZGSettings *ks);
void free_fk20_single_settings(FK20SingleSettings *fk);
void free_fk20_multi_settings(FK20MultiSettings *fk);
