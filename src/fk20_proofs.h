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

// TODO: Benchmark some of the other options at https://graphics.stanford.edu/~seander/bithacks.html#BitReverseTable
#define rev_byte(a) ((((a)&0xff) * 0x0202020202ULL & 0x010884422010ULL) % 1023)
#define rev_4byte(a) (rev_byte(a) << 24 | rev_byte((a) >> 8) << 16 | rev_byte((a) >> 16) << 8 | rev_byte((a) >> 24))

typedef struct {
    KZGSettings *ks;
    blst_p1 *x_ext_fft;
    uint64_t x_ext_fft_len;
} FK20SingleSettings;

typedef struct {
    KZGSettings *ks;
    uint64_t chunk_len;
    blst_p1 **x_ext_fft_files;
    uint64_t length;
} FK20MultiSettings;

int log2_pow2(uint32_t n);
uint32_t reverse_bits(uint32_t a);
uint32_t reverse_bits_limited(uint32_t length, uint32_t value);
C_KZG_RET reverse_bit_order(void *values, size_t size, uint64_t n);
C_KZG_RET toeplitz_part_1(blst_p1 *out, const blst_p1 *x, uint64_t n, KZGSettings *ks);
C_KZG_RET toeplitz_part_2(blst_p1 *out, const poly *toeplitz_coeffs, const FK20SingleSettings *fk);
C_KZG_RET toeplitz_part_3(blst_p1 *out, const blst_p1 *h_ext_fft, uint64_t n2, const FK20SingleSettings *fk);
C_KZG_RET fk20_single_da_opt(blst_p1 *out, const poly *p, FK20SingleSettings *fk);
C_KZG_RET da_using_fk20_single(blst_p1 *out, const poly *p, FK20SingleSettings *fk);
C_KZG_RET new_fk20_single_settings(FK20SingleSettings *fk, uint64_t n2, KZGSettings *ks);
void free_fk20_single_settings(FK20SingleSettings *fk);
