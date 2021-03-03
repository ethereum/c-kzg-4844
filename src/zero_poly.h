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
 *  @file zero_poly.h
 *
 *  Methods for constructing zero polynomials and reconstructing polynomials from partial evaluations on a subgroup
 */

#include "c_kzg.h"
#include "fft_common.h"
#include "poly.h"

C_KZG_RET do_zero_poly_mul_leaf(fr_t *dst, uint64_t len_dst, const uint64_t *indices, uint64_t len_indices,
                                uint64_t stride, const FFTSettings *fs);
C_KZG_RET reduce_leaves(poly *dst, uint64_t len_dst, fr_t *scratch, uint64_t len_scratch, const poly *leaves,
                        uint64_t leaf_count, const FFTSettings *fs);
C_KZG_RET zero_polynomial_via_multiplication(fr_t *zero_eval, fr_t *zero_poly, uint64_t *zero_poly_len, uint64_t length,
                                             const uint64_t *missing_indices, uint64_t len_missing,
                                             const FFTSettings *fs);
