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
 *  Methods for constructing polynomials that evaluate to zero for given lists of powers of roots of unity.
 */

#include "c_kzg.h"
#include "fft_common.h"
#include "poly.h"

C_KZG_RET do_zero_poly_mul_partial(poly *dst, const uint64_t *indices, uint64_t len_indices, uint64_t stride,
                                   const FFTSettings *fs);
C_KZG_RET reduce_partials(poly *dst, uint64_t len_dst, fr_t *scratch, uint64_t len_scratch, const poly *partials,
                          uint64_t partial_count, const FFTSettings *fs);
C_KZG_RET zero_polynomial_via_multiplication(fr_t *zero_eval, poly *zero_poly, uint64_t width,
                                             const uint64_t *missing_indices, uint64_t len_missing,
                                             const FFTSettings *fs);
