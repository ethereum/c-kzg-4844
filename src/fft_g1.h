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

/** @file fft_g1.h */

#include "fft_common.h"

void fft_g1_slow(g1_t *out, const g1_t *in, uint64_t stride, const fr_t *roots, uint64_t roots_stride, uint64_t n);
void fft_g1_fast(g1_t *out, const g1_t *in, uint64_t stride, const fr_t *roots, uint64_t roots_stride, uint64_t n);
C_KZG_RET fft_g1(g1_t *out, const g1_t *in, bool inverse, uint64_t n, const FFTSettings *fs);
