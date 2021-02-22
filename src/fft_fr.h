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

/** @file fft_fr.h */

#include "fft_common.h"

void fft_fr_slow(fr_t *out, const fr_t *in, uint64_t stride, const fr_t *roots, uint64_t roots_stride, uint64_t n);
void fft_fr_fast(fr_t *out, const fr_t *in, uint64_t stride, const fr_t *roots, uint64_t roots_stride, uint64_t n);
C_KZG_RET fft_fr(fr_t *out, const fr_t *in, bool inverse, uint64_t n, const FFTSettings *fs);
C_KZG_RET fft_fr_in_place(fr_t *data, bool inverse, uint64_t n, const FFTSettings *fs);
C_KZG_RET fft_fr_in_place_lomem(fr_t *data, bool inverse, uint64_t n, const FFTSettings *fs);
