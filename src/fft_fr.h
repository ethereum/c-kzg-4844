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

#include "c-kzg.h"
#include "fft_util.h"

void fft_fr_slow(blst_fr *out, blst_fr *in, uint64_t offset, uint64_t stride, blst_fr *roots, uint64_t roots_stride, uint64_t l);
void fft_fr_fast(blst_fr *out, blst_fr *in, uint64_t offset, uint64_t stride, blst_fr *roots, uint64_t roots_stride, uint64_t l);
void fft_fr_helper(blst_fr *out, blst_fr *in, uint64_t offset, uint64_t stride, blst_fr *roots, uint64_t roots_stride, uint64_t l);
void fft_fr (blst_fr *out, blst_fr *in, FFTSettings *fs, bool inv, uint64_t n);
