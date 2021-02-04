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

#include "c_kzg.h"
#include "fft_common.h"

typedef struct {
    FFTSettings *fs;
    blst_p1 *secret_g1;
    blst_p1 *extended_secret_g1;
    blst_p2 *secret_g2;
    uint64_t length;
} KZGSettings;

C_KZG_RET new_kzg_settings(KZGSettings *ks, FFTSettings *fs, blst_p1 *secret_g1, blst_p2 *secret_g2, uint64_t length);
