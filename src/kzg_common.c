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

#include <stdlib.h>
#include "kzg_common.h"

C_KZG_RET new_kzg_settings(KZGSettings *ks, FFTSettings *fs, blst_p1 *secret_g1, blst_p2 *secret_g2, uint64_t length) {
    ASSERT(length >= fs->max_width, C_KZG_BADARGS);
    ks->fs = fs;
    ks->secret_g1 = secret_g1;
    ks->extended_secret_g1 = NULL;
    ks->secret_g2 = secret_g2;
    ks->length = length;
    return C_KZG_OK;
}
