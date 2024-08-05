/*
 * Copyright 2024 Benjamin Edgington
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

#pragma once

#include "common/fr.h"
#include "common/g1.h"
#include "common/ret.h"
#include "common/settings.h"

#ifdef __cplusplus
extern "C" {
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////
// Public Functions
////////////////////////////////////////////////////////////////////////////////////////////////////

C_KZG_RET fr_fft(fr_t *out, const fr_t *in, size_t n, const KZGSettings *s);
C_KZG_RET fr_ifft(fr_t *out, const fr_t *in, size_t n, const KZGSettings *s);

C_KZG_RET g1_fft(g1_t *out, const g1_t *in, size_t n, const KZGSettings *s);
C_KZG_RET g1_ifft(g1_t *out, const g1_t *in, size_t n, const KZGSettings *s);

#ifdef __cplusplus
}
#endif
