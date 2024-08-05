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

#include "types.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool fr_equal(const fr_t *a, const fr_t *b);
bool fr_is_one(const fr_t *p);
bool fr_is_null(const fr_t *p);
void fr_div(fr_t *out, const fr_t *a, const fr_t *b);
void fr_pow(fr_t *out, const fr_t *a, uint64_t n);

#ifdef __cplusplus
}
#endif