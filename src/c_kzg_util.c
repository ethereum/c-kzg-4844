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

#include <stdlib.h> // malloc
#include "c_kzg_util.h"

C_KZG_RET c_kzg_malloc(void **p, size_t n) {
    if (n > 0) {
        *p = malloc(n);
        return *p != NULL ? C_KZG_OK : C_KZG_MALLOC;
    }
    *p = NULL;
    return C_KZG_OK;
}
