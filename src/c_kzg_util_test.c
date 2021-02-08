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

#include "../inc/acutest.h"
#include "debug_util.h"
#include "c_kzg_util.h"

void title(void) {}

void malloc_works(void) {
    int *p;
    TEST_CHECK(C_KZG_OK == c_kzg_malloc((void **)&p, 4));
}

void malloc_huge_fails(void) {
    int *p;
    TEST_CHECK(C_KZG_MALLOC == c_kzg_malloc((void **)&p, -1));
}

TEST_LIST = {
    {"C_KZG_UTIL_TEST", title},
    {"malloc_works", malloc_works},
    {"malloc_huge_fails", malloc_huge_fails},
    {NULL, NULL} /* zero record marks the end of the list */
};
