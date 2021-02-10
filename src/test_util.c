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

#include <stdlib.h> // malloc()
#include "test_util.h"
#include "blst_util.h"

void generate_trusted_setup(blst_p1 **s1, blst_p2 **s2, const blst_scalar *secret, const uint64_t n) {
    blst_fr s_pow, s;
    blst_fr_from_scalar(&s, secret);
    s_pow = fr_one;

    *s1 = malloc(n * sizeof(blst_p1));
    *s2 = malloc(n * sizeof(blst_p2));

    for (uint64_t i = 0; i < n; i++) {
        p1_mul((*s1) + i, blst_p1_generator(), &s_pow);
        p2_mul((*s2) + i, blst_p2_generator(), &s_pow);
        blst_fr_mul(&s_pow, &s_pow, &s);
    }
}

void free_trusted_setup(blst_p1 *s1, blst_p2 *s2) {
    free(s1);
    free(s2);
}

// Dummy function used to get the test-suite to print a title
void title(void) {}
