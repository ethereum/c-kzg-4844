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

#include <stdlib.h> // rand()
#include "bench_util.h"
#include "blst_util.h"

unsigned long tdiff(timespec_t start, timespec_t end) {
    return (end.tv_sec - start.tv_sec) * NANO + (end.tv_nsec - start.tv_nsec);
}

uint64_t rand_uint64() {
    uint64_t a = (uint64_t)rand();
    uint64_t b = (uint64_t)rand();
    return a << 32 | b;
}

blst_fr rand_fr() {
    blst_fr ret;
    uint64_t a[4];
    a[0] = rand_uint64();
    a[1] = rand_uint64();
    a[2] = rand_uint64();
    a[3] = rand_uint64();
    blst_fr_from_uint64(&ret, a);
    return ret;
}

blst_p1 rand_g1() {
    blst_p1 ret;
    blst_fr random = rand_fr();
    p1_mul(&ret, blst_p1_generator(), &random);
    return ret;
}
