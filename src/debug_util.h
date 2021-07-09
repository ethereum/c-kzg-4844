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

#include "bls12_381.h"

// Fr utilities
void print_fr(const fr_t *a);
void print_frs(const char *s, const fr_t *x, uint64_t n);

// G1 and G2 utilities
void print_g1_bytes(byte p1[96]);
void print_g1(const g1_t *p1);
void print_g1_limbs(const g1_t *p1);