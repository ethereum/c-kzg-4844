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

#include <stdio.h>
#include "debug_util.h"

#ifdef BLST

//
// General Utilities
//

// Big-endian
void print_bytes_as_hex(byte *bytes, int start, int len) {
    for (int i = start; i < start + len; i++) {
        printf("%02x", bytes[i]);
    }
}

// Little-endian
void print_bytes_as_hex_le(byte *bytes, int start, int len) {
    for (int i = start + len - 1; i >= start; i--) {
        printf("%02x", bytes[i]);
    }
}

//
// Fr utilities
//

// Print a `blst_fr`
void print_fr(const fr_t *a) {
    scalar_t b;
    blst_scalar_from_fr(&b, a);
    print_bytes_as_hex_le(b.b, 0, 32);
}

// Print a vector of Frs
void print_frs(const char *s, const fr_t *x, uint64_t n) {
    printf("\n----\n");
    for (uint64_t i = 0; i < n; i++) {
        printf("%s %lu: ", s, i);
        print_fr(x + i);
        printf("\n");
    }
    printf("----\n");
}

//
// Fp Utilities
//

void print_limbs(const fp_t *fp) {
    printf("(%08lx, %08lx, %08lx, %08lx, %08lx, %08lx)", fp->l[0], fp->l[1], fp->l[2], fp->l[3], fp->l[4], fp->l[5]);
}

//
// G1 and G2 utilities
//

void print_p1_bytes(byte p1[96]) {
    printf("[0x");
    print_bytes_as_hex(p1, 0, 48);
    printf(",0x");
    print_bytes_as_hex(p1, 48, 48);
    printf("]\n");
}

/* "Pretty" print serialisation of a point in G1 */
void print_p1(const g1_t *p1) {
    byte p1_bytes[96];
    blst_p1_serialize(p1_bytes, p1);
    print_p1_bytes(p1_bytes);
}

/* "Pretty" print internals of a point in G1 */
void print_p1_limbs(const g1_t *p1) {
    printf("x = ");
    print_limbs(&p1->x);
    printf(", y = ");
    print_limbs(&p1->y);
    printf(", z = ");
    print_limbs(&p1->z);
    printf("\n");
}

#endif // BLST