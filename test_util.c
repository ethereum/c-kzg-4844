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

#include "test_util.h"

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
void print_fr(const blst_fr *a) {
    blst_scalar b;
    blst_scalar_from_fr(&b, a);
    print_bytes_as_hex_le(b.b, 0, 32);
}

bool fr_equal(blst_fr *aa, blst_fr *bb) {
    uint64_t a[4], b[4];
    blst_uint64_from_fr(a, aa);
    blst_uint64_from_fr(b, bb);
    return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3];
}

//
// G1 and G2 utilities
//

/* "Pretty" print an affine point in G1 */
void print_p1_affine(const blst_p1_affine *p1) {
    byte *p1_hex = (byte *)malloc(96);
    blst_p1_affine_serialize(p1_hex, p1);
    printf("[0x");
    print_bytes_as_hex(p1_hex, 0, 48);
    printf(",0x");
    print_bytes_as_hex(p1_hex, 48, 48);
    printf("]\n");
    free(p1_hex);
}

/* "Pretty" print an affine point in G2 */
void print_p2_affine(const blst_p2_affine *p2) {
    byte *p2_hex = (byte *)malloc(192);
    blst_p2_affine_serialize(p2_hex, p2);
    printf("[(0x");
    print_bytes_as_hex(p2_hex, 0, 48);
    printf(",0x");
    print_bytes_as_hex(p2_hex, 48, 48);
    printf("),(0x");
    print_bytes_as_hex(p2_hex, 96, 48);
    printf(",0x");
    print_bytes_as_hex(p2_hex, 144, 48);
    printf(")]\n");
    free(p2_hex);
}
