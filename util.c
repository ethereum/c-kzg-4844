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
#include <stdio.h>

#include "inc/blst.h"

void print_bytes_as_hex(byte *bytes, int start, int len) {
    for (int i = start; i < start + len; i++) {
        printf("%02x", bytes[i]);
    }
}

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


int main() {
    print_p1_affine(blst_p1_affine_generator());
    print_p2_affine(blst_p2_affine_generator());
    return 0;
}
