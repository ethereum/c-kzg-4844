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

#include "debug.h"

void print_bytes32(const Bytes32 *bytes) {
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", bytes->bytes[i]);
    }
    printf("\n");
}

void print_bytes48(const Bytes48 *bytes) {
    for (size_t i = 0; i < 48; i++) {
        printf("%02x", bytes->bytes[i]);
    }
    printf("\n");
}

void print_fr(const fr_t *f) {
    Bytes32 bytes;
    bytes_from_bls_field(&bytes, f);
    print_bytes32(&bytes);
}

void print_g1(const g1_t *g) {
    Bytes48 bytes;
    bytes_from_g1(&bytes, g);
    print_bytes48(&bytes);
}

void print_blob(const Blob *blob) {
    for (size_t i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++) {
        Bytes32 *field = (Bytes32 *)&blob->bytes[i * BYTES_PER_FIELD_ELEMENT];
        print_bytes32(field);
    }
}

void print_cell(const Cell *cell) {
    for (size_t i = 0; i < FIELD_ELEMENTS_PER_CELL; i++) {
        Bytes32 *field = (Bytes32 *)&cell->bytes[i * BYTES_PER_FIELD_ELEMENT];
        print_bytes32(field);
    }
}