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

#include "blst.h"

////////////////////////////////////////////////////////////////////////////////////////////////////
// Macros
////////////////////////////////////////////////////////////////////////////////////////////////////

/** Length of the domain string. */
#define DOMAIN_STR_LENGTH 16

/** The number of field elements in a cell. */
#define FIELD_ELEMENTS_PER_CELL 64

/** The number of cells in an extended blob. */
#define CELLS_PER_EXT_BLOB (FIELD_ELEMENTS_PER_EXT_BLOB / FIELD_ELEMENTS_PER_CELL)

/** The number of bytes in a single cell. */
#define BYTES_PER_CELL (FIELD_ELEMENTS_PER_CELL * BYTES_PER_FIELD_ELEMENT)

////////////////////////////////////////////////////////////////////////////////////////////////////
// Constants
////////////////////////////////////////////////////////////////////////////////////////////////////

/** The domain separator for verify_cell_kzg_proof_batch's random challenge. */
static const char *RANDOM_CHALLENGE_DOMAIN_VERIFY_CELL_KZG_PROOF_BATCH = "RCKZGCBATCH__V1_";

/**
 * The coset shift factor for the cell recovery code.
 *
 *   fr_t a;
 *   fr_from_uint64(&a, 7);
 *   for (size_t i = 0; i < 4; i++)
 *       printf("%#018llxL,\n", a.l[i]);
 */
static const fr_t RECOVERY_SHIFT_FACTOR = {
    0x0000000efffffff1L,
    0x17e363d300189c0fL,
    0xff9c57876f8457b0L,
    0x351332208fc5a8c4L,
};

/**
 * The inverse of RECOVERY_SHIFT_FACTOR.
 *
 *   fr_t a;
 *   fr_from_uint64(&a, 7);
 *   fr_div(&a, &FR_ONE, &a);
 *   for (size_t i = 0; i < 4; i++)
 *       printf("%#018llxL,\n", a.l[i]);
 */
static const fr_t INV_RECOVERY_SHIFT_FACTOR = {
    0xdb6db6dadb6db6dcL,
    0xe6b5824adb6cc6daL,
    0xf8b356e005810db9L,
    0x66d0f1e660ec4796L,
};