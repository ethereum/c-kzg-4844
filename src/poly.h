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

#include "c_kzg.h"

uint64_t poly_long_div_length(const uint64_t len_dividend, const uint64_t len_divisor);
C_KZG_RET poly_long_div(blst_fr *out, const uint64_t len_out, const blst_fr *dividend, const uint64_t len_dividend, const blst_fr *divisor, const uint64_t len_divisor);
