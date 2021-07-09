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

/**
 * @file control.h
 *
 * Macros for control flow and error handling.
 */

#ifdef DEBUG
#include <stdlib.h>
#include <stdio.h>
#define CHECK(cond)                                                                                                    \
    if (!(cond)) {                                                                                                     \
        printf("\n%s:%d: Failed CHECK: %s\n", __FILE__, __LINE__, #cond);                                              \
        abort();                                                                                                       \
    }
#define TRY(result)                                                                                                    \
    {                                                                                                                  \
        C_KZG_RET ret = (result);                                                                                      \
        if (ret != C_KZG_OK) {                                                                                         \
            printf("\n%s:%d: Failed TRY: %s, result = %d\n", __FILE__, __LINE__, #result, ret);                        \
            abort();                                                                                                   \
        }                                                                                                              \
    }
#define ASSERT(cond)                                                                                                   \
    if (!(cond)) {                                                                                                     \
        printf("\n%s:%d: Failed ASSERT: %s\n", __FILE__, __LINE__, #cond);                                             \
        abort();                                                                                                       \
    }
#else
#define CHECK(cond)                                                                                                    \
    if (!(cond)) return C_KZG_BADARGS
#define TRY(result)                                                                                                    \
    {                                                                                                                  \
        C_KZG_RET ret = (result);                                                                                      \
        if (ret == C_KZG_MALLOC) return ret;                                                                           \
        if (ret != C_KZG_OK) return C_KZG_ERROR;                                                                       \
    }
#define ASSERT(cond)                                                                                                   \
    if (!(cond)) return C_KZG_ERROR
#endif // DEBUG

/** @def CHECK
 *
 * Test input parameters.
 *
 * Differs from `ASSERT` in returning `C_KZG_BADARGS`.
 *
 * This macro comes in two versions according to whether `DEBUG` is defined or not (`-DDEBUG` compiler flag).
 *   - `DEBUG` is undefined: when @p cond is false, return from the current function with the value `C_KZG_BADARGS`,
 * otherwise continue.
 *   - `DEBUG` is defined: when @p cond is false, print file and line number information and abort the run. This is very
 * useful for dubugging. The @p ret parameter is ignored in this case.
 *
 * @param cond The condition to be tested
 */

/** @def TRY
 *
 * Handle errors in called functions.
 *
 * This macro comes in two versions according to whether `DEBUG` is defined or not (`-DDEBUG` compiler flag).
 *   - `DEBUG` is undefined: if the @p result is not `C_KZG_OK`, return immediately with either `C_KZG_MALLOC` or
 * `C_KZG_ERROR`. Otherwise continue.
 *   - `DEBUG` is defined: if @p result is not `C_KZG_OK`, print file and line number information and abort the run.
 * This is very useful for dubugging.
 *
 * @param result The function call result to be tested
 */

/** @def ASSERT
 *
 * Test the correctness of statements.
 *
 * Differs from `CHECK` in returning `C_KZG_ERROR`.
 *
 * This macro comes in two versions according to whether `DEBUG` is defined or not (`-DDEBUG` compiler flag).
 *   - `DEBUG` is undefined: when @p cond is false, return from the current function with the value `C_KZG_ERROR`,
 * otherwise continue.
 *   - `DEBUG` is defined: when @p cond is false, print file and line number information and abort the run. This is very
 * useful for dubugging. The @p ret parameter is ignored in this case.
 *
 * @param cond The condition to be tested
 */
