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

/** @file c_kzg.h */

#ifndef C_KZG_H
#define C_KZG_H

#include <stdbool.h>
#include "../inc/blst.h"

/**
 * The common return type for all routines in which something can go wrong.
 *
 * @warning In the case of @p C_KZG_OK or @p C_KZG_BADARGS, the caller can assume that all memory allocated by the
 * called routines has been deallocated. However, in the case of @p C_KZG_ERROR or @p C_KZG_MALLOC being returned, these
 * are unrecoverable and memory may have been leaked.
 *
 * @todo Check that memory is not leaked anywhere in the case of C_KZG_BADARGS.
 */
typedef enum {
    C_KZG_OK = 0,  /**< Success! */
    C_KZG_BADARGS, /**< The supplied data is invalid in some way */
    C_KZG_ERROR,   /**< Internal error - this should never occur and may indicate a bug in the library */
    C_KZG_MALLOC,  /**< Could not allocate memory */
} C_KZG_RET;

#ifdef DEBUG
#include <stdlib.h>
#include <stdio.h>
#define ASSERT(cond, ret)                                                                                              \
    if (!(cond)) {                                                                                                     \
        printf("\n%s:%d: Failed ASSERT: %s\n", __FILE__, __LINE__, #cond);                                             \
        abort();                                                                                                       \
    }
#else
#define ASSERT(cond, ret)                                                                                              \
    if (!(cond)) return (ret)
#endif // DEBUG

/** @def ASSERT
 *
 * Handle errors.
 *
 * This macro comes in two versions according to whether `DEBUG` is defined or not (`-DDEBUG` compiler flag).
 *   - `DEBUG` is undefined: when @p cond is false, return from the function with the value @p ret, otherwise continue.
 *   - `DEBUG` is defined: when @p cond is false, print file and line number information and abort the run. This is very
 * useful for dubugging. The @p ret parameter is ignored in this case.
 *
 * @param cond The condition to be tested
 * @param ret  The return code to be returned in case the condition is false
 */

#endif // C_KZG_H
