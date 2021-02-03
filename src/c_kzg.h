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

#ifndef C_KZG_H
#define C_KZG_H

typedef enum {
    C_KZG_SUCCESS = 0,
    C_KZG_BADARGS,
    C_KZG_ERROR,
} C_KZG_RET;

#include <stdbool.h>
#include "../inc/blst.h"

#ifdef DEBUG
#include <assert.h>
#include <stdio.h>
#define ASSERT(cond, ret) if (!(cond)) \
        { \
            printf("\n%s:%d: Failed ASSERT: %s\n", __FILE__, __LINE__, #cond); \
            abort(); \
        }
#else
#define ASSERT(cond, ret) if (!(cond)) return (ret)
#endif

#endif
