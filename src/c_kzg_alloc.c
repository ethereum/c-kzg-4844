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
 *  @file c_kzg_alloc.c
 *
 * Utilities for dynamically allocating arrays of things.
 */

#include "c_kzg_alloc.h"

/**
 * Wrapped `malloc()` that reports failures to allocate.
 *
 * @param[out] x Pointer to the allocated space
 * @param[in]  n The number of bytes to be allocated
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
static C_KZG_RET c_kzg_malloc(void **x, size_t n) {
    if (n > 0) {
        *x = malloc(n);
        return *x != NULL ? C_KZG_OK : C_KZG_MALLOC;
    }
    *x = NULL;
    return C_KZG_OK;
}

/**
 * Allocate memory for an array of uint64_t.
 *
 * @remark Free the space later using `free()`.
 *
 * @param[out] x Pointer to the allocated space
 * @param[in]  n The number of utin64_t to be allocated
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET new_uint64_array(uint64_t **x, size_t n) {
    return c_kzg_malloc((void **)x, n * sizeof **x);
}

/**
 * Allocate memory for an array of field elements.
 *
 * @remark Free the space later using `free()`.
 *
 * @param[out] x Pointer to the allocated space
 * @param[in]  n The number of field elements to be allocated
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET new_fr_array(fr_t **x, size_t n) {
    return c_kzg_malloc((void **)x, n * sizeof **x);
}

/**
 * Allocate memory for an array of arrays of field elements.
 *
 * @remark Free the space later using `free()`, after freeing each of the array's elements.
 *
 * @param[out] x Pointer to the allocated space
 * @param[in]  n The number of field element arrays to be allocated
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET new_fr_array_2(fr_t ***x, size_t n) {
    return c_kzg_malloc((void **)x, n * sizeof **x);
}

/**
 * Allocate memory for an array of G1 group elements.
 *
 * @remark Free the space later using `free()`.
 *
 * @param[out] x Pointer to the allocated space
 * @param[in]  n The number of G1 elements to be allocated
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET new_g1_array(g1_t **x, size_t n) {
    return c_kzg_malloc((void **)x, n * sizeof **x);
}

/**
 * Allocate memory for an array of arrays of G1 group elements.
 *
 * @remark Free the space later using `free()`, after freeing each of the array's elements.
 *
 * @param[out] x Pointer to the allocated space
 * @param[in]  n The number of G1 arrays to be allocated
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET new_g1_array_2(g1_t ***x, size_t n) {
    return c_kzg_malloc((void **)x, n * sizeof **x);
}

/**
 * Allocate memory for an array of G2 group elements.
 *
 * @remark Free the space later using `free()`.
 *
 * @param[out] x Pointer to the allocated space
 * @param[in]  n The number of G2 elements to be allocated
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET new_g2_array(g2_t **x, size_t n) {
    return c_kzg_malloc((void **)x, n * sizeof **x);
}

/**
 * Allocate memory for an array of polynomial headers.
 *
 * @remark Free the space later using `free()`, after freeing the individual polynomials via #free_poly.
 *
 * @param[out] x Pointer to the allocated space
 * @param[in]  n The number of polynomial headers to be allocated
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET new_poly_array(poly **x, size_t n) {
    return c_kzg_malloc((void **)x, n * sizeof **x);
}

#ifdef KZGTEST

#include "../inc/acutest.h"
#include "test_util.h"

void malloc_works(void) {
    int *p;
    TEST_CHECK(C_KZG_OK == c_kzg_malloc((void **)&p, 4));
    free(p);
}

void malloc_huge_fails(void) {
    int *p;
    TEST_CHECK(C_KZG_MALLOC == c_kzg_malloc((void **)&p, -1));
}

TEST_LIST = {
    {"C_KZG_UTIL_TEST", title},
    {"malloc_works", malloc_works},
    {"malloc_huge_fails", malloc_huge_fails},
    {NULL, NULL} /* zero record marks the end of the list */
};

#endif // KZGTEST