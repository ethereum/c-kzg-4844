#include "common.h"

#include <stdlib.h>

/**
 * Wrapped malloc() that reports failures to allocate.
 *
 * @remark Will return C_KZG_BADARGS if the requested size is zero.
 *
 * @param[out] out  Pointer to the allocated space
 * @param[in]  size The number of bytes to be allocated
 */
C_KZG_RET c_kzg_malloc(void **out, size_t size) {
    *out = NULL;
    if (size == 0) return C_KZG_BADARGS;
    *out = malloc(size);
    return *out != NULL ? C_KZG_OK : C_KZG_MALLOC;
}
