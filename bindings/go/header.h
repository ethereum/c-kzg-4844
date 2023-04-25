#include <stdint.h>
#include "server.c"

/*
 * The necessary types from blst.h:
 */
typedef uint8_t byte;
typedef long long unsigned int limb_t;
typedef struct { byte b[256/8]; } blst_scalar;
typedef struct { limb_t l[256/8/sizeof(limb_t)]; } blst_fr;
typedef struct { limb_t l[384/8/sizeof(limb_t)]; } blst_fp;
typedef struct { blst_fp fp[2]; } blst_fp2;
typedef struct { blst_fp2 fp2[3]; } blst_fp6;
typedef struct { blst_fp6 fp6[2]; } blst_fp12;
typedef struct { blst_fp x, y, z; } blst_p1;
typedef struct { blst_fp x, y; } blst_p1_affine;
typedef struct { blst_fp2 x, y, z; } blst_p2;
typedef struct { blst_fp2 x, y; } blst_p2_affine;

/*
 * Default to the mainnet preset.
 */
#ifndef FIELD_ELEMENTS_PER_BLOB
#define FIELD_ELEMENTS_PER_BLOB 4096
#endif

#include "c_kzg_4844.c"
