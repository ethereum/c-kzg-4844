#ifndef CKZG_H
#define CKZG_H

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "c_kzg_4844.h"

#ifdef _WIN32
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT
#endif

typedef blst_p1 g1_t;         /**< Internal G1 group element type */
typedef blst_p2 g2_t;         /**< Internal G2 group element type */
typedef blst_fr fr_t;         /**< Internal Fr field element type */


DLLEXPORT KZGSettings* load_trusted_setup_wrap(const char* file);

DLLEXPORT void free_trusted_setup_wrap(KZGSettings *s);

DLLEXPORT C_KZG_RET blob_to_kzg_commitment_wrap(uint8_t out[48], const Blob blob, const KZGSettings *s);

DLLEXPORT int verify_aggregate_kzg_proof_wrap(const Blob blobs[], const KZGCommitment commitments[], size_t n, const uint8_t proof[48], const KZGSettings *s);

DLLEXPORT C_KZG_RET compute_aggregate_kzg_proof_wrap(uint8_t out[48], const Blob blobs[], size_t n, const KZGSettings *s);

DLLEXPORT int verify_kzg_proof_wrap(const uint8_t c[48], const uint8_t z[32], const uint8_t y[32], const uint8_t p[48], KZGSettings *s);

#endif