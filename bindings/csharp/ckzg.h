#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "c_kzg_4844.h"

#ifdef _WIN32
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT
#endif

DLLEXPORT KZGSettings* load_trusted_setup_wrap(const char* file);

DLLEXPORT void free_trusted_setup_wrap(KZGSettings *s);

DLLEXPORT C_KZG_RET blob_to_kzg_commitment_wrap(KZGCommitment *out, const Blob blob, const KZGSettings *s);

DLLEXPORT int verify_aggregate_kzg_proof_wrap(const Blob blobs[], const KZGCommitment *commitments, size_t n, const KZGProof *proof, const KZGSettings *s);

DLLEXPORT C_KZG_RET compute_aggregate_kzg_proof_wrap(KZGProof *out, const Blob blobs[], size_t n, const KZGSettings *s);

DLLEXPORT int verify_kzg_proof_wrap(const KZGCommitment *c, const BLSFieldElement *z, const BLSFieldElement *y, const KZGProof *p, KZGSettings *s);
