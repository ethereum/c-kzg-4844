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

DLLEXPORT C_KZG_RET blob_to_kzg_commitment(KZGCommitment *out, const Blob *blob, const KZGSettings *s);

DLLEXPORT C_KZG_RET compute_kzg_proof(KZGProof *out, const Blob *blob, const Bytes32 *z_bytes, const KZGSettings *s);

DLLEXPORT C_KZG_RET compute_blob_kzg_proof(KZGProof *out, const Blob *blob, const KZGSettings *s);

DLLEXPORT C_KZG_RET verify_kzg_proof(bool *result, const Bytes48 *commitments_bytes, const Bytes32 *z_bytes, const Bytes32 *y_bytes, const Bytes48 *proof_bytes, const KZGSettings *s);

DLLEXPORT C_KZG_RET verify_blob_kzg_proof(bool *result, const Blob *blob, const Bytes48 *commitment_bytes, const Bytes48 *proof_bytes, const KZGSettings *s);

DLLEXPORT C_KZG_RET verify_blob_kzg_proof_batch(bool *result, const Blob *blobs, const Bytes48 *commitments_bytes, const Bytes48 *proofs_bytes, size_t count, const KZGSettings *s);
