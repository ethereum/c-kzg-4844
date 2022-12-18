#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "c_kzg_4844.h"
#include "ckzg.h"


KZGSettings* load_trusted_setup_wrap(const char* file)
{
  KZGSettings* out = malloc(sizeof(KZGSettings));
  if (out == NULL) return NULL;

  FILE* f = fopen(file, "r");
  if (f == NULL) { free(out); return NULL; }

  if (load_trusted_setup_file(out, f) != C_KZG_OK) { free(out); fclose(f); return NULL; }
  fclose(f);
  return out;
}

void free_trusted_setup_wrap(KZGSettings *s) {
  free_trusted_setup(s);
  free(s);
}

C_KZG_RET blob_to_kzg_commitment_wrap(KZGCommitment out, const Blob blob, const KZGSettings *s) {

  C_KZG_RET ret = blob_to_kzg_commitment(out, blob, s);
  return ret;
}

int verify_aggregate_kzg_proof_wrap(const Blob blobs[], const KZGCommitment commitments[], size_t n, const uint8_t proof[48], const KZGSettings *s)
{
  C_KZG_RET ret;
  bool      b;
  
  ret = verify_aggregate_kzg_proof(&b, blobs, commitments, n, proof, s);
  if (ret != C_KZG_OK) return -1;
  return b ? 0 : 1;
}

C_KZG_RET compute_aggregate_kzg_proof_wrap(KZGProof out, const Blob blobs[], size_t n, const KZGSettings *s)
 {
  C_KZG_RET ret;

  ret = compute_aggregate_kzg_proof(out, blobs, n, s);
  return ret;
}

int verify_kzg_proof_wrap(const uint8_t c[48], const uint8_t z[32], const uint8_t y[32], const uint8_t p[48], KZGSettings *s)
{
  bool out;

  if (verify_kzg_proof(&out, c, z, y, p, s) != C_KZG_OK)
    return -2;

  return out ? 0 : 1;
}
