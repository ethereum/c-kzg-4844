#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "c_kzg_4844.h"
#include "ckzg.h"

KZGSettings* load_trusted_setup_wrap(const char* file) {
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

int verify_aggregate_kzg_proof_wrap(const Blob *blobs, const KZGCommitment *commitments, size_t n, const KZGProof *proof, const KZGSettings *s) {
  bool b;
  C_KZG_RET ret = verify_aggregate_kzg_proof(&b, blobs, commitments, n, proof, s);
  if (ret != C_KZG_OK) return -1;

  return b ? 0 : 1;
}

int verify_kzg_proof_wrap(const KZGCommitment *c, const Bytes32 *z, const Bytes32 *y, const KZGProof *p, KZGSettings *s) {
  bool out;
  if (verify_kzg_proof(&out, c, z, y, p, s) != C_KZG_OK)
    return -2;

  return out ? 0 : 1;
}
