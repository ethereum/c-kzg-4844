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

  if (load_trusted_setup(out, f) != C_KZG_OK) { free(out); return NULL; }

  return out;
}

void free_trusted_setup_wrap(KZGSettings *s) {
  free_trusted_setup(s);
  free(s);
}

void blob_to_kzg_commitment_wrap(uint8_t out[48], const Blob blob, const KZGSettings *s) {
  KZGCommitment c;
  blob_to_kzg_commitment(&c, blob, s);
  bytes_from_g1(out, &c);
}

int verify_aggregate_kzg_proof_wrap(const Blob blobs[], const uint8_t commitments[], size_t n, const uint8_t proof[48], const KZGSettings *s) {
  KZGProof f;
  C_KZG_RET ret;
  ret = bytes_to_g1(&f, proof);
  if (ret != C_KZG_OK) return -1;

  KZGCommitment* c = calloc(n, sizeof(KZGCommitment));
  if (c == NULL) return -2;

  for (size_t i = 0; i < n; i++) {
    ret = bytes_to_g1(&c[i], &commitments[i * 48]);
    if (ret != C_KZG_OK) { free(c); return -1; }
  }

  bool b;
  ret = verify_aggregate_kzg_proof(&b, blobs, c, n, &f, s);
  free(c);
  if (ret != C_KZG_OK) return -1;

  return b ? 0 : 1;
}

C_KZG_RET compute_aggregate_kzg_proof_wrap(uint8_t out[48], const Blob blobs[], size_t n, const KZGSettings *s) {
  KZGProof f;
  C_KZG_RET ret;
  ret = compute_aggregate_kzg_proof(&f, blobs, n, s);
  if (ret != C_KZG_OK) return -1;
  bytes_from_g1(out, &f);
  return C_KZG_OK;
}

int verify_kzg_proof_wrap(const uint8_t c[48], const uint8_t z[32], const uint8_t y[32], const uint8_t p[48], KZGSettings *s) {
  KZGCommitment commitment;
  KZGProof proof;
  bool out;

  if (bytes_to_g1(&commitment, c) != C_KZG_OK) return -1;
  if (bytes_to_g1(&proof, p) != C_KZG_OK) return -1;

  if (verify_kzg_proof(&out, &commitment, z, y, &proof, s) != C_KZG_OK)
    return -2;

  return out ? 0 : 1;
}
