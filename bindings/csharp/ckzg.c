#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "c_kzg_4844.h"

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

void blob_to_kzg_commitment_wrap(uint8_t out[48], const uint8_t blob[FIELD_ELEMENTS_PER_BLOB * 32], const KZGSettings *s) {
  Polynomial p;
  for (size_t i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++)
    bytes_to_bls_field(&p[i], &blob[i * 32]);

  KZGCommitment c;
  blob_to_kzg_commitment(&c, p, s);

  bytes_from_g1(out, &c);
}

int verify_aggregate_kzg_proof_wrap(const uint8_t blobs[], const uint8_t commitments[], size_t n, const uint8_t proof[48], const KZGSettings *s) {
  Polynomial* p = calloc(n, sizeof(Polynomial));
  if (p == NULL) return -1;

  KZGCommitment* c = calloc(n, sizeof(KZGCommitment));
  if (c == NULL) { free(p); return -1; }

  C_KZG_RET ret;

  for (size_t i = 0; i < n; i++) {
    for (size_t j = 0; j < FIELD_ELEMENTS_PER_BLOB; j++)
      bytes_to_bls_field(&p[i][j], &blobs[i * FIELD_ELEMENTS_PER_BLOB * 32 + j * 32]);
    ret = bytes_to_g1(&c[i], &commitments[i * 48]);
    if (ret != C_KZG_OK) { free(c); free(p); return -1; }
  }

  KZGProof f;
  ret = bytes_to_g1(&f, proof);
  if (ret != C_KZG_OK) { free(c); free(p); return -1; }

  bool b;
  ret = verify_aggregate_kzg_proof(&b, p, c, n, &f, s);
  if (ret != C_KZG_OK) { free(c); free(p); return -1; }

  free(c); free(p);
  return b ? 0 : 1;
}

C_KZG_RET compute_aggregate_kzg_proof_wrap(uint8_t out[48], const uint8_t blobs[], size_t n, const KZGSettings *s) {
  Polynomial* p = calloc(n, sizeof(Polynomial));
  if (p == NULL) return -1;

  for (size_t i = 0; i < n; i++)
    for (size_t j = 0; j < FIELD_ELEMENTS_PER_BLOB; j++)
      bytes_to_bls_field(&p[i][j], &blobs[i * FIELD_ELEMENTS_PER_BLOB * 32 + j * 32]);

  KZGProof f;
  C_KZG_RET ret = compute_aggregate_kzg_proof(&f, p, n, s);

  free(p);
  if (ret != C_KZG_OK) return ret;

  bytes_from_g1(out, &f);
  return C_KZG_OK;
}

int verify_kzg_proof_wrap(const uint8_t c[48], const uint8_t x[32], const uint8_t y[32], const uint8_t p[48], KZGSettings *s) {
  KZGCommitment commitment;
  KZGProof proof;
  BLSFieldElement fx, fy;
  bool out;

  bytes_to_bls_field(&fx, x);
  bytes_to_bls_field(&fy, y);
  if (bytes_to_g1(&commitment, c) != C_KZG_OK) return -1;
  if (bytes_to_g1(&proof, p) != C_KZG_OK) return -1;

  if (verify_kzg_proof(&out, &commitment, &fx, &fy, &proof, s) != C_KZG_OK)
    return -2;

  return out ? 0 : 1;
}
