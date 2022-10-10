#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "c_kzg_4844.h"

BLSFieldElement* bytes_to_bls_field_wrap(const uint8_t bytes[]) {
  BLSFieldElement* out = (BLSFieldElement*)malloc(sizeof(BLSFieldElement));
  if (out != NULL) bytes_to_bls_field(out, bytes);
  return out;
}

BLSFieldElement* compute_powers_wrap(const BLSFieldElement *r, uint64_t n) {
  BLSFieldElement* out = (BLSFieldElement*)calloc(n, sizeof(BLSFieldElement));
  if (out != NULL) compute_powers(out, r, n);
  return out;
}

PolynomialEvalForm* vector_lincomb_wrap(const uint8_t bytes[], const BLSFieldElement scalars[], uint64_t num_vectors, uint64_t vector_len) {
  PolynomialEvalForm *p = (PolynomialEvalForm*)malloc(sizeof(PolynomialEvalForm));
  if (p == NULL) return NULL;

  if (alloc_polynomial(p, vector_len) != C_KZG_OK) {
    free(p);
    return NULL;
  }

  BLSFieldElement *vectors = (BLSFieldElement*)calloc(num_vectors * vector_len, sizeof(BLSFieldElement));
  if (vectors == NULL) {
    free_polynomial(p);
    free(p);
    return NULL;
  }

  for (uint64_t i = 0; i < num_vectors; i++)
    for (uint64_t j = 0; j < vector_len; j++)
      bytes_to_bls_field(&vectors[i * vector_len + j], &bytes[(i * vector_len + j) * 32]);

  vector_lincomb(p->values, vectors, scalars, num_vectors, vector_len);

  free(vectors);
  return p;
}

KZGCommitment* g1_lincomb_wrap(const uint8_t bytes[], const BLSFieldElement scalars[], uint64_t num_points) {
  KZGCommitment* points = (KZGCommitment*)calloc(num_points, sizeof(KZGCommitment));
  if (points == NULL) return NULL;

  for (uint64_t i = 0; i < num_points; i++) {
    if (bytes_to_g1(&points[i], &bytes[i * 48]) != C_KZG_OK) {
      free(points);
      return NULL;
    }
  }

  KZGCommitment* out = (KZGCommitment*)malloc(sizeof(KZGCommitment));
  if (out == NULL) {
    free(points);
    return NULL;
  }

  g1_lincomb(out, points, scalars, num_points);

  free(points);
  return out;
}

int verify_kzg_proof_wrap(const KZGCommitment* c, const BLSFieldElement* x, const BLSFieldElement* y, const uint8_t p[48], KZGSettings *s) {
  KZGProof proof;
  bool out;

  if (bytes_to_g1(&proof, p) != C_KZG_OK) return -1;

  if (verify_kzg_proof(&out, c, x, y, &proof, s) != C_KZG_OK)
    return -2;

  return out ? 1 : 0;
}

KZGSettings* load_trusted_setup_wrap(const char* file) {
  KZGSettings* out = (KZGSettings*)malloc(sizeof(KZGSettings));

  if (out == NULL) return NULL;

  FILE* f = fopen(file, "r");

  if (f == NULL) return NULL;

  if (load_trusted_setup(out, f) != C_KZG_OK) return NULL;

  return out;
}

int evaluate_polynomial_wrap(uint8_t out[32], const uint8_t pvals[], size_t n, const uint8_t point[32], const KZGSettings *s) {
  PolynomialEvalForm p;

  if (alloc_polynomial(&p, n) != C_KZG_OK)
    return -1;

  for (size_t i = 0; i < n; i++)
    bytes_to_bls_field(&p.values[i], &pvals[i * 32]);

  BLSFieldElement z;
  bytes_to_bls_field(&z, point);

  BLSFieldElement r;

  if (evaluate_polynomial_in_evaluation_form(&r, &p, &z, s) != C_KZG_OK) {
    free_polynomial(&p);
    return -1;
  }

  bytes_from_bls_field(out, &r);

  return 0;
}

void free_trusted_setup_wrap(KZGSettings* s) {
  free_trusted_setup(s);
  free(s);
}
