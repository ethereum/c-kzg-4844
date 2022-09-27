/*
 * Copyright 2021 Benjamin Edgington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "c_kzg_4844.h"
#include "c_kzg_alloc.h"

#include <inttypes.h>
#include <stdio.h>

C_KZG_RET load_trusted_setup(KZGSettings *out, FILE *in) {
  // custom version of new_kzg_settings to avoid unnecessary allocation

  uint64_t n2, i;
  int j; uint8_t c[96];
  blst_p1_affine g1_affine;
  blst_p2_affine g2_affine;

  fscanf(in, "%" SCNu64, &out->length);
  fscanf(in, "%" SCNu64, &n2);

  TRY(new_g1_array(&out->secret_g1, out->length));
  TRY(new_g1_array(&out->secret_g1_l, out->length));
  TRY(new_g2_array(&out->secret_g2, n2));

  for (i = 0; i < out->length; i++) {
    for (j = 0; j < 48; j++) {
      fscanf(in, "%2hhx", &c[j]);
    }
    blst_p1_uncompress(&g1_affine, c);
    blst_p1_from_affine(&out->secret_g1[i], &g1_affine);
  }

  for (i = 0; i < n2; i++) {
    for (j = 0; j < 96; j++) {
      fscanf(in, "%2hhx", &c[j]);
    }
    blst_p2_uncompress(&g2_affine, c);
    blst_p2_from_affine(&out->secret_g2[i], &g2_affine);
  }

  unsigned int max_scale = 0;
  while (((uint64_t)1 << max_scale) < out->length) max_scale++;

  out->fs = (FFTSettings*)malloc(sizeof(FFTSettings));

  TRY(new_fft_settings((FFTSettings*)out->fs, max_scale));

  return fft_g1(out->secret_g1_l, out->secret_g1, true, out->length, out->fs);

}

void free_trusted_setup(KZGSettings *s) {
  free_fft_settings((FFTSettings*)s->fs);
  free_kzg_settings(s);
}

void compute_powers(BLSFieldElement out[], const BLSFieldElement *x, uint64_t n) { fr_pow(out, x, n); }

void vector_lincomb(BLSFieldElement out[], const BLSFieldElement *vectors, const BLSFieldElement *scalars, uint64_t num_vectors, uint64_t vector_len) {
  fr_vector_lincomb(out, vectors, scalars, num_vectors, vector_len);
}

void g1_lincomb(KZGCommitment *out, const KZGCommitment points[], const BLSFieldElement scalars[], uint64_t num_points) {
  g1_linear_combination(out, points, scalars, num_points);

void blob_to_kzg_commitment(KZGCommitment *out, const BLSFieldElement blob[], const KZGSettings *s) {
  g1_linear_combination(out, s->secret_g1_l, blob, s->length);
}

void bytes_to_bls_field(BLSFieldElement *out, const scalar_t *bytes) {
  fr_from_scalar(out, bytes);
}

C_KZG_RET evaluate_polynomial_in_evaluation_form(BLSFieldElement *out, const PolynomialEvalForm *polynomial, const BLSFieldElement *z, const KZGSettings *s) {
   return eval_poly_l(out, polynomial, z, s->fs);
}

C_KZG_RET verify_kzg_proof(bool *out, const KZGCommitment *polynomial_kzg, const BLSFieldElement *z, const BLSFieldElement *y, const KZGProof *kzg_proof, const KZGSettings *s) {
  return check_proof_single(out, polynomial_kzg, kzg_proof, z, y, s);
}

C_KZG_RET compute_kzg_proof(KZGProof *out, const PolynomialEvalForm *polynomial, const BLSFieldElement *z, const KZGSettings *s) {
  BLSFieldElement value;
  TRY(evaluate_polynomial_in_evaluation_form(&value, polynomial, z, s));
  return compute_proof_single_l(out, polynomial, z, &value, s);
}

#ifdef KZGTEST

#include "../inc/acutest.h"
#include "test_util.h"

void load_trusted_setup_test(void) {
  FILE *in = fopen("trusted_setup.txt", "r");
  KZGSettings ks;
  TEST_CHECK(C_KZG_OK == load_trusted_setup(&ks, in));
  fclose(in);
  free_trusted_setup(&ks);
}

TEST_LIST = {
    {"C_KZG_4844_TEST", title},
    {"load_trusted_setup_test", load_trusted_setup_test},
    {NULL, NULL} /* zero record marks the end of the list */
};

#endif // KZGTEST
