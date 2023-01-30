/* Tests for myfunctions.c, using TinyTest. */

#define UNIT_TESTS

#include "tinytest.h"
#include "blst.h"

#include "c_kzg_4844.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

KZGSettings s;

void load_setup() {
  FILE *fp;
  C_KZG_RET ret;
  fp = fopen("trusted_setup.txt", "r");

  ret = load_trusted_setup_file(&s, fp);
  assert(ret == C_KZG_OK);

  fclose(fp);
}

void get_32_rand_bytes(uint8_t *out) {
  static uint64_t seed = 0;
  seed++;
  blst_sha256(out, (uint8_t*)&seed, sizeof(seed));
}

void get_rand_field_element(Bytes32 *out) {
  fr_t tmp;
  Bytes32 tmp_rand;

  memset(out, 0, sizeof(Bytes32));

  // Take 32 random bytes, make them an Fr, and then turn the Fr back to a bytes array
  get_32_rand_bytes((uint8_t *) &tmp_rand);
  hash_to_bls_field(&tmp, &tmp_rand);
  bytes_from_bls_field(out, &tmp);
}

void get_rand_blob(Blob *out) {
  memset(out, 0, sizeof(Blob));

  uint8_t *blob_bytes = (uint8_t *) out;
  for (int i = 0; i < 128; i++) {
    get_rand_field_element((Bytes32 *)&blob_bytes[i * 32]);
  }
}

void test_compute_kzg_proof() {
  C_KZG_RET ret;
  Bytes48 proof;
  Bytes32 z;
  KZGCommitment c;
  Blob blob;

  get_rand_field_element(&z);
  get_rand_blob(&blob);

  ret = blob_to_kzg_commitment(&c, &blob, &s);
  ASSERT_EQUALS(ret, C_KZG_OK);

  ret = compute_kzg_proof(&proof, &blob, &z, &s);
  ASSERT_EQUALS(ret, C_KZG_OK);

  // XXX now verify it!
}

/* test runner */
int main()
{
  load_setup();

  RUN(test_compute_kzg_proof);

  free_trusted_setup(&s);
  return TEST_REPORT();
}
