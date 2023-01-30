/*
 * This file contains unit tests for C-KZG-4844.
 */
#define UNIT_TESTS

#include "tinytest.h"
#include "blst.h"
#include "c_kzg_4844.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>

KZGSettings s;

static void setup(void) {
    FILE *fp;
    C_KZG_RET ret;

    fp = fopen("trusted_setup.txt", "r");
    assert(fp != NULL);

    ret = load_trusted_setup_file(&s, fp);
    assert(ret == C_KZG_OK);

    fclose(fp);
}

static void teardown(void) {
    free_trusted_setup(&s);
}

static void get_32_rand_bytes(uint8_t *out) {
    static uint64_t seed = 0;
    seed++;
    blst_sha256(out, (uint8_t*)&seed, sizeof(seed));
}

static void get_rand_field_element(Bytes32 *out) {
    fr_t tmp_fr;
    Bytes32 tmp_bytes;

    /*
     * Take 32 random bytes, make them an Fr, and then
     * turn the Fr back to a bytes array.
     */
    get_32_rand_bytes((uint8_t *)&tmp_bytes);
    hash_to_bls_field(&tmp_fr, &tmp_bytes);
    bytes_from_bls_field(out, &tmp_fr);
}

void get_rand_blob(Blob *out) {
    for (int i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++) {
        get_rand_field_element((Bytes32 *)&out->bytes[i * 32]);
    }
}

static void test_compute_kzg_proof(void) {
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

int main(void)
{
    setup();
    RUN(test_compute_kzg_proof);
    teardown();

    return TEST_REPORT();
}
