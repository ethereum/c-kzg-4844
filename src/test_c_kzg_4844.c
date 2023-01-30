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

static void test_compute_and_verify_kzg_proof(void) {
    C_KZG_RET ret;
    Bytes48 proof;
    Bytes32 z, y;
    KZGCommitment c;
    Blob blob;
    Polynomial poly;
    fr_t y_fr, z_fr;
    bool ok;

    /* Some preparation */
    get_rand_field_element(&z);
    get_rand_blob(&blob);

    ret = blob_to_kzg_commitment(&c, &blob, &s);
    ASSERT_EQUALS(ret, C_KZG_OK);

    /* Compute the proof */
    ret = compute_kzg_proof(&proof, &blob, &z, &s);
    ASSERT_EQUALS(ret, C_KZG_OK);

    /* Now let's attempt to verify the proof */
    /* First convert the blob to field elements */
    ret = blob_to_polynomial(&poly, &blob);
    ASSERT_EQUALS(ret, C_KZG_OK);

    /* Also convert z to a field element */
    ret = bytes_to_bls_field(&z_fr, &z);
    ASSERT_EQUALS(ret, C_KZG_OK);

    /* Now evaluate the poly at `z` to learn `y` */
    ret = evaluate_polynomial_in_evaluation_form(&y_fr, &poly, &z_fr, &s);
    ASSERT_EQUALS(ret, C_KZG_OK);

    /* Now also get `y` in bytes */
    bytes_from_bls_field(&y, &y_fr);

    /* Finally verify the proof */
    ret = verify_kzg_proof(&ok, &c, &z, &y, &proof, &s);
    ASSERT_EQUALS(ret, C_KZG_OK);

    /* The proof should verify! */
    ASSERT_EQUALS(ok, 1);
}

int main(void)
{
    setup();
    RUN(test_compute_and_verify_kzg_proof);
    teardown();

    return TEST_REPORT();
}
