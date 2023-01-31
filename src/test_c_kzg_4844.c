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

///////////////////////////////////////////////////////////////////////////////
// Globals
///////////////////////////////////////////////////////////////////////////////

KZGSettings s;

///////////////////////////////////////////////////////////////////////////////
// Helper functions
///////////////////////////////////////////////////////////////////////////////

static void get_32_rand_bytes(uint8_t *out) {
    static uint64_t seed = 0;
    blst_sha256(out, (uint8_t*)&seed, sizeof(seed));
    seed++;
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

///////////////////////////////////////////////////////////////////////////////
// Tests for blob_to_kzg_commitment
///////////////////////////////////////////////////////////////////////////////

static void test_blob_to_kzg_commitment__succeeds_x_less_than_modulus(void) {
    C_KZG_RET ret;
    KZGCommitment c;
    Blob blob;

    /*
     * A valid field element is x < BLS_MODULUS.
     * Therefore, x = BLS_MODULUS - 1 should be valid.
     *
     * bls_modulus = 52435875175126190479447740508185965837690552500527637822603658699938581184513
     * x = int(bls_modulus - 1).to_bytes(32, 'little')
     * print("{" + ", ".join([f"0x{i:02x}" for i in x]) + "}")
     */
    Bytes32 field_element = {
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4, 0xbd, 0x53,
        0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33,
        0x48, 0x7d, 0x9d, 0x29, 0x53, 0xa7, 0xed, 0x73
    };

    memset(&blob, 0, sizeof(blob));
    memcpy(blob.bytes, field_element.bytes, BYTES_PER_FIELD_ELEMENT);
    ret = blob_to_kzg_commitment(&c, &blob, &s);
    ASSERT_EQUALS(ret, C_KZG_OK);
}

static void test_blob_to_kzg_commitment__fails_x_equal_to_modulus(void) {
    C_KZG_RET ret;
    KZGCommitment c;
    Blob blob;

    /*
     * A valid field element is x < BLS_MODULUS.
     * Therefore, x = BLS_MODULUS should be invalid.
     *
     * bls_modulus = 52435875175126190479447740508185965837690552500527637822603658699938581184513
     * x = int(bls_modulus).to_bytes(32, 'little')
     * print("{" + ", ".join([f"0x{i:02x}" for i in x]) + "}")
     */
    Bytes32 field_element = {
        0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4, 0xbd, 0x53,
        0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33,
        0x48, 0x7d, 0x9d, 0x29, 0x53, 0xa7, 0xed, 0x73
    };

    memset(&blob, 0, sizeof(blob));
    memcpy(blob.bytes, field_element.bytes, BYTES_PER_FIELD_ELEMENT);
    ret = blob_to_kzg_commitment(&c, &blob, &s);
    ASSERT_EQUALS(ret, C_KZG_BADARGS);
}

static void test_blob_to_kzg_commitment__fails_x_greater_than_modulus(void) {
    C_KZG_RET ret;
    KZGCommitment c;
    Blob blob;

    /*
     * A valid field element is x < BLS_MODULUS.
     * Therefore, x = BLS_MODULUS + 1 should be invalid.
     *
     * bls_modulus = 52435875175126190479447740508185965837690552500527637822603658699938581184513
     * x = int(bls_modulus + 1).to_bytes(32, 'little')
     * print("{" + ", ".join([f"0x{i:02x}" for i in x]) + "}")
     */
    Bytes32 field_element = {
        0x02, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4, 0xbd, 0x53,
        0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33,
        0x48, 0x7d, 0x9d, 0x29, 0x53, 0xa7, 0xed, 0x73
    };

    memset(&blob, 0, sizeof(blob));
    memcpy(blob.bytes, field_element.bytes, BYTES_PER_FIELD_ELEMENT);
    ret = blob_to_kzg_commitment(&c, &blob, &s);
    ASSERT_EQUALS(ret, C_KZG_BADARGS);
}

static void test_blob_to_kzg_commitment__succeeds_point_at_infinity(void) {
    C_KZG_RET ret;
    KZGCommitment c;
    Blob blob;

    /*
     * Get the commitment for a blob that's all zeros.
     */
    memset(&blob, 0, sizeof(blob));
    ret = blob_to_kzg_commitment(&c, &blob, &s);
    ASSERT_EQUALS(ret, C_KZG_OK);

    /*
     * The commitment should be the serialized point at infinity.
     */
    Bytes48 point_at_infinity = {
        0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    int diff = memcmp(c.bytes, point_at_infinity.bytes, BYTES_PER_COMMITMENT);
    ASSERT_EQUALS(diff, 0);
}

static void test_blob_to_kzg_commitment__succeeds_consistent_commitment(void) {
    C_KZG_RET ret;
    KZGCommitment c;
    Blob blob;

    /*
     * Get a commitment to a random blob.
     */
    get_rand_blob(&blob);
    ret = blob_to_kzg_commitment(&c, &blob, &s);
    ASSERT_EQUALS(ret, C_KZG_OK);

    /*
     * We expect the commitment to match. If it doesn't
     * match, something important has changed.
     */
    Bytes48 expected_commitment = {
        0xaf, 0x19, 0xe4, 0x60, 0x16, 0x9c, 0x57, 0x95,
        0x9c, 0x04, 0x78, 0x6c, 0x95, 0x8e, 0x01, 0xf9,
        0x84, 0xc1, 0x95, 0xbc, 0x56, 0xe9, 0x9b, 0x04,
        0xc0, 0x7e, 0x0c, 0x97, 0x47, 0xe5, 0xdf, 0xa5,
        0x66, 0xa4, 0x77, 0x1b, 0x8b, 0x13, 0x8c, 0xd8,
        0xee, 0xd6, 0x7e, 0xfa, 0x81, 0x16, 0x56, 0x63
    };
    int diff = memcmp(c.bytes, expected_commitment.bytes, BYTES_PER_COMMITMENT);
    ASSERT_EQUALS(diff, 0);
}

///////////////////////////////////////////////////////////////////////////////
// Tests for compute_kzg_proof
///////////////////////////////////////////////////////////////////////////////

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

///////////////////////////////////////////////////////////////////////////////
// Main logic
///////////////////////////////////////////////////////////////////////////////

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

int main(void) {
    setup();
    RUN(test_blob_to_kzg_commitment__succeeds_x_less_than_modulus);
    RUN(test_blob_to_kzg_commitment__fails_x_equal_to_modulus);
    RUN(test_blob_to_kzg_commitment__fails_x_greater_than_modulus);
    RUN(test_blob_to_kzg_commitment__succeeds_point_at_infinity);
    RUN(test_blob_to_kzg_commitment__succeeds_consistent_commitment);
    RUN(test_compute_and_verify_kzg_proof);
    teardown();

    return TEST_REPORT();
}
