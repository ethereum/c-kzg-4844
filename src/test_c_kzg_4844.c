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

    memset(out, 0, sizeof(Bytes32));

    /*
     * Take 32 random bytes, make them an Fr, and then
     * turn the Fr back to a bytes array.
     */
    get_32_rand_bytes((uint8_t *)&tmp_bytes);
    hash_to_bls_field(&tmp_fr, &tmp_bytes);
    bytes_from_bls_field(out, &tmp_fr);
}

void get_rand_blob(Blob *out) {
    memset(out, 0, sizeof(Blob));

    uint8_t *blob_bytes = (uint8_t *) out;
    for (int i = 0; i < 128; i++) {
        get_rand_field_element((Bytes32 *)&blob_bytes[i * 32]);
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
    uint8_t field_element_bytes[BYTES_PER_FIELD_ELEMENT] = {
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4, 0xbd, 0x53,
        0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33,
        0x48, 0x7d, 0x9d, 0x29, 0x53, 0xa7, 0xed, 0x73
    };

    memset(&blob, 0, sizeof(blob));
    memcpy(blob.bytes, field_element_bytes, BYTES_PER_FIELD_ELEMENT);
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
    uint8_t field_element_bytes[BYTES_PER_FIELD_ELEMENT] = {
        0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4, 0xbd, 0x53,
        0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33,
        0x48, 0x7d, 0x9d, 0x29, 0x53, 0xa7, 0xed, 0x73
    };

    memset(&blob, 0, sizeof(blob));
    memcpy(blob.bytes, field_element_bytes, BYTES_PER_FIELD_ELEMENT);
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
    uint8_t field_element_bytes[BYTES_PER_FIELD_ELEMENT] = {
        0x02, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4, 0xbd, 0x53,
        0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33,
        0x48, 0x7d, 0x9d, 0x29, 0x53, 0xa7, 0xed, 0x73
    };

    memset(&blob, 0, sizeof(blob));
    memcpy(blob.bytes, field_element_bytes, BYTES_PER_FIELD_ELEMENT);
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
    uint8_t point_at_infinity[BYTES_PER_COMMITMENT] = {
        0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    int diff = memcmp(c.bytes, point_at_infinity, BYTES_PER_COMMITMENT);
    ASSERT_EQUALS(diff, 0);
}

int main(void)
{
    setup();
    RUN(test_compute_kzg_proof);
    RUN(test_blob_to_kzg_commitment__succeeds_x_less_than_modulus);
    RUN(test_blob_to_kzg_commitment__fails_x_equal_to_modulus);
    RUN(test_blob_to_kzg_commitment__fails_x_greater_than_modulus);
    RUN(test_blob_to_kzg_commitment__succeeds_point_at_infinity);
    teardown();

    return TEST_REPORT();
}
