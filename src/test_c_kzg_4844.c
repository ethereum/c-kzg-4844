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

static void get_rand_bytes32(Bytes32 *out) {
    static uint64_t seed = 0;
    blst_sha256(out->bytes, (uint8_t*)&seed, sizeof(seed));
    seed++;
}

static void get_rand_field_element(Bytes32 *out) {
    fr_t tmp_fr;
    Bytes32 tmp_bytes;

    /*
     * Take 32 random bytes, make them an Fr, and then
     * turn the Fr back to a bytes array.
     */
    get_rand_bytes32(&tmp_bytes);
    hash_to_bls_field(&tmp_fr, &tmp_bytes);
    bytes_from_bls_field(out, &tmp_fr);
}

static void get_rand_blob(Blob *out) {
    for (int i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++) {
        get_rand_field_element((Bytes32 *)&out->bytes[i * 32]);
    }
}

static void get_rand_g1_bytes(Bytes48 *out) {
    C_KZG_RET ret;
    Blob blob;

    /*
     * Get the commitment to a random blob.
     * This commitment is a valid g1 point.
     */
    get_rand_blob(&blob);
    ret = blob_to_kzg_commitment(out, &blob, &s);
    ASSERT_EQUALS(ret, C_KZG_OK);
}

static void bytes32_from_hex(Bytes32 *out, const char *hex) {
    int matches;
    for (int i = 0; i < sizeof(Bytes32); i++) {
        matches = sscanf(hex + i*2, "%2hhx", &out->bytes[i]);
        ASSERT_EQUALS(matches, 1);
    }
}

static void bytes48_from_hex(Bytes48 *out, const char *hex) {
    int matches;
    for (int i = 0; i < sizeof(Bytes48); i++) {
        matches = sscanf(hex + i*2, "%2hhx", &out->bytes[i]);
        ASSERT_EQUALS(matches, 1);
    }
}

static void get_rand_uint32(uint32_t *out) {
    Bytes32 b;
    get_rand_bytes32(&b);
    *out = *(uint32_t *)(b.bytes);
}

///////////////////////////////////////////////////////////////////////////////
// Tests for blob_to_kzg_commitment
///////////////////////////////////////////////////////////////////////////////

static void test_blob_to_kzg_commitment__succeeds_x_less_than_modulus(void) {
    C_KZG_RET ret;
    KZGCommitment c;
    Blob blob;
    Bytes32 b;

    /*
     * A valid field element is x < BLS_MODULUS.
     * Therefore, x = BLS_MODULUS - 1 should be valid.
     *
     * int(BLS_MODULUS - 1).to_bytes(32, 'little').hex()
     */
    bytes32_from_hex(&b, "00000000fffffffffe5bfeff02a4bd5305d8a10908d83933487d9d2953a7ed73");

    memset(&blob, 0, sizeof(blob));
    memcpy(blob.bytes, b.bytes, BYTES_PER_FIELD_ELEMENT);
    ret = blob_to_kzg_commitment(&c, &blob, &s);
    ASSERT_EQUALS(ret, C_KZG_OK);
}

static void test_blob_to_kzg_commitment__fails_x_equal_to_modulus(void) {
    C_KZG_RET ret;
    KZGCommitment c;
    Blob blob;
    Bytes32 b;

    /*
     * A valid field element is x < BLS_MODULUS.
     * Therefore, x = BLS_MODULUS should be invalid.
     *
     * int(BLS_MODULUS).to_bytes(32, 'little').hex()
     */
    bytes32_from_hex(&b, "01000000fffffffffe5bfeff02a4bd5305d8a10908d83933487d9d2953a7ed73");

    memset(&blob, 0, sizeof(blob));
    memcpy(blob.bytes, b.bytes, BYTES_PER_FIELD_ELEMENT);
    ret = blob_to_kzg_commitment(&c, &blob, &s);
    ASSERT_EQUALS(ret, C_KZG_BADARGS);
}

static void test_blob_to_kzg_commitment__fails_x_greater_than_modulus(void) {
    C_KZG_RET ret;
    KZGCommitment c;
    Blob blob;
    Bytes32 b;

    /*
     * A valid field element is x < BLS_MODULUS.
     * Therefore, x = BLS_MODULUS + 1 should be invalid.
     *
     * int(BLS_MODULUS + 1).to_bytes(32, 'little').hex()
     */
    bytes32_from_hex(&b, "02000000fffffffffe5bfeff02a4bd5305d8a10908d83933487d9d2953a7ed73");

    memset(&blob, 0, sizeof(blob));
    memcpy(blob.bytes, b.bytes, BYTES_PER_FIELD_ELEMENT);
    ret = blob_to_kzg_commitment(&c, &blob, &s);
    ASSERT_EQUALS(ret, C_KZG_BADARGS);
}

static void test_blob_to_kzg_commitment__succeeds_point_at_infinity(void) {
    C_KZG_RET ret;
    KZGCommitment c;
    Blob blob;
    Bytes48 point_at_infinity;
    int diff;

    /*
     * Get the commitment for a blob that's all zeros.
     */
    memset(&blob, 0, sizeof(blob));
    ret = blob_to_kzg_commitment(&c, &blob, &s);
    ASSERT_EQUALS(ret, C_KZG_OK);

    /*
     * The commitment should be the serialized point at infinity.
     */
    bytes48_from_hex(&point_at_infinity, "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    diff = memcmp(c.bytes, point_at_infinity.bytes, BYTES_PER_COMMITMENT);
    ASSERT_EQUALS(diff, 0);
}

static void test_blob_to_kzg_commitment__succeeds_consistent_commitment(void) {
    C_KZG_RET ret;
    KZGCommitment c;
    Blob blob;
    Bytes48 expected_commitment;
    int diff;

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
    bytes48_from_hex(&expected_commitment, "af19e460169c57959c04786c958e01f984c195bc56e99b04c07e0c9747e5dfa566a4771b8b138cd8eed67efa81165663");
    diff = memcmp(c.bytes, expected_commitment.bytes, BYTES_PER_COMMITMENT);
    ASSERT_EQUALS(diff, 0);
}

///////////////////////////////////////////////////////////////////////////////
// Tests for validate_kzg_g1
///////////////////////////////////////////////////////////////////////////////

static void test_validate_kzg_g1__succeeds_round_trip(void) {
    C_KZG_RET ret;
    Bytes48 a, b;
    g1_t g1;
    int diff;

    get_rand_g1_bytes(&a);
    ret = validate_kzg_g1(&g1, &a);
    ASSERT_EQUALS(ret, C_KZG_OK);
    bytes_from_g1(&b, &g1);

    diff = memcmp(a.bytes, b.bytes, sizeof(Bytes48));
    ASSERT_EQUALS(diff, 0);
}

static void test_validate_kzg_g1__succeeds_correct_point(void) {
    C_KZG_RET ret;
    Bytes48 b;
    g1_t g1;

    bytes48_from_hex(&b, "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a");
    ret = validate_kzg_g1(&g1, &b);
    ASSERT_EQUALS(ret, C_KZG_OK);
}

static void test_validate_kzg_g1__fails_not_in_g1(void) {
    C_KZG_RET ret;
    Bytes48 b;
    g1_t g1;

    bytes48_from_hex(&b, "8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    ret = validate_kzg_g1(&g1, &b);
    ASSERT_EQUALS(ret, C_KZG_BADARGS);
}

static void test_validate_kzg_g1__fails_not_in_curve(void) {
    C_KZG_RET ret;
    Bytes48 b;
    g1_t g1;

    bytes48_from_hex(&b, "8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde0");
    ret = validate_kzg_g1(&g1, &b);
    ASSERT_EQUALS(ret, C_KZG_BADARGS);
}

static void test_validate_kzg_g1__fails_x_equal_to_modulus(void) {
    C_KZG_RET ret;
    Bytes48 b;
    g1_t g1;

    bytes48_from_hex(&b, "9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab");
    ret = validate_kzg_g1(&g1, &b);
    ASSERT_EQUALS(ret, C_KZG_BADARGS);
}

static void test_validate_kzg_g1__fails_x_greater_than_modulus(void) {
    C_KZG_RET ret;
    Bytes48 b;
    g1_t g1;

    bytes48_from_hex(&b, "9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaac");
    ret = validate_kzg_g1(&g1, &b);
    ASSERT_EQUALS(ret, C_KZG_BADARGS);
}

static void test_validate_kzg_g1__succeeds_infinity_with_true_b_flag(void) {
    C_KZG_RET ret;
    Bytes48 b;
    g1_t g1;

    bytes48_from_hex(&b, "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    ret = validate_kzg_g1(&g1, &b);
    ASSERT_EQUALS(ret, C_KZG_OK);
}

static void test_validate_kzg_g1__fails_infinity_with_true_b_flag(void) {
    C_KZG_RET ret;
    Bytes48 b;
    g1_t g1;

    bytes48_from_hex(&b, "c01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    ret = validate_kzg_g1(&g1, &b);
    ASSERT_EQUALS(ret, C_KZG_BADARGS);
}

static void test_validate_kzg_g1__fails_infinity_with_false_b_flag(void) {
    C_KZG_RET ret;
    Bytes48 b;
    g1_t g1;

    bytes48_from_hex(&b, "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    ret = validate_kzg_g1(&g1, &b);
    ASSERT_EQUALS(ret, C_KZG_BADARGS);
}

static void test_validate_kzg_g1__fails_with_wrong_c_flag(void) {
    C_KZG_RET ret;
    Bytes48 b;
    g1_t g1;

    bytes48_from_hex(&b, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    ret = validate_kzg_g1(&g1, &b);
    ASSERT_EQUALS(ret, C_KZG_BADARGS);
}

static void test_validate_kzg_g1__fails_with_b_flag_and_x_nonzero(void) {
    C_KZG_RET ret;
    Bytes48 b;
    g1_t g1;

    bytes48_from_hex(&b, "c123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    ret = validate_kzg_g1(&g1, &b);
    ASSERT_EQUALS(ret, C_KZG_BADARGS);
}

static void test_validate_kzg_g1__fails_with_b_flag_and_a_flag_true(void) {
    C_KZG_RET ret;
    Bytes48 b;
    g1_t g1;

    bytes48_from_hex(&b, "e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    ret = validate_kzg_g1(&g1, &b);
    ASSERT_EQUALS(ret, C_KZG_BADARGS);
}

///////////////////////////////////////////////////////////////////////////////
// Tests for reverse_bits
///////////////////////////////////////////////////////////////////////////////

static void test_reverse_bits__round_trip(void) {
    uint32_t original;
    uint32_t reversed;
    uint32_t reversed_reversed;

    get_rand_uint32(&original);
    reversed = reverse_bits(original);
    reversed_reversed = reverse_bits(reversed);
    ASSERT_EQUALS(reversed_reversed, original);
}

static void test_reverse_bits__all_bits_are_zero(void) {
    uint32_t original = 0b00000000000000000000000000000000;
    uint32_t reversed = 0b00000000000000000000000000000000;
    ASSERT_EQUALS(reverse_bits(original), reversed);
}

static void test_reverse_bits__some_bits_are_one(void) {
    uint32_t original = 0b10101000011111100000000000000010;
    uint32_t reversed = 0b01000000000000000111111000010101;
    ASSERT_EQUALS(reverse_bits(original), reversed);
}

static void test_reverse_bits__all_bits_are_one(void) {
    uint32_t original = 0b11111111111111111111111111111111;
    uint32_t reversed = 0b11111111111111111111111111111111;
    ASSERT_EQUALS(reverse_bits(original), reversed);
}

///////////////////////////////////////////////////////////////////////////////
// Tests for compute_powers
///////////////////////////////////////////////////////////////////////////////

static void test_compute_powers__expected_result(void) {
    C_KZG_RET ret;
    Bytes32 field_element_bytes;
    fr_t field_element_fr;
    fr_t *powers = NULL;
    int n = 3, diff;
    Bytes32 expected[n];
    Bytes32 powers_bytes[n];

    get_rand_field_element(&field_element_bytes);
    ret = bytes_to_bls_field(&field_element_fr, &field_element_bytes);
    ASSERT_EQUALS(ret, C_KZG_OK);

    powers = calloc(n, sizeof(fr_t));
    ASSERT("failed to allocate powers", powers != NULL);
    compute_powers(powers, &field_element_fr, n);

#if 0
    /*
     * Generate the expected results.
     */
    for (int i = 0; i < n; i++) {
        Bytes32 tmp;
        bytes_from_bls_field(&tmp, &powers[i]);
        for (int j = 0; j < 32; j++) {
            printf("%02x", tmp.bytes[j]);
        }
        printf("\n");
    }
#endif

    bytes32_from_hex(&expected[0], "0100000000000000000000000000000000000000000000000000000000000000");
    bytes32_from_hex(&expected[1], "e1c3192925d7eb42bd9861585eba38d231736117ca42e2b4968146a00d41f51b");
    bytes32_from_hex(&expected[2], "0e8a454760e9de40001e89f33d8c9ea9f30345d4b6615dbcf83f6988cb7b412f");

    for (int i = 0; i < n; i++) {
        bytes_from_bls_field(&powers_bytes[i], &powers[i]);
        diff = memcmp(powers_bytes[i].bytes, expected[i].bytes, sizeof(Bytes32));
        ASSERT_EQUALS(diff, 0);
    }
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
    RUN(test_validate_kzg_g1__succeeds_round_trip);
    RUN(test_validate_kzg_g1__succeeds_correct_point);
    RUN(test_validate_kzg_g1__fails_not_in_g1);
    RUN(test_validate_kzg_g1__fails_not_in_curve);
    RUN(test_validate_kzg_g1__fails_x_equal_to_modulus);
    RUN(test_validate_kzg_g1__fails_x_greater_than_modulus);
    RUN(test_validate_kzg_g1__succeeds_infinity_with_true_b_flag);
    RUN(test_validate_kzg_g1__fails_infinity_with_true_b_flag);
    RUN(test_validate_kzg_g1__fails_infinity_with_false_b_flag);
    RUN(test_validate_kzg_g1__fails_with_wrong_c_flag);
    RUN(test_validate_kzg_g1__fails_with_b_flag_and_x_nonzero);
    RUN(test_validate_kzg_g1__fails_with_b_flag_and_a_flag_true);
    RUN(test_reverse_bits__round_trip);
    RUN(test_reverse_bits__all_bits_are_zero);
    RUN(test_reverse_bits__some_bits_are_one);
    RUN(test_reverse_bits__all_bits_are_one);
    RUN(test_compute_powers__expected_result);
    RUN(test_compute_and_verify_kzg_proof);
    teardown();

    return TEST_REPORT();
}
