/*
 * This file contains unit tests for C-KZG-4844.
 */
#include "c_kzg_4844.c"
#include "tinytest.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#ifdef PROFILE
#include <gperftools/profiler.h>
#endif

///////////////////////////////////////////////////////////////////////////////
// Globals
///////////////////////////////////////////////////////////////////////////////

KZGSettings s;

///////////////////////////////////////////////////////////////////////////////
// Helper functions
///////////////////////////////////////////////////////////////////////////////

static void get_rand_bytes32(Bytes32 *out) {
    static uint64_t seed = 0;
    blst_sha256(out->bytes, (uint8_t *)&seed, sizeof(seed));
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
    for (size_t i = 0; i < sizeof(Bytes32); i++) {
        matches = sscanf(hex + i * 2, "%2hhx", &out->bytes[i]);
        ASSERT_EQUALS(matches, 1);
    }
}

static void bytes48_from_hex(Bytes48 *out, const char *hex) {
    int matches;
    for (size_t i = 0; i < sizeof(Bytes48); i++) {
        matches = sscanf(hex + i * 2, "%2hhx", &out->bytes[i]);
        ASSERT_EQUALS(matches, 1);
    }
}

static void get_rand_uint32(uint32_t *out) {
    Bytes32 b;
    get_rand_bytes32(&b);
    *out = *(uint32_t *)(b.bytes);
}

///////////////////////////////////////////////////////////////////////////////
// Tests for memory allocation functions
///////////////////////////////////////////////////////////////////////////////

static void test_c_kzg_malloc__succeeds_size_greater_than_zero(void) {
    C_KZG_RET ret;
    void *ptr = NULL;

    ret = c_kzg_malloc(&ptr, 123);
    ASSERT_EQUALS(ret, C_KZG_OK);
    ASSERT("valid pointer", ptr != NULL);
    free(ptr);
}

static void test_c_kzg_malloc__fails_size_equal_to_zero(void) {
    C_KZG_RET ret;
    void *ptr = (void *)0x123;

    ret = c_kzg_malloc(&ptr, 0);
    ASSERT_EQUALS(ret, C_KZG_BADARGS);
    ASSERT_EQUALS(ptr, NULL);
}

static void test_c_kzg_malloc__fails_too_big(void) {
    C_KZG_RET ret;
    void *ptr = NULL;

    ret = c_kzg_malloc(&ptr, UINT64_MAX);
    ASSERT_EQUALS(ret, C_KZG_MALLOC);
    ASSERT_EQUALS(ptr, NULL);
}

static void test_c_kzg_calloc__succeeds_size_greater_than_zero(void) {
    C_KZG_RET ret;
    void *ptr = NULL;

    ret = c_kzg_calloc(&ptr, 123, 456);
    ASSERT_EQUALS(ret, C_KZG_OK);
    ASSERT("valid pointer", ptr != NULL);
    free(ptr);
}

static void test_c_kzg_calloc__fails_count_equal_to_zero(void) {
    C_KZG_RET ret;
    void *ptr = (void *)0x123;

    ret = c_kzg_calloc(&ptr, 0, 456);
    ASSERT_EQUALS(ret, C_KZG_BADARGS);
    ASSERT_EQUALS(ptr, NULL);
}

static void test_c_kzg_calloc__fails_size_equal_to_zero(void) {
    C_KZG_RET ret;
    void *ptr = (void *)0x123;

    ret = c_kzg_calloc(&ptr, 123, 0);
    ASSERT_EQUALS(ret, C_KZG_BADARGS);
    ASSERT_EQUALS(ptr, NULL);
}

static void test_c_kzg_calloc__fails_too_big(void) {
    C_KZG_RET ret;
    void *ptr = NULL;

    ret = c_kzg_calloc(&ptr, UINT64_MAX, UINT64_MAX);
    ASSERT_EQUALS(ret, C_KZG_MALLOC);
    ASSERT_EQUALS(ptr, NULL);
}

///////////////////////////////////////////////////////////////////////////////
// Tests for blob_to_kzg_commitment
///////////////////////////////////////////////////////////////////////////////

static void test_blob_to_kzg_commitment__succeeds_x_less_than_modulus(void) {
    C_KZG_RET ret;
    KZGCommitment c;
    Blob blob;
    Bytes32 field_element;

    /*
     * A valid field element is x < BLS_MODULUS.
     * Therefore, x = BLS_MODULUS - 1 should be valid.
     *
     * int(BLS_MODULUS - 1).to_bytes(32, 'little').hex()
     */
    bytes32_from_hex(
        &field_element,
        "00000000fffffffffe5bfeff02a4bd5305d8a10908d83933487d9d2953a7ed73"
    );

    memset(&blob, 0, sizeof(blob));
    memcpy(blob.bytes, field_element.bytes, BYTES_PER_FIELD_ELEMENT);
    ret = blob_to_kzg_commitment(&c, &blob, &s);
    ASSERT_EQUALS(ret, C_KZG_OK);
}

static void test_blob_to_kzg_commitment__fails_x_equal_to_modulus(void) {
    C_KZG_RET ret;
    KZGCommitment c;
    Blob blob;
    Bytes32 field_element;

    /*
     * A valid field element is x < BLS_MODULUS.
     * Therefore, x = BLS_MODULUS should be invalid.
     *
     * int(BLS_MODULUS).to_bytes(32, 'little').hex()
     */
    bytes32_from_hex(
        &field_element,
        "01000000fffffffffe5bfeff02a4bd5305d8a10908d83933487d9d2953a7ed73"
    );

    memset(&blob, 0, sizeof(blob));
    memcpy(blob.bytes, field_element.bytes, BYTES_PER_FIELD_ELEMENT);
    ret = blob_to_kzg_commitment(&c, &blob, &s);
    ASSERT_EQUALS(ret, C_KZG_BADARGS);
}

static void test_blob_to_kzg_commitment__fails_x_greater_than_modulus(void) {
    C_KZG_RET ret;
    KZGCommitment c;
    Blob blob;
    Bytes32 field_element;

    /*
     * A valid field element is x < BLS_MODULUS.
     * Therefore, x = BLS_MODULUS + 1 should be invalid.
     *
     * int(BLS_MODULUS + 1).to_bytes(32, 'little').hex()
     */
    bytes32_from_hex(
        &field_element,
        "02000000fffffffffe5bfeff02a4bd5305d8a10908d83933487d9d2953a7ed73"
    );

    memset(&blob, 0, sizeof(blob));
    memcpy(blob.bytes, field_element.bytes, BYTES_PER_FIELD_ELEMENT);
    ret = blob_to_kzg_commitment(&c, &blob, &s);
    ASSERT_EQUALS(ret, C_KZG_BADARGS);
}

static void test_blob_to_kzg_commitment__succeeds_point_at_infinity(void) {
    C_KZG_RET ret;
    KZGCommitment c;
    Blob blob;
    Bytes48 point_at_infinity;
    int diff;

    /* Get the commitment for a blob that's all zeros */
    memset(&blob, 0, sizeof(blob));
    ret = blob_to_kzg_commitment(&c, &blob, &s);
    ASSERT_EQUALS(ret, C_KZG_OK);

    /* The commitment should be the serialized point at infinity */
    bytes48_from_hex(
        &point_at_infinity,
        "c00000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000"
    );
    diff = memcmp(c.bytes, point_at_infinity.bytes, BYTES_PER_COMMITMENT);
    ASSERT_EQUALS(diff, 0);
}

static void test_blob_to_kzg_commitment__succeeds_expected_commitment(void) {
    C_KZG_RET ret;
    KZGCommitment c;
    Blob blob;
    Bytes32 field_element;
    Bytes48 expected_commitment;
    int diff;

    bytes32_from_hex(
        &field_element,
        "ad5570f5a3810b7af9d4b24bc1c2ea670245db2eaa49aae654b8f7393a9a6214"
    );

    /* Initialize the blob with a single field element */
    memset(&blob, 0, sizeof(blob));
    memcpy(blob.bytes, field_element.bytes, BYTES_PER_FIELD_ELEMENT);

    /* Get a commitment to this particular blob */
    ret = blob_to_kzg_commitment(&c, &blob, &s);
    ASSERT_EQUALS(ret, C_KZG_OK);

    /*
     * We expect the commitment to match. If it doesn't
     * match, something important has changed.
     */
    bytes48_from_hex(
        &expected_commitment,
        "9815ded2101b6d233fdf31d826ba0557778506df8526f42a"
        "87ccd82db36a238b50f8965c25d4484782097436d29e458e"
    );
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
    Bytes48 g1_bytes;
    g1_t g1;

    bytes48_from_hex(
        &g1_bytes,
        "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e264"
        "4f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a"
    );
    ret = validate_kzg_g1(&g1, &g1_bytes);
    ASSERT_EQUALS(ret, C_KZG_OK);
}

static void test_validate_kzg_g1__fails_not_in_g1(void) {
    C_KZG_RET ret;
    Bytes48 g1_bytes;
    g1_t g1;

    bytes48_from_hex(
        &g1_bytes,
        "8123456789abcdef0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef0123456789abcdef"
    );
    ret = validate_kzg_g1(&g1, &g1_bytes);
    ASSERT_EQUALS(ret, C_KZG_BADARGS);
}

static void test_validate_kzg_g1__fails_not_in_curve(void) {
    C_KZG_RET ret;
    Bytes48 g1_bytes;
    g1_t g1;

    bytes48_from_hex(
        &g1_bytes,
        "8123456789abcdef0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef0123456789abcde0"
    );
    ret = validate_kzg_g1(&g1, &g1_bytes);
    ASSERT_EQUALS(ret, C_KZG_BADARGS);
}

static void test_validate_kzg_g1__fails_x_equal_to_modulus(void) {
    C_KZG_RET ret;
    Bytes48 g1_bytes;
    g1_t g1;

    bytes48_from_hex(
        &g1_bytes,
        "9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf"
        "6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab"
    );
    ret = validate_kzg_g1(&g1, &g1_bytes);
    ASSERT_EQUALS(ret, C_KZG_BADARGS);
}

static void test_validate_kzg_g1__fails_x_greater_than_modulus(void) {
    C_KZG_RET ret;
    Bytes48 g1_bytes;
    g1_t g1;

    bytes48_from_hex(
        &g1_bytes,
        "9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf"
        "6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaac"
    );
    ret = validate_kzg_g1(&g1, &g1_bytes);
    ASSERT_EQUALS(ret, C_KZG_BADARGS);
}

static void test_validate_kzg_g1__succeeds_infinity_with_true_b_flag(void) {
    C_KZG_RET ret;
    Bytes48 g1_bytes;
    g1_t g1;

    bytes48_from_hex(
        &g1_bytes,
        "c00000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000"
    );
    ret = validate_kzg_g1(&g1, &g1_bytes);
    ASSERT_EQUALS(ret, C_KZG_OK);
}

static void test_validate_kzg_g1__fails_infinity_with_true_b_flag(void) {
    C_KZG_RET ret;
    Bytes48 g1_bytes;
    g1_t g1;

    bytes48_from_hex(
        &g1_bytes,
        "c01000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000"
    );
    ret = validate_kzg_g1(&g1, &g1_bytes);
    ASSERT_EQUALS(ret, C_KZG_BADARGS);
}

static void test_validate_kzg_g1__fails_infinity_with_false_b_flag(void) {
    C_KZG_RET ret;
    Bytes48 g1_bytes;
    g1_t g1;

    bytes48_from_hex(
        &g1_bytes,
        "800000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000"
    );
    ret = validate_kzg_g1(&g1, &g1_bytes);
    ASSERT_EQUALS(ret, C_KZG_BADARGS);
}

static void test_validate_kzg_g1__fails_with_wrong_c_flag(void) {
    C_KZG_RET ret;
    Bytes48 g1_bytes;
    g1_t g1;

    bytes48_from_hex(
        &g1_bytes,
        "0123456789abcdef0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef0123456789abcdef"
    );
    ret = validate_kzg_g1(&g1, &g1_bytes);
    ASSERT_EQUALS(ret, C_KZG_BADARGS);
}

static void test_validate_kzg_g1__fails_with_b_flag_and_x_nonzero(void) {
    C_KZG_RET ret;
    Bytes48 g1_bytes;
    g1_t g1;

    bytes48_from_hex(
        &g1_bytes,
        "c123456789abcdef0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef0123456789abcdef"
    );
    ret = validate_kzg_g1(&g1, &g1_bytes);
    ASSERT_EQUALS(ret, C_KZG_BADARGS);
}

static void test_validate_kzg_g1__fails_with_b_flag_and_a_flag_true(void) {
    C_KZG_RET ret;
    Bytes48 g1_bytes;
    g1_t g1;

    bytes48_from_hex(
        &g1_bytes,
        "e00000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000"
    );
    ret = validate_kzg_g1(&g1, &g1_bytes);
    ASSERT_EQUALS(ret, C_KZG_BADARGS);
}

///////////////////////////////////////////////////////////////////////////////
// Tests for reverse_bits
///////////////////////////////////////////////////////////////////////////////

static void test_reverse_bits__succeeds_round_trip(void) {
    uint32_t original;
    uint32_t reversed;
    uint32_t reversed_reversed;

    get_rand_uint32(&original);
    reversed = reverse_bits(original);
    reversed_reversed = reverse_bits(reversed);
    ASSERT_EQUALS(reversed_reversed, original);
}

static void test_reverse_bits__succeeds_all_bits_are_zero(void) {
    uint32_t original = 0b00000000000000000000000000000000;
    uint32_t reversed = 0b00000000000000000000000000000000;
    ASSERT_EQUALS(reverse_bits(original), reversed);
}

static void test_reverse_bits__succeeds_some_bits_are_one(void) {
    uint32_t original = 0b10101000011111100000000000000010;
    uint32_t reversed = 0b01000000000000000111111000010101;
    ASSERT_EQUALS(reverse_bits(original), reversed);
}

static void test_reverse_bits__succeeds_all_bits_are_one(void) {
    uint32_t original = 0b11111111111111111111111111111111;
    uint32_t reversed = 0b11111111111111111111111111111111;
    ASSERT_EQUALS(reverse_bits(original), reversed);
}

///////////////////////////////////////////////////////////////////////////////
// Tests for compute_powers
///////////////////////////////////////////////////////////////////////////////

static void test_compute_powers__succeeds_expected_powers(void) {
    C_KZG_RET ret;
    Bytes32 field_element_bytes;
    fr_t field_element_fr;
    const int n = 3;
    int diff;
    fr_t powers[n];
    Bytes32 powers_bytes[n];
    Bytes32 expected_bytes[n];

    /* Convert random field element to a fr_t */
    bytes32_from_hex(
        &field_element_bytes,
        "e1c3192925d7eb42bd9861585eba38d231736117ca42e2b4968146a00d41f51b"
    );
    ret = bytes_to_bls_field(&field_element_fr, &field_element_bytes);
    ASSERT_EQUALS(ret, C_KZG_OK);

    /* Compute three powers for the given field element */
    compute_powers((fr_t *)&powers, &field_element_fr, n);

    /*
     * These are the expected results. Notable, the first element should always
     * be 1 since x^0 is 1. The second element should be equivalent to the
     * input field element. The third element can be verified with Python.
     */
    bytes32_from_hex(
        &expected_bytes[0],
        "0100000000000000000000000000000000000000000000000000000000000000"
    );
    bytes32_from_hex(
        &expected_bytes[1],
        "e1c3192925d7eb42bd9861585eba38d231736117ca42e2b4968146a00d41f51b"
    );

    /*
     * b = bytes.fromhex("e1c3192925d...")
     * i = (int.from_bytes(b, "little") ** 2) % BLS_MODULUS
     * print(i.to_bytes(32, "little").hex())
     */
    bytes32_from_hex(
        &expected_bytes[2],
        "0e8a454760e9de40001e89f33d8c9ea9f30345d4b6615dbcf83f6988cb7b412f"
    );

    for (int i = 0; i < n; i++) {
        bytes_from_bls_field(&powers_bytes[i], &powers[i]);
        diff = memcmp(
            powers_bytes[i].bytes, expected_bytes[i].bytes, sizeof(Bytes32)
        );
        ASSERT_EQUALS(diff, 0);
    }
}

///////////////////////////////////////////////////////////////////////////////
// Tests for log_2_byte
///////////////////////////////////////////////////////////////////////////////

static void test_log_2_byte__succeeds_expected_values(void) {
    byte i = 0;
    while (true) {
        /*
         * Corresponds to the index of the highest bit set in the byte.
         * Adapted from
         * https://graphics.stanford.edu/~seander/bithacks.html#IntegerLog.
         */
        byte b = i;
        int r, shift;
        r = (b > 0xF) << 2;
        b >>= r;
        shift = (b > 0x3) << 1;
        b >>= (shift + 1);
        r |= shift | b;

        ASSERT_EQUALS(r, log_2_byte(i));

        if (i == 255) break;
        i += 1;
    }
}

///////////////////////////////////////////////////////////////////////////////
// Tests for compute_kzg_proof
///////////////////////////////////////////////////////////////////////////////

static void test_compute_kzg_proof__succeeds_expected_proof(void) {
    C_KZG_RET ret;
    Blob blob;
    Bytes32 input_value, field_element;
    Bytes48 proof, expected_proof;
    int diff;

    bytes32_from_hex(
        &field_element,
        "138a16c66bdd9b0b17978ebd00bedf62307aa545d6b899b35703aedb696e3869"
    );
    bytes32_from_hex(
        &input_value,
        "0d32bafe47065f59692005d9d4b8b4ef67bd0de4c517a91ae0f9b441b84fea03"
    );

    /* Initialize the blob with a single field element */
    memset(&blob, 0, sizeof(blob));
    memcpy(blob.bytes, field_element.bytes, BYTES_PER_FIELD_ELEMENT);

    /* Compute the KZG proof for the given blob & z */
    ret = compute_kzg_proof(&proof, &blob, &input_value, &s);
    ASSERT_EQUALS(ret, C_KZG_OK);

    bytes48_from_hex(
        &expected_proof,
        "899b7e1e7ff2e9b28c631d2f9d6b9ae828749c9dbf84f3f4"
        "3b910bda9558f360f2fa0dac1143460b55908406038eb538"
    );

    /* Compare the computed proof to the expected proof */
    diff = memcmp(proof.bytes, expected_proof.bytes, sizeof(Bytes48));
    ASSERT_EQUALS(diff, 0);
}

static void test_compute_and_verify_kzg_proof__succeeds_round_trip(void) {
    C_KZG_RET ret;
    Bytes48 proof;
    Bytes32 z, y;
    KZGCommitment c;
    Blob blob;
    Polynomial poly;
    fr_t y_fr, z_fr;
    bool ok;

    get_rand_field_element(&z);
    get_rand_blob(&blob);

    /* Get a commitment to that particular blob */
    ret = blob_to_kzg_commitment(&c, &blob, &s);
    ASSERT_EQUALS(ret, C_KZG_OK);

    /* Compute the proof */
    ret = compute_kzg_proof(&proof, &blob, &z, &s);
    ASSERT_EQUALS(ret, C_KZG_OK);

    /*
     * Now let's attempt to verify the proof.
     * First convert the blob to field elements.
     */
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
    ASSERT_EQUALS(ok, true);
}

static void test_compute_and_verify_kzg_proof__succeeds_within_domain(void) {
    for (int i = 0; i < 25; i++) {
        C_KZG_RET ret;
        Blob blob;
        KZGCommitment c;
        Polynomial poly;
        Bytes48 proof;
        Bytes32 z, y;
        fr_t y_fr, z_fr;
        bool ok;

        get_rand_blob(&blob);

        /* Get a commitment to that particular blob */
        ret = blob_to_kzg_commitment(&c, &blob, &s);
        ASSERT_EQUALS(ret, C_KZG_OK);

        /* Get the polynomial version of the blob */
        ret = blob_to_polynomial(&poly, &blob);
        ASSERT_EQUALS(ret, C_KZG_OK);

        z_fr = s.fs->roots_of_unity[i];
        bytes_from_bls_field(&z, &z_fr);

        /* Compute the proof */
        ret = compute_kzg_proof(&proof, &blob, &z, &s);
        ASSERT_EQUALS(ret, C_KZG_OK);

        /* Now evaluate the poly at `z` to learn `y` */
        ret = evaluate_polynomial_in_evaluation_form(&y_fr, &poly, &z_fr, &s);
        ASSERT_EQUALS(ret, C_KZG_OK);

        /* Now also get `y` in bytes */
        bytes_from_bls_field(&y, &y_fr);

        /* Finally verify the proof */
        ret = verify_kzg_proof(&ok, &c, &z, &y, &proof, &s);
        ASSERT_EQUALS(ret, C_KZG_OK);
        ASSERT_EQUALS(ok, true);
    }
}

///////////////////////////////////////////////////////////////////////////////
// Tests for compute_blob_kzg_proof
///////////////////////////////////////////////////////////////////////////////

static void test_compute_and_verify_blob_kzg_proof__succeeds_round_trip(void) {
    C_KZG_RET ret;
    Bytes48 proof;
    KZGCommitment c;
    Blob blob;
    bool ok;

    /* Some preparation */
    get_rand_blob(&blob);
    ret = blob_to_kzg_commitment(&c, &blob, &s);
    ASSERT_EQUALS(ret, C_KZG_OK);

    /* Compute the proof */
    ret = compute_blob_kzg_proof(&proof, &blob, &s);
    ASSERT_EQUALS(ret, C_KZG_OK);

    /* Finally verify the proof */
    ret = verify_blob_kzg_proof(&ok, &blob, &c, &proof, &s);
    ASSERT_EQUALS(ret, C_KZG_OK);
    ASSERT_EQUALS(ok, true);
}

///////////////////////////////////////////////////////////////////////////////
// Tests for verify_kzg_proof_batch
///////////////////////////////////////////////////////////////////////////////

static void test_verify_kzg_proof_batch__succeeds_round_trip(void) {
    C_KZG_RET ret;
    const int n_samples = 16;
    Bytes48 proofs[n_samples];
    KZGCommitment commitments[n_samples];
    Blob blobs[n_samples];
    bool ok;

    /* Some preparation */
    for (int i = 0; i < n_samples; i++) {
        get_rand_blob(&blobs[i]);
        ret = blob_to_kzg_commitment(&commitments[i], &blobs[i], &s);
        ASSERT_EQUALS(ret, C_KZG_OK);
        ret = compute_blob_kzg_proof(&proofs[i], &blobs[i], &s);
        ASSERT_EQUALS(ret, C_KZG_OK);
    }

    /* Verify batched proofs for 0,1,2..16 blobs */
    /* This should still work with zero blobs */
    for (int count = 0; count <= 16; count++) {
        ret = verify_blob_kzg_proof_batch(
            &ok, blobs, commitments, proofs, count, &s
        );
        ASSERT_EQUALS(ret, C_KZG_OK);
        ASSERT_EQUALS(ok, true);
    }
}

static void test_verify_kzg_proof_batch__fails_with_incorrect_proof(void) {
    C_KZG_RET ret;
    const int n_samples = 2;
    Bytes48 proofs[n_samples];
    KZGCommitment commitments[n_samples];
    Blob blobs[n_samples];
    bool ok;

    /* Some preparation */
    for (int i = 0; i < n_samples; i++) {
        get_rand_blob(&blobs[i]);
        ret = blob_to_kzg_commitment(&commitments[i], &blobs[i], &s);
        ASSERT_EQUALS(ret, C_KZG_OK);
        ret = compute_blob_kzg_proof(&proofs[i], &blobs[i], &s);
        ASSERT_EQUALS(ret, C_KZG_OK);
    }

    /* Overwrite second proof with an incorrect one */
    proofs[1] = proofs[0];

    ret = verify_blob_kzg_proof_batch(
        &ok, blobs, commitments, proofs, n_samples, &s
    );
    ASSERT_EQUALS(ret, C_KZG_OK);
    ASSERT_EQUALS(ok, false);
}

///////////////////////////////////////////////////////////////////////////////
// Profiling Functions
///////////////////////////////////////////////////////////////////////////////

#ifdef PROFILE
static void profile_blob_to_kzg_commitment(void) {
    Blob blob;
    KZGCommitment c;

    get_rand_blob(&blob);

    ProfilerStart("blob_to_kzg_commitment.prof");
    for (int i = 0; i < 1000; i++) {
        blob_to_kzg_commitment(&c, &blob, &s);
    }
    ProfilerStop();
}

static void profile_verify_kzg_proof(void) {
    Bytes32 z, y;
    Bytes48 commitment, proof;
    bool out;

    get_rand_g1_bytes(&commitment);
    get_rand_field_element(&z);
    get_rand_field_element(&y);
    get_rand_g1_bytes(&proof);

    ProfilerStart("verify_kzg_proof.prof");
    for (int i = 0; i < 5000; i++) {
        verify_kzg_proof(&out, &commitment, &z, &y, &proof, &s);
    }
    ProfilerStop();
}

static void profile_verify_aggregate_kzg_proof(void) {
    const int n = 16;
    Blob blobs[n];
    Bytes48 commitments[n];
    Bytes48 proof;
    bool out;

    for (int i = 0; i < n; i++) {
        get_rand_g1_bytes(&commitments[i]);
        get_rand_blob(&blobs[i]);
    }
    get_rand_g1_bytes(&proof);

    ProfilerStart("verify_aggregate_kzg_proof.prof");
    for (int i = 0; i < 1000; i++) {
        verify_aggregate_kzg_proof(&out, blobs, commitments, n, &proof, &s);
    }
    ProfilerStop();
}

static void profile_compute_kzg_proof(void) {
    Blob blob;
    Bytes32 z;
    KZGProof out;

    get_rand_blob(&blob);
    get_rand_field_element(&z);

    ProfilerStart("compute_kzg_proof.prof");
    for (int i = 0; i < 100; i++) {
        compute_kzg_proof(&out, &blob, &z, &s);
    }
    ProfilerStop();
}

static void profile_compute_aggregate_kzg_proof(void) {
    const int n = 16;
    Blob blobs[n];
    KZGProof out;

    for (int i = 0; i < n; i++) {
        get_rand_blob(&blobs[i]);
    }

    ProfilerStart("compute_aggregate_kzg_proof.prof");
    for (int i = 0; i < 10; i++) {
        compute_aggregate_kzg_proof(&out, blobs, n, &s);
    }
    ProfilerStop();
}
#endif /* PROFILE */

///////////////////////////////////////////////////////////////////////////////
// Main logic
///////////////////////////////////////////////////////////////////////////////

static void setup(void) {
    FILE *fp;
    C_KZG_RET ret;

    /* Open the mainnet trusted setup file */
    fp = fopen("trusted_setup.txt", "r");
    assert(fp != NULL);

    /* Load that trusted setup file */
    ret = load_trusted_setup_file(&s, fp);
    assert(ret == C_KZG_OK);

    fclose(fp);
}

static void teardown(void) {
    free_trusted_setup(&s);
}

int main(void) {
    setup();
    RUN(test_c_kzg_malloc__succeeds_size_greater_than_zero);
    RUN(test_c_kzg_malloc__fails_size_equal_to_zero);
    RUN(test_c_kzg_malloc__fails_too_big);
    RUN(test_c_kzg_calloc__succeeds_size_greater_than_zero);
    RUN(test_c_kzg_calloc__fails_size_equal_to_zero);
    RUN(test_c_kzg_calloc__fails_count_equal_to_zero);
    RUN(test_c_kzg_calloc__fails_too_big);
    RUN(test_blob_to_kzg_commitment__succeeds_x_less_than_modulus);
    RUN(test_blob_to_kzg_commitment__fails_x_equal_to_modulus);
    RUN(test_blob_to_kzg_commitment__fails_x_greater_than_modulus);
    RUN(test_blob_to_kzg_commitment__succeeds_point_at_infinity);
    RUN(test_blob_to_kzg_commitment__succeeds_expected_commitment);
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
    RUN(test_reverse_bits__succeeds_round_trip);
    RUN(test_reverse_bits__succeeds_all_bits_are_zero);
    RUN(test_reverse_bits__succeeds_some_bits_are_one);
    RUN(test_reverse_bits__succeeds_all_bits_are_one);
    RUN(test_compute_powers__succeeds_expected_powers);
    RUN(test_log_2_byte__succeeds_expected_values);
    RUN(test_compute_kzg_proof__succeeds_expected_proof);
    RUN(test_compute_and_verify_kzg_proof__succeeds_round_trip);
    RUN(test_compute_and_verify_kzg_proof__succeeds_within_domain);
    RUN(test_compute_and_verify_blob_kzg_proof__succeeds_round_trip);
    RUN(test_verify_kzg_proof_batch__succeeds_round_trip);
    RUN(test_verify_kzg_proof_batch__fails_with_incorrect_proof);

    /*
     * These functions are only executed if we're profiling. To me, it makes
     * sense to put these in the testing file so we can re-use the helper
     * functions. Additionally, it checks that whatever performance changes
     * haven't broken the library.
     */
#ifdef PROFILE
    profile_blob_to_kzg_commitment();
    profile_verify_kzg_proof();
    profile_verify_aggregate_kzg_proof();
    profile_compute_kzg_proof();
    profile_compute_aggregate_kzg_proof();
#endif
    teardown();

    return TEST_REPORT();
}
