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

static void get_rand_fr(fr_t *out) {
    Bytes32 tmp_bytes;

    get_rand_bytes32(&tmp_bytes);
    hash_to_bls_field(out, &tmp_bytes);
}

/*static void get_rand_scalar(blst_scalar *out) {
    Bytes32 tmp_bytes;
    fr_t tmp_fr;

    get_rand_bytes32(&tmp_bytes);
    hash_to_bls_field(&tmp_fr, &tmp_bytes);
    blst_scalar_from_fr(out, &tmp_fr);
}*/

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

static void get_rand_g1(g1_t *out) {
    Bytes32 tmp_bytes;

    get_rand_bytes32(&tmp_bytes);

    blst_hash_to_g1(out, tmp_bytes.bytes, 32, NULL, 0, NULL, 0);
}

static void get_rand_g2(g2_t *out) {
    Bytes32 tmp_bytes;

    get_rand_bytes32(&tmp_bytes);

    blst_hash_to_g2(out, tmp_bytes.bytes, 32, NULL, 0, NULL, 0);
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
// Tests for fr_div
///////////////////////////////////////////////////////////////////////////////

static void test_fr_div__by_one_is_equal(void) {
    fr_t a, q;

    get_rand_fr(&a);

    fr_div(&q, &a, &FR_ONE);

    bool ok = fr_equal(&q, &a);
    ASSERT_EQUALS(ok, true);
}

static void test_fr_div__by_itself_is_one(void) {
    fr_t a, q;

    get_rand_fr(&a);

    fr_div(&q, &a, &a);

    bool ok = fr_equal(&q, &FR_ONE);
    ASSERT_EQUALS(ok, true);
}

static void test_fr_div__specific_value(void) {
    fr_t a, b, q, check;

    fr_from_uint64(&a, 2345);
    fr_from_uint64(&b, 54321);
    blst_fr_from_hexascii(&check, (const byte*)("0x264d23155705ca938a1f22117681ea9759f348cb177a07ffe0813de67e85c684"));

    fr_div(&q, &a, &b);

    bool ok = fr_equal(&q, &check);
    ASSERT_EQUALS(ok, true);
}

static void test_fr_div__succeeds_round_trip(void) {
    fr_t a, b, q, r;

    get_rand_fr(&a);
    get_rand_fr(&b);

    fr_div(&q, &a, &b);
    blst_fr_mul(&r, &q, &b);


    bool ok = fr_equal(&r, &a);
    ASSERT_EQUALS(ok, true);
}

///////////////////////////////////////////////////////////////////////////////
// Tests for fr_pow
///////////////////////////////////////////////////////////////////////////////

static void test_fr_pow__test_power_of_two(void) {
    fr_t a, r, check;

    fr_from_uint64(&a, 2);
    fr_from_uint64(&check, 0x100000000);

    fr_pow(&r, &a, 32);

    bool ok = fr_equal(&r, &check);
    ASSERT_EQUALS(ok, true);
}

static void test_fr_pow__test_inverse_on_root_of_unity(void) {
    fr_t a, r;

    blst_fr_from_uint64(&a, SCALE2_ROOT_OF_UNITY[31]);

    fr_pow(&r, &a, 1 << 31);

    bool ok = fr_equal(&r, &FR_ONE);
    ASSERT_EQUALS(ok, true);
}

///////////////////////////////////////////////////////////////////////////////
// Tests for fr_batch_inv
///////////////////////////////////////////////////////////////////////////////

static void test_fr_batch_inv__test_consistent(void) {
    fr_t a[32], batch_inverses[32], check_inverses[32];

    for(size_t i = 0; i < 32; i++) {
        get_rand_fr(&a[i]);
        blst_fr_eucl_inverse(&check_inverses[i], &a[i]);
    }

    fr_batch_inv(batch_inverses, a, 32);

    for(size_t i = 0; i < 32; i++) {
        bool ok = fr_equal(&check_inverses[i], &batch_inverses[i]);
        ASSERT_EQUALS(ok, true);
    }
}

static void test_fr_batch_inv__test_zero(void) {
    fr_t a[32], batch_inverses[32];

    for(size_t i = 0; i < 32; i++) {
        get_rand_fr(&a[i]);
    }

    a[5] = FR_ZERO;

    fr_batch_inv(batch_inverses, a, 32);

    for(size_t i = 0; i < 32; i++) {
        bool ok = fr_equal(&batch_inverses[i], &FR_ZERO);
        ASSERT_EQUALS(ok, true);
    }
}

///////////////////////////////////////////////////////////////////////////////
// Tests for g1_mul
///////////////////////////////////////////////////////////////////////////////

static void test_g1_mul__test_consistent(void) {
    blst_scalar s;
    Bytes32 b;
    fr_t f;
    g1_t g, r, check;

    get_rand_field_element(&b);
    blst_scalar_from_lendian(&s, b.bytes);
    blst_fr_from_scalar(&f, &s);

    get_rand_g1(&g);

    blst_p1_mult(&check, &g, (const byte *)&b, 256);
    g1_mul(&r, &g, &f);

    ASSERT("points are equal", blst_p1_is_equal(&check, &r));
}

static void test_g1_mul__test_scalar_is_zero(void) {
    fr_t f;
    g1_t g, r;

    fr_from_uint64(&f, 0);
    get_rand_g1(&g);

    g1_mul(&r, &g, &f);

    ASSERT("result is neutral element", blst_p1_is_inf(&r));
}

static void test_g1_mul__test_different_bit_lengths(void) {
    Bytes32 b;
    fr_t f, two;
    g1_t g, r, check;

    fr_from_uint64(&f, 1);
    fr_from_uint64(&two, 2);
    bytes_from_bls_field(&b, &f);

    for(int i = 1; i < 255; i++) {
        get_rand_g1(&g);

        blst_p1_mult(&check, &g, (const byte *)&b, 256);
        g1_mul(&r, &g, &f);
        
        ASSERT("points are equal", blst_p1_is_equal(&check, &r));

        blst_fr_mul(&f, &f, &two);
        bytes_from_bls_field(&b, &f);
    }
}

///////////////////////////////////////////////////////////////////////////////
// Tests for pairings_verify
///////////////////////////////////////////////////////////////////////////////

static void test_pairings_verify__good_pairing(void) {
    fr_t s;
    g1_t g1, sg1;
    g2_t g2, sg2;

    get_rand_fr(&s);

    get_rand_g1(&g1);
    get_rand_g2(&g2);

    g1_mul(&sg1, &g1, &s);
    g2_mul(&sg2, &g2, &s);

    ASSERT("pairings verify", pairings_verify(&g1, &sg2, &sg1, &g2));
}

static void test_pairings_verify__bad_pairing(void) {
    fr_t s, splusone;
    g1_t g1, sg1;
    g2_t g2, s1g2;

    get_rand_fr(&s);
    blst_fr_add(&splusone, &s, &FR_ONE);

    get_rand_g1(&g1);
    get_rand_g2(&g2);

    g1_mul(&sg1, &g1, &s);
    g2_mul(&s1g2, &g2, &splusone);

    ASSERT("pairings fail", !pairings_verify(&g1, &s1g2, &sg1, &g2));
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

static void test_blob_to_kzg_commitment__succeeds_consistent_commitment(void) {
    C_KZG_RET ret;
    KZGCommitment c;
    Blob blob;
    Bytes48 expected_commitment;
    int diff;

    /* Get a commitment to a random blob */
    get_rand_blob(&blob);
    ret = blob_to_kzg_commitment(&c, &blob, &s);
    ASSERT_EQUALS(ret, C_KZG_OK);

    /*
     * We expect the commitment to match. If it doesn't
     * match, something important has changed.
     */
    bytes48_from_hex(
        &expected_commitment,
        "af19e460169c57959c04786c958e01f984c195bc56e99b04"
        "c07e0c9747e5dfa566a4771b8b138cd8eed67efa81165663"
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
// Tests for log2_pow2
///////////////////////////////////////////////////////////////////////////////

static void test_log2_pow2__succeeds_expected_values(void) {
    uint32_t x = 1;
    for (int i = 0; i < 31; i++) {
        ASSERT_EQUALS(i, log2_pow2(x));
        x <<= 1;
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
    ASSERT_EQUALS(ok, 1);
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
        ASSERT_EQUALS(ok, 1);
    }
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
    RUN(test_fr_div__by_one_is_equal);
    RUN(test_fr_div__by_itself_is_one);
    RUN(test_fr_div__specific_value);
    RUN(test_fr_div__succeeds_round_trip);
    RUN(test_fr_pow__test_power_of_two);
    RUN(test_fr_pow__test_inverse_on_root_of_unity);
    RUN(test_fr_batch_inv__test_consistent);
    RUN(test_fr_batch_inv__test_zero);
    RUN(test_g1_mul__test_consistent);
    RUN(test_g1_mul__test_scalar_is_zero);
    RUN(test_g1_mul__test_different_bit_lengths);
    RUN(test_pairings_verify__good_pairing);
    RUN(test_pairings_verify__bad_pairing);
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
    RUN(test_reverse_bits__succeeds_round_trip);
    RUN(test_reverse_bits__succeeds_all_bits_are_zero);
    RUN(test_reverse_bits__succeeds_some_bits_are_one);
    RUN(test_reverse_bits__succeeds_all_bits_are_one);
    RUN(test_compute_powers__succeeds_expected_powers);
    RUN(test_log_2_byte__succeeds_expected_values);
    RUN(test_log2_pow2__succeeds_expected_values);
    RUN(test_compute_kzg_proof__succeeds_expected_proof);
    RUN(test_compute_and_verify_kzg_proof__succeeds_round_trip);
    RUN(test_compute_and_verify_kzg_proof__succeeds_within_domain);

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
