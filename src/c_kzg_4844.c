/*
 * Copyright 2024 Benjamin Edgington
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

/**
 * @file c_kzg_4844.c
 *
 * Minimal implementation of the polynomial commitments API for EIP-4844.
 */
#include "c_kzg_4844.h"
#include "common.h"

#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

////////////////////////////////////////////////////////////////////////////////////////////////////
// Constants
////////////////////////////////////////////////////////////////////////////////////////////////////

/** The domain separator for the Fiat-Shamir protocol. */
static const char *FIAT_SHAMIR_PROTOCOL_DOMAIN = "FSBLOBVERIFY_V1_";

/** The domain separator for verify_blob_kzg_proof's random challenge. */
static const char *RANDOM_CHALLENGE_DOMAIN_VERIFY_BLOB_KZG_PROOF_BATCH = "RCKZGBATCH___V1_";

/** The number of bytes in a g1 point. */
#define BYTES_PER_G1 48

/** The number of bytes in a g2 point. */
#define BYTES_PER_G2 96

/** The number of g1 points in a trusted setup. */
#define NUM_G1_POINTS FIELD_ELEMENTS_PER_BLOB

/** The number of g2 points in a trusted setup. */
#define NUM_G2_POINTS 65

////////////////////////////////////////////////////////////////////////////////////////////////////
// Helper Functions
////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Test whether the operand is zero in the finite field.
 *
 * @param[in] p The field element to be checked
 *
 * @retval true  The element is zero
 * @retval false The element is not zero
 */
static bool fr_is_zero(const fr_t *p) {
    uint64_t a[4];
    blst_uint64_from_fr(a, p);
    return a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0;
}

/**
 * Montgomery batch inversion in finite field.
 *
 * @param[out] out The inverses of `a`, length `len`
 * @param[in]  a   A vector of field elements, length `len`
 * @param[in]  len The number of field elements
 *
 * @remark This function only supports len > 0.
 * @remark This function does NOT support in-place computation.
 * @remark Return C_KZG_BADARGS if a zero is found in the input. In this case,
 *         the `out` output array has already been mutated.
 */
static C_KZG_RET fr_batch_inv(fr_t *out, const fr_t *a, int len) {
    int i;

    assert(len > 0);
    assert(a != out);

    fr_t accumulator = FR_ONE;

    for (i = 0; i < len; i++) {
        out[i] = accumulator;
        blst_fr_mul(&accumulator, &accumulator, &a[i]);
    }

    /* Bail on any zero input */
    if (fr_is_zero(&accumulator)) {
        return C_KZG_BADARGS;
    }

    blst_fr_eucl_inverse(&accumulator, &accumulator);

    for (i = len - 1; i >= 0; i--) {
        blst_fr_mul(&out[i], &out[i], &accumulator);
        blst_fr_mul(&accumulator, &accumulator, &a[i]);
    }

    return C_KZG_OK;
}

/**
 * Multiply a G2 group element by a field element.
 *
 * @param[out] out `a * b`
 * @param[in]  a   The G2 group element
 * @param[in]  b   The multiplier
 */
static void g2_mul(g2_t *out, const g2_t *a, const fr_t *b) {
    blst_scalar s;
    blst_scalar_from_fr(&s, b);
    blst_p2_mult(out, a, s.b, BITS_PER_FIELD_ELEMENT);
}

/**
 * Subtraction of G2 group elements.
 *
 * @param[out] out `a - b`
 * @param[in]  a   A G2 group element
 * @param[in]  b   The G2 group element to be subtracted
 */
static void g2_sub(g2_t *out, const g2_t *a, const g2_t *b) {
    g2_t bneg = *b;
    blst_p2_cneg(&bneg, true);
    blst_p2_add_or_double(out, a, &bneg);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// BLS12-381 Helper Functions
////////////////////////////////////////////////////////////////////////////////////////////////////

/* Input size to the Fiat-Shamir challenge computation. */
#define CHALLENGE_INPUT_SIZE (DOMAIN_STR_LENGTH + 16 + BYTES_PER_BLOB + BYTES_PER_COMMITMENT)

/**
 * Return the Fiat-Shamir challenge required to verify `blob` and `commitment`.
 *
 * @param[out] eval_challenge_out The evaluation challenge
 * @param[in]  blob               A blob
 * @param[in]  commitment         A commitment
 *
 * @remark This function should compute challenges even if `n == 0`.
 */
static void compute_challenge(fr_t *eval_challenge_out, const Blob *blob, const g1_t *commitment) {
    Bytes32 eval_challenge;
    uint8_t bytes[CHALLENGE_INPUT_SIZE];

    /* Pointer tracking `bytes` for writing on top of it */
    uint8_t *offset = bytes;

    /* Copy domain separator */
    memcpy(offset, FIAT_SHAMIR_PROTOCOL_DOMAIN, DOMAIN_STR_LENGTH);
    offset += DOMAIN_STR_LENGTH;

    /* Copy polynomial degree (16-bytes, big-endian) */
    bytes_from_uint64(offset, 0);
    offset += sizeof(uint64_t);
    bytes_from_uint64(offset, FIELD_ELEMENTS_PER_BLOB);
    offset += sizeof(uint64_t);

    /* Copy blob */
    memcpy(offset, blob->bytes, BYTES_PER_BLOB);
    offset += BYTES_PER_BLOB;

    /* Copy commitment */
    bytes_from_g1((Bytes48 *)offset, commitment);
    offset += BYTES_PER_COMMITMENT;

    /* Make sure we wrote the entire buffer */
    assert(offset == bytes + CHALLENGE_INPUT_SIZE);

    /* Now let's create the challenge! */
    blst_sha256(eval_challenge.bytes, bytes, CHALLENGE_INPUT_SIZE);
    hash_to_bls_field(eval_challenge_out, &eval_challenge);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Polynomials Functions
////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Evaluate a polynomial in evaluation form at a given point.
 *
 * @param[out] out The result of the evaluation
 * @param[in]  p   The polynomial in evaluation form
 * @param[in]  x   The point to evaluate the polynomial at
 * @param[in]  s   The trusted setup
 */
static C_KZG_RET evaluate_polynomial_in_evaluation_form(
    fr_t *out, const Polynomial *p, const fr_t *x, const KZGSettings *s
) {
    C_KZG_RET ret;
    fr_t tmp;
    fr_t *inverses_in = NULL;
    fr_t *inverses = NULL;
    uint64_t i;
    const fr_t *roots_of_unity = s->roots_of_unity;

    ret = new_fr_array(&inverses_in, FIELD_ELEMENTS_PER_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&inverses, FIELD_ELEMENTS_PER_BLOB);
    if (ret != C_KZG_OK) goto out;

    for (i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++) {
        /*
         * If the point to evaluate at is one of the evaluation points by which the polynomial is
         * given, we can just return the result directly.  Note that special-casing this is
         * necessary, as the formula below would divide by zero otherwise.
         */
        if (fr_equal(x, &roots_of_unity[i])) {
            *out = p->evals[i];
            ret = C_KZG_OK;
            goto out;
        }
        blst_fr_sub(&inverses_in[i], x, &roots_of_unity[i]);
    }

    ret = fr_batch_inv(inverses, inverses_in, FIELD_ELEMENTS_PER_BLOB);
    if (ret != C_KZG_OK) goto out;

    *out = FR_ZERO;
    for (i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++) {
        blst_fr_mul(&tmp, &inverses[i], &roots_of_unity[i]);
        blst_fr_mul(&tmp, &tmp, &p->evals[i]);
        blst_fr_add(out, out, &tmp);
    }
    fr_from_uint64(&tmp, FIELD_ELEMENTS_PER_BLOB);
    fr_div(out, out, &tmp);
    fr_pow(&tmp, x, FIELD_ELEMENTS_PER_BLOB);
    blst_fr_sub(&tmp, &tmp, &FR_ONE);
    blst_fr_mul(out, out, &tmp);

out:
    c_kzg_free(inverses_in);
    c_kzg_free(inverses);
    return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// KZG Functions
////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Compute a KZG commitment from a polynomial.
 *
 * @param[out] out The resulting commitment
 * @param[in]  p   The polynomial to commit to
 * @param[in]  s   The trusted setup
 */
static C_KZG_RET poly_to_kzg_commitment(g1_t *out, const Polynomial *p, const KZGSettings *s) {
    return g1_lincomb_fast(
        out, s->g1_values_lagrange_brp, (const fr_t *)(&p->evals), FIELD_ELEMENTS_PER_BLOB
    );
}

/**
 * Convert a blob to a KZG commitment.
 *
 * @param[out] out  The resulting commitment
 * @param[in]  blob The blob representing the polynomial to be committed to
 * @param[in]  s    The trusted setup
 */
C_KZG_RET blob_to_kzg_commitment(KZGCommitment *out, const Blob *blob, const KZGSettings *s) {
    C_KZG_RET ret;
    Polynomial p;
    g1_t commitment;

    ret = blob_to_polynomial(&p, blob);
    if (ret != C_KZG_OK) return ret;
    ret = poly_to_kzg_commitment(&commitment, &p, s);
    if (ret != C_KZG_OK) return ret;
    bytes_from_g1(out, &commitment);
    return C_KZG_OK;
}

/* Forward function declaration */
static C_KZG_RET verify_kzg_proof_impl(
    bool *ok,
    const g1_t *commitment,
    const fr_t *z,
    const fr_t *y,
    const g1_t *proof,
    const KZGSettings *s
);

/**
 * Verify a KZG proof claiming that `p(z) == y`.
 *
 * @param[out] ok         True if the proofs are valid, otherwise false
 * @param[in]  commitment The KZG commitment corresponding to poly p(x)
 * @param[in]  z          The evaluation point
 * @param[in]  y          The claimed evaluation result
 * @param[in]  kzg_proof  The KZG proof
 * @param[in]  s          The trusted setup
 */
C_KZG_RET verify_kzg_proof(
    bool *ok,
    const Bytes48 *commitment_bytes,
    const Bytes32 *z_bytes,
    const Bytes32 *y_bytes,
    const Bytes48 *proof_bytes,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    fr_t z_fr, y_fr;
    g1_t commitment_g1, proof_g1;

    *ok = false;

    /* Convert untrusted inputs to trusted inputs */
    ret = bytes_to_kzg_commitment(&commitment_g1, commitment_bytes);
    if (ret != C_KZG_OK) return ret;
    ret = bytes_to_bls_field(&z_fr, z_bytes);
    if (ret != C_KZG_OK) return ret;
    ret = bytes_to_bls_field(&y_fr, y_bytes);
    if (ret != C_KZG_OK) return ret;
    ret = bytes_to_kzg_proof(&proof_g1, proof_bytes);
    if (ret != C_KZG_OK) return ret;

    /* Call helper to do pairings check */
    return verify_kzg_proof_impl(ok, &commitment_g1, &z_fr, &y_fr, &proof_g1, s);
}

/**
 * Helper function: Verify KZG proof claiming that `p(z) == y`.
 *
 * Given a `commitment` to a polynomial, a `proof` for `z`, and the claimed value `y` at `z`, verify
 * the claim.
 *
 * @param[out]  ok          True if the proof is valid, otherwise false
 * @param[in]   commitment  The commitment to a polynomial
 * @param[in]   z           The point at which the proof is to be opened
 * @param[in]   y           The claimed value of the polynomial at `z`
 * @param[in]   proof       A proof of the value of the polynomial at `z`
 * @param[in]   s           The trusted setup
 */
static C_KZG_RET verify_kzg_proof_impl(
    bool *ok,
    const g1_t *commitment,
    const fr_t *z,
    const fr_t *y,
    const g1_t *proof,
    const KZGSettings *s
) {
    g2_t x_g2, X_minus_z;
    g1_t y_g1, P_minus_y;

    /* Calculate: X_minus_z */
    g2_mul(&x_g2, blst_p2_generator(), z);
    g2_sub(&X_minus_z, &s->g2_values_monomial[1], &x_g2);

    /* Calculate: P_minus_y */
    g1_mul(&y_g1, blst_p1_generator(), y);
    g1_sub(&P_minus_y, commitment, &y_g1);

    /* Verify: P - y = Q * (X - z) */
    *ok = pairings_verify(&P_minus_y, blst_p2_generator(), proof, &X_minus_z);

    return C_KZG_OK;
}

/* Forward function declaration */
static C_KZG_RET compute_kzg_proof_impl(
    KZGProof *proof_out,
    fr_t *y_out,
    const Polynomial *polynomial,
    const fr_t *z,
    const KZGSettings *s
);

/**
 * Compute KZG proof for polynomial in Lagrange form at position z.
 *
 * @param[out] proof_out The combined proof as a single G1 element
 * @param[out] y_out     The evaluation of the polynomial at the evaluation point z
 * @param[in]  blob      The blob (polynomial) to generate a proof for
 * @param[in]  z         The generator z-value for the evaluation points
 * @param[in]  s         The trusted setup
 */
C_KZG_RET compute_kzg_proof(
    KZGProof *proof_out,
    Bytes32 *y_out,
    const Blob *blob,
    const Bytes32 *z_bytes,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    Polynomial polynomial;
    fr_t frz, fry;

    ret = blob_to_polynomial(&polynomial, blob);
    if (ret != C_KZG_OK) goto out;
    ret = bytes_to_bls_field(&frz, z_bytes);
    if (ret != C_KZG_OK) goto out;
    ret = compute_kzg_proof_impl(proof_out, &fry, &polynomial, &frz, s);
    if (ret != C_KZG_OK) goto out;
    bytes_from_bls_field(y_out, &fry);

out:
    return ret;
}

/**
 * Helper function for compute_kzg_proof() and compute_blob_kzg_proof().
 *
 * @param[out] proof_out  The combined proof as a single G1 element
 * @param[out] y_out      The evaluation of the polynomial at the evaluation point z
 * @param[in]  polynomial The polynomial in Lagrange form
 * @param[in]  z          The evaluation point
 * @param[in]  s          The trusted setup
 */
static C_KZG_RET compute_kzg_proof_impl(
    KZGProof *proof_out,
    fr_t *y_out,
    const Polynomial *polynomial,
    const fr_t *z,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    fr_t *inverses_in = NULL;
    fr_t *inverses = NULL;

    ret = evaluate_polynomial_in_evaluation_form(y_out, polynomial, z, s);
    if (ret != C_KZG_OK) goto out;

    fr_t tmp;
    Polynomial q;
    const fr_t *roots_of_unity = s->roots_of_unity;
    uint64_t i;
    /* m != 0 indicates that the evaluation point z equals root_of_unity[m-1] */
    uint64_t m = 0;

    ret = new_fr_array(&inverses_in, FIELD_ELEMENTS_PER_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&inverses, FIELD_ELEMENTS_PER_BLOB);
    if (ret != C_KZG_OK) goto out;

    for (i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++) {
        if (fr_equal(z, &roots_of_unity[i])) {
            /* We are asked to compute a KZG proof inside the domain */
            m = i + 1;
            inverses_in[i] = FR_ONE;
            continue;
        }
        // (p_i - y) / (ω_i - z)
        blst_fr_sub(&q.evals[i], &polynomial->evals[i], y_out);
        blst_fr_sub(&inverses_in[i], &roots_of_unity[i], z);
    }

    ret = fr_batch_inv(inverses, inverses_in, FIELD_ELEMENTS_PER_BLOB);
    if (ret != C_KZG_OK) goto out;

    for (i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++) {
        blst_fr_mul(&q.evals[i], &q.evals[i], &inverses[i]);
    }

    if (m != 0) { /* ω_{m-1} == z */
        q.evals[--m] = FR_ZERO;
        for (i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++) {
            if (i == m) continue;
            /* Build denominator: z * (z - ω_i) */
            blst_fr_sub(&tmp, z, &roots_of_unity[i]);
            blst_fr_mul(&inverses_in[i], &tmp, z);
        }

        ret = fr_batch_inv(inverses, inverses_in, FIELD_ELEMENTS_PER_BLOB);
        if (ret != C_KZG_OK) goto out;

        for (i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++) {
            if (i == m) continue;
            /* Build numerator: ω_i * (p_i - y) */
            blst_fr_sub(&tmp, &polynomial->evals[i], y_out);
            blst_fr_mul(&tmp, &tmp, &roots_of_unity[i]);
            /* Do the division: (p_i - y) * ω_i / (z * (z - ω_i)) */
            blst_fr_mul(&tmp, &tmp, &inverses[i]);
            blst_fr_add(&q.evals[m], &q.evals[m], &tmp);
        }
    }

    g1_t out_g1;
    ret = g1_lincomb_fast(
        &out_g1, s->g1_values_lagrange_brp, (const fr_t *)(&q.evals), FIELD_ELEMENTS_PER_BLOB
    );
    if (ret != C_KZG_OK) goto out;

    bytes_from_g1(proof_out, &out_g1);

out:
    c_kzg_free(inverses_in);
    c_kzg_free(inverses);
    return ret;
}

/**
 * Given a blob and a commitment, return the KZG proof that is used to verify it against the
 * commitment. This function does not verify that the commitment is correct with respect to the
 * blob.
 *
 * @param[out] out              The resulting proof
 * @param[in]  blob             A blob
 * @param[in]  commitment_bytes Commitment to verify
 * @param[in]  s                The trusted setup
 */
C_KZG_RET compute_blob_kzg_proof(
    KZGProof *out, const Blob *blob, const Bytes48 *commitment_bytes, const KZGSettings *s
) {
    C_KZG_RET ret;
    Polynomial polynomial;
    g1_t commitment_g1;
    fr_t evaluation_challenge_fr;
    fr_t y;

    /* Do conversions first to fail fast, compute_challenge is expensive */
    ret = bytes_to_kzg_commitment(&commitment_g1, commitment_bytes);
    if (ret != C_KZG_OK) goto out;
    ret = blob_to_polynomial(&polynomial, blob);
    if (ret != C_KZG_OK) goto out;

    /* Compute the challenge for the given blob/commitment */
    compute_challenge(&evaluation_challenge_fr, blob, &commitment_g1);

    /* Call helper function to compute proof and y */
    ret = compute_kzg_proof_impl(out, &y, &polynomial, &evaluation_challenge_fr, s);
    if (ret != C_KZG_OK) goto out;

out:
    return ret;
}

/**
 * Given a blob and its proof, verify that it corresponds to the provided commitment.
 *
 * @param[out] ok               True if the proofs are valid, otherwise false
 * @param[in]  blob             Blob to verify
 * @param[in]  commitment_bytes Commitment to verify
 * @param[in]  proof_bytes      Proof used for verification
 * @param[in]  s                The trusted setup
 */
C_KZG_RET verify_blob_kzg_proof(
    bool *ok,
    const Blob *blob,
    const Bytes48 *commitment_bytes,
    const Bytes48 *proof_bytes,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    Polynomial polynomial;
    fr_t evaluation_challenge_fr, y_fr;
    g1_t commitment_g1, proof_g1;

    *ok = false;

    /* Do conversions first to fail fast, compute_challenge is expensive */
    ret = bytes_to_kzg_commitment(&commitment_g1, commitment_bytes);
    if (ret != C_KZG_OK) return ret;
    ret = blob_to_polynomial(&polynomial, blob);
    if (ret != C_KZG_OK) return ret;
    ret = bytes_to_kzg_proof(&proof_g1, proof_bytes);
    if (ret != C_KZG_OK) return ret;

    /* Compute challenge for the blob/commitment */
    compute_challenge(&evaluation_challenge_fr, blob, &commitment_g1);

    /* Evaluate challenge to get y */
    ret = evaluate_polynomial_in_evaluation_form(&y_fr, &polynomial, &evaluation_challenge_fr, s);
    if (ret != C_KZG_OK) return ret;

    /* Call helper to do pairings check */
    return verify_kzg_proof_impl(ok, &commitment_g1, &evaluation_challenge_fr, &y_fr, &proof_g1, s);
}

/**
 * Compute random linear combination challenge scalars for batch verification.
 *
 * @param[out]  r_powers_out   The output challenges
 * @param[in]   commitments_g1 The input commitments
 * @param[in]   zs_fr          The input evaluation points
 * @param[in]   ys_fr          The input evaluation results
 * @param[in]   proofs_g1      The input proofs
 */
static C_KZG_RET compute_r_powers_for_verify_kzg_proof_batch(
    fr_t *r_powers_out,
    const g1_t *commitments_g1,
    const fr_t *zs_fr,
    const fr_t *ys_fr,
    const g1_t *proofs_g1,
    size_t n
) {
    C_KZG_RET ret;
    uint8_t *bytes = NULL;
    Bytes32 r_bytes;
    fr_t r;

    size_t input_size = DOMAIN_STR_LENGTH + sizeof(uint64_t) + sizeof(uint64_t) +
                        (n * (BYTES_PER_COMMITMENT + 2 * BYTES_PER_FIELD_ELEMENT + BYTES_PER_PROOF)
                        );
    ret = c_kzg_malloc((void **)&bytes, input_size);
    if (ret != C_KZG_OK) goto out;

    /* Pointer tracking `bytes` for writing on top of it */
    uint8_t *offset = bytes;

    /* Copy domain separator */
    memcpy(offset, RANDOM_CHALLENGE_DOMAIN_VERIFY_BLOB_KZG_PROOF_BATCH, DOMAIN_STR_LENGTH);
    offset += DOMAIN_STR_LENGTH;

    /* Copy degree of the polynomial */
    bytes_from_uint64(offset, FIELD_ELEMENTS_PER_BLOB);
    offset += sizeof(uint64_t);

    /* Copy number of commitments */
    bytes_from_uint64(offset, n);
    offset += sizeof(uint64_t);

    for (size_t i = 0; i < n; i++) {
        /* Copy commitment */
        bytes_from_g1((Bytes48 *)offset, &commitments_g1[i]);
        offset += BYTES_PER_COMMITMENT;

        /* Copy z */
        bytes_from_bls_field((Bytes32 *)offset, &zs_fr[i]);
        offset += BYTES_PER_FIELD_ELEMENT;

        /* Copy y */
        bytes_from_bls_field((Bytes32 *)offset, &ys_fr[i]);
        offset += BYTES_PER_FIELD_ELEMENT;

        /* Copy proof */
        bytes_from_g1((Bytes48 *)offset, &proofs_g1[i]);
        offset += BYTES_PER_PROOF;
    }

    /* Now let's create the challenge! */
    blst_sha256(r_bytes.bytes, bytes, input_size);
    hash_to_bls_field(&r, &r_bytes);

    compute_powers(r_powers_out, &r, n);

    /* Make sure we wrote the entire buffer */
    assert(offset == bytes + input_size);

out:
    c_kzg_free(bytes);
    return ret;
}

/**
 * Helper function for verify_blob_kzg_proof_batch(): actually perform the verification.
 *
 * @param[out] ok             True if the proofs are valid, otherwise false
 * @param[in]  commitments_g1 Array of commitments to verify
 * @param[in]  zs_fr          Array of evaluation points for the KZG proofs
 * @param[in]  ys_fr          Array of evaluation results for the KZG proofs
 * @param[in]  proofs_g1      Array of proofs used for verification
 * @param[in]  n              The number of blobs/commitments/proofs
 * @param[in]  s              The trusted setup
 *
 * @remark This function only works for `n > 0`.
 * @remark This function assumes that `n` is trusted and that all input arrays contain `n` elements.
 * `n` should be the actual size of the arrays and not read off a length field in the protocol.
 */
static C_KZG_RET verify_kzg_proof_batch(
    bool *ok,
    const g1_t *commitments_g1,
    const fr_t *zs_fr,
    const fr_t *ys_fr,
    const g1_t *proofs_g1,
    size_t n,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    g1_t proof_lincomb, proof_z_lincomb, C_minus_y_lincomb, rhs_g1;
    fr_t *r_powers = NULL;
    g1_t *C_minus_y = NULL;
    fr_t *r_times_z = NULL;

    assert(n > 0);

    *ok = false;

    /* First let's allocate our arrays */
    ret = new_fr_array(&r_powers, n);
    if (ret != C_KZG_OK) goto out;
    ret = new_g1_array(&C_minus_y, n);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&r_times_z, n);
    if (ret != C_KZG_OK) goto out;

    /* Compute the random lincomb challenges */
    ret = compute_r_powers_for_verify_kzg_proof_batch(
        r_powers, commitments_g1, zs_fr, ys_fr, proofs_g1, n
    );
    if (ret != C_KZG_OK) goto out;

    /* Compute \sum r^i * Proof_i */
    g1_lincomb_naive(&proof_lincomb, proofs_g1, r_powers, n);

    for (size_t i = 0; i < n; i++) {
        g1_t ys_encrypted;
        /* Get [y_i] */
        g1_mul(&ys_encrypted, blst_p1_generator(), &ys_fr[i]);
        /* Get C_i - [y_i] */
        g1_sub(&C_minus_y[i], &commitments_g1[i], &ys_encrypted);
        /* Get r^i * z_i */
        blst_fr_mul(&r_times_z[i], &r_powers[i], &zs_fr[i]);
    }

    /* Get \sum r^i z_i Proof_i */
    g1_lincomb_naive(&proof_z_lincomb, proofs_g1, r_times_z, n);
    /* Get \sum r^i (C_i - [y_i]) */
    g1_lincomb_naive(&C_minus_y_lincomb, C_minus_y, r_powers, n);
    /* Get C_minus_y_lincomb + proof_z_lincomb */
    blst_p1_add_or_double(&rhs_g1, &C_minus_y_lincomb, &proof_z_lincomb);

    /* Do the pairing check! */
    *ok = pairings_verify(&proof_lincomb, &s->g2_values_monomial[1], &rhs_g1, blst_p2_generator());

out:
    c_kzg_free(r_powers);
    c_kzg_free(C_minus_y);
    c_kzg_free(r_times_z);
    return ret;
}

/**
 * Given a list of blobs and blob KZG proofs, verify that they correspond to the provided
 * commitments.
 *
 * @param[out] ok                True if the proofs are valid, otherwise false
 * @param[in]  blobs             Array of blobs to verify
 * @param[in]  commitments_bytes Array of commitments to verify
 * @param[in]  proofs_bytes      Array of proofs used for verification
 * @param[in]  n                 The number of blobs/commitments/proofs
 * @param[in]  s                 The trusted setup
 *
 * @remark This function accepts if called with `n==0`.
 * @remark This function assumes that `n` is trusted and that all input arrays contain `n` elements.
 * `n` should be the actual size of the arrays and not read off a length field in the protocol.
 */
C_KZG_RET verify_blob_kzg_proof_batch(
    bool *ok,
    const Blob *blobs,
    const Bytes48 *commitments_bytes,
    const Bytes48 *proofs_bytes,
    size_t n,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    g1_t *commitments_g1 = NULL;
    g1_t *proofs_g1 = NULL;
    fr_t *evaluation_challenges_fr = NULL;
    fr_t *ys_fr = NULL;

    /* Exit early if we are given zero blobs */
    if (n == 0) {
        *ok = true;
        return C_KZG_OK;
    }

    /* For a single blob, just do a regular single verification */
    if (n == 1) {
        return verify_blob_kzg_proof(ok, &blobs[0], &commitments_bytes[0], &proofs_bytes[0], s);
    }

    /* We will need a bunch of arrays to store our objects... */
    ret = new_g1_array(&commitments_g1, n);
    if (ret != C_KZG_OK) goto out;
    ret = new_g1_array(&proofs_g1, n);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&evaluation_challenges_fr, n);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&ys_fr, n);
    if (ret != C_KZG_OK) goto out;

    for (size_t i = 0; i < n; i++) {
        Polynomial polynomial;

        /* Convert each commitment to a g1 point */
        ret = bytes_to_kzg_commitment(&commitments_g1[i], &commitments_bytes[i]);
        if (ret != C_KZG_OK) goto out;

        /* Convert each blob from bytes to a poly */
        ret = blob_to_polynomial(&polynomial, &blobs[i]);
        if (ret != C_KZG_OK) goto out;

        compute_challenge(&evaluation_challenges_fr[i], &blobs[i], &commitments_g1[i]);

        ret = evaluate_polynomial_in_evaluation_form(
            &ys_fr[i], &polynomial, &evaluation_challenges_fr[i], s
        );
        if (ret != C_KZG_OK) goto out;

        ret = bytes_to_kzg_proof(&proofs_g1[i], &proofs_bytes[i]);
        if (ret != C_KZG_OK) goto out;
    }

    ret = verify_kzg_proof_batch(
        ok, commitments_g1, evaluation_challenges_fr, ys_fr, proofs_g1, n, s
    );

out:
    c_kzg_free(commitments_g1);
    c_kzg_free(proofs_g1);
    c_kzg_free(evaluation_challenges_fr);
    c_kzg_free(ys_fr);
    return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Trusted Setup Functions
////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Generate powers of a root of unity in the field.
 *
 * @param[out] out   The roots of unity (length `width + 1`)
 * @param[in]  root  A root of unity
 * @param[in]  width One less than the size of `out`
 *
 * @remark `root` must be such that `root ^ width` is equal to one, but no smaller power of `root`
 * is equal to one.
 */
static C_KZG_RET expand_root_of_unity(fr_t *out, const fr_t *root, uint64_t width) {
    uint64_t i;

    /* We assume it's at least two */
    if (width < 2) {
        return C_KZG_BADARGS;
    }

    /* We know what these will be */
    out[0] = FR_ONE;
    out[1] = *root;

    /* Compute powers of root */
    for (i = 2; i <= width; i++) {
        blst_fr_mul(&out[i], &out[i - 1], root);
        if (fr_is_one(&out[i])) break;
    }

    /* We expect the last entry to be one */
    if (i != width || !fr_is_one(&out[width])) {
        return C_KZG_BADARGS;
    }

    return C_KZG_OK;
}

/**
 * Initialize the roots of unity.
 *
 * @param[out]  s   Pointer to KZGSettings
 */
static C_KZG_RET compute_roots_of_unity(KZGSettings *s) {
    C_KZG_RET ret;
    fr_t root_of_unity;

    uint32_t max_scale = 0;
    while ((1ULL << max_scale) < s->max_width)
        max_scale++;

    /* Ensure this element will exist */
    if (max_scale >= NUM_ELEMENTS(SCALE2_ROOT_OF_UNITY)) {
        return C_KZG_BADARGS;
    }

    /* Get the root of unity */
    blst_fr_from_uint64(&root_of_unity, SCALE2_ROOT_OF_UNITY[max_scale]);

    /* Populate the roots of unity */
    ret = expand_root_of_unity(s->expanded_roots_of_unity, &root_of_unity, s->max_width);
    if (ret != C_KZG_OK) goto out;

    /* Copy all but the last root to the roots of unity */
    memcpy(s->roots_of_unity, s->expanded_roots_of_unity, sizeof(fr_t) * s->max_width);

    /* Permute the roots of unity */
    ret = bit_reversal_permutation(s->roots_of_unity, sizeof(fr_t), s->max_width);
    if (ret != C_KZG_OK) goto out;

    /* Populate reverse roots of unity */
    for (uint64_t i = 0; i <= s->max_width; i++) {
        s->reverse_roots_of_unity[i] = s->expanded_roots_of_unity[s->max_width - i];
    }

out:
    return ret;
}

/**
 * Free a trusted setup (KZGSettings).
 *
 * @param[in] s The trusted setup to free
 *
 * @remark This does nothing if `s` is NULL.
 */
void free_trusted_setup(KZGSettings *s) {
    if (s == NULL) return;
    s->max_width = 0;
    c_kzg_free(s->roots_of_unity);
    c_kzg_free(s->expanded_roots_of_unity);
    c_kzg_free(s->reverse_roots_of_unity);
    c_kzg_free(s->g1_values_monomial);
    c_kzg_free(s->g1_values_lagrange_brp);
    c_kzg_free(s->g2_values_monomial);

    /*
     * If for whatever reason we accidentally call free_trusted_setup() on an uninitialized
     * structure, we don't want to deference these 2d arrays.  Without these NULL checks, it's
     * possible for there to be a segmentation fault via null pointer dereference.
     */
    if (s->x_ext_fft_columns != NULL) {
        for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
            c_kzg_free(s->x_ext_fft_columns[i]);
        }
    }
    if (s->tables != NULL) {
        for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
            c_kzg_free(s->tables[i]);
        }
    }
    c_kzg_free(s->x_ext_fft_columns);
    c_kzg_free(s->tables);
    s->wbits = 0;
    s->scratch_size = 0;
}

/**
 * The first part of the Toeplitz matrix multiplication algorithm: the Fourier transform of the
 * vector x extended.
 *
 * @param[out]  out The FFT of the extension of x, size n * 2
 * @param[in]   x   The input vector, size n
 * @param[in]   n   The length of the input vector x
 * @param[in]   s   The trusted setup
 */
static C_KZG_RET toeplitz_part_1(g1_t *out, const g1_t *x, size_t n, const KZGSettings *s) {
    C_KZG_RET ret;
    size_t n2 = n * 2;
    g1_t *x_ext;

    /* Create extended array of points */
    ret = new_g1_array(&x_ext, n2);
    if (ret != C_KZG_OK) goto out;

    /* Copy x & extend with zero */
    for (size_t i = 0; i < n; i++) {
        x_ext[i] = x[i];
    }
    for (size_t i = n; i < n2; i++) {
        x_ext[i] = G1_IDENTITY;
    }

    /* Peform forward transformation */
    ret = fft_g1(out, x_ext, n2, s);
    if (ret != C_KZG_OK) goto out;

out:
    c_kzg_free(x_ext);
    return ret;
}

/**
 * Initialize fields for FK20 multi-proof computations.
 *
 * @param[out]  s   Pointer to KZGSettings to initialize
 */
static C_KZG_RET init_fk20_multi_settings(KZGSettings *s) {
    C_KZG_RET ret;
    uint64_t n, k, k2;
    g1_t *x = NULL;
    g1_t *points = NULL;
    blst_p1_affine *p_affine = NULL;
    bool precompute = s->wbits != 0;

    n = s->max_width / 2;
    k = n / FIELD_ELEMENTS_PER_CELL;
    k2 = 2 * k;

    if (FIELD_ELEMENTS_PER_CELL >= NUM_G2_POINTS) {
        ret = C_KZG_BADARGS;
        goto out;
    }

    /* Allocate space for arrays */
    ret = new_g1_array(&x, k);
    if (ret != C_KZG_OK) goto out;
    ret = new_g1_array(&points, k2);
    if (ret != C_KZG_OK) goto out;

    /* Allocate space for array of pointers, this is a 2D array */
    ret = c_kzg_calloc((void **)&s->x_ext_fft_columns, k2, sizeof(void *));
    if (ret != C_KZG_OK) goto out;
    for (size_t i = 0; i < k2; i++) {
        ret = new_g1_array(&s->x_ext_fft_columns[i], FIELD_ELEMENTS_PER_CELL);
        if (ret != C_KZG_OK) goto out;
    }

    for (size_t offset = 0; offset < FIELD_ELEMENTS_PER_CELL; offset++) {
        /* Compute x, sections of the g1 values */
        size_t start = n - FIELD_ELEMENTS_PER_CELL - 1 - offset;
        for (size_t i = 0; i < k - 1; i++) {
            size_t j = start - i * FIELD_ELEMENTS_PER_CELL;
            x[i] = s->g1_values_monomial[j];
        }
        x[k - 1] = G1_IDENTITY;

        /* Compute points, the fft of an extended x */
        ret = toeplitz_part_1(points, x, k, s);
        if (ret != C_KZG_OK) goto out;

        /* Reorganize from rows into columns */
        for (size_t row = 0; row < k2; row++) {
            s->x_ext_fft_columns[row][offset] = points[row];
        }
    }

    if (precompute) {
        /* Allocate space for precomputed tables */
        ret = c_kzg_calloc((void **)&s->tables, k2, sizeof(void *));
        if (ret != C_KZG_OK) goto out;

        /* Allocate space for points in affine representation */
        ret = c_kzg_calloc((void **)&p_affine, FIELD_ELEMENTS_PER_CELL, sizeof(blst_p1_affine));
        if (ret != C_KZG_OK) goto out;

        /* Calculate the size of each table, this can be re-used */
        size_t table_size = blst_p1s_mult_wbits_precompute_sizeof(
            s->wbits, FIELD_ELEMENTS_PER_CELL
        );

        for (size_t i = 0; i < k2; i++) {
            /* Transform the points to affine representation */
            const blst_p1 *p_arg[2] = {s->x_ext_fft_columns[i], NULL};
            blst_p1s_to_affine(p_affine, p_arg, FIELD_ELEMENTS_PER_CELL);
            const blst_p1_affine *points_arg[2] = {p_affine, NULL};

            /* Allocate space for the table */
            ret = c_kzg_malloc((void **)&s->tables[i], table_size);
            if (ret != C_KZG_OK) goto out;

            /* Compute table for fixed-base MSM */
            blst_p1s_mult_wbits_precompute(
                s->tables[i], s->wbits, points_arg, FIELD_ELEMENTS_PER_CELL
            );
        }

        /* Calculate the size of the scratch */
        s->scratch_size = blst_p1s_mult_wbits_scratch_sizeof(FIELD_ELEMENTS_PER_CELL);
    }

out:
    c_kzg_free(x);
    c_kzg_free(points);
    c_kzg_free(p_affine);
    return ret;
}

/**
 * Basic sanity check that the trusted setup was loaded in Lagrange form.
 *
 * @param[in] s  Pointer to the stored trusted setup data
 * @param[in] n1 Number of `g1` points in trusted_setup
 * @param[in] n2 Number of `g2` points in trusted_setup
 */
static C_KZG_RET is_trusted_setup_in_lagrange_form(const KZGSettings *s, size_t n1, size_t n2) {
    /* Trusted setup is too small; we can't work with this */
    if (n1 < 2 || n2 < 2) {
        return C_KZG_BADARGS;
    }

    /*
     * If the following pairing equation checks out:
     *     e(G1_SETUP[1], G2_SETUP[0]) ?= e(G1_SETUP[0], G2_SETUP[1])
     * then the trusted setup was loaded in monomial form.
     * If so, error out since we want the trusted setup in Lagrange form.
     */
    bool is_monomial_form = pairings_verify(
        &s->g1_values_lagrange_brp[1],
        &s->g2_values_monomial[0],
        &s->g1_values_lagrange_brp[0],
        &s->g2_values_monomial[1]
    );
    return is_monomial_form ? C_KZG_BADARGS : C_KZG_OK;
}

/**
 * Load trusted setup into a KZGSettings.
 *
 * @param[out]  out                     Pointer to the stored trusted setup
 * @param[in]   g1_monomial_bytes       Array of G1 points in monomial form
 * @param[in]   num_g1_monomial_bytes   Number of g1 monomial bytes
 * @param[in]   g1_lagrange_bytes       Array of G1 points in Lagrange form
 * @param[in]   num_g1_lagrange_bytes   Number of g1 Lagrange bytes
 * @param[in]   g2_monomial_bytes       Array of G2 points in monomial form
 * @param[in]   num_g2_monomial_bytes   Number of g2 monomial bytes
 * @param[in]   precompute              Configurable value between 0-15
 *
 * @remark Free afterwards use with free_trusted_setup().
 */
C_KZG_RET load_trusted_setup(
    KZGSettings *out,
    const uint8_t *g1_monomial_bytes,
    size_t num_g1_monomial_bytes,
    const uint8_t *g1_lagrange_bytes,
    size_t num_g1_lagrange_bytes,
    const uint8_t *g2_monomial_bytes,
    size_t num_g2_monomial_bytes,
    size_t precompute
) {
    C_KZG_RET ret;

    out->max_width = 0;
    out->roots_of_unity = NULL;
    out->expanded_roots_of_unity = NULL;
    out->reverse_roots_of_unity = NULL;
    out->g1_values_monomial = NULL;
    out->g1_values_lagrange_brp = NULL;
    out->g2_values_monomial = NULL;
    out->x_ext_fft_columns = NULL;
    out->tables = NULL;

    /* It seems that blst limits the input to 15 */
    if (precompute > 15) {
        ret = C_KZG_BADARGS;
        goto out_error;
    }

    /*
     * This is the window size for the windowed multiplication in proof generation. The larger wbits
     * is, the faster the MSM will be, but the size of the precomputed table will grow
     * exponentially. With 8 bits, the tables are 96 MiB; with 9 bits, the tables are 192 MiB and so
     * forth. From our testing, there are diminishing returns after 8 bits.
     */
    out->wbits = precompute;

    /* Sanity check in case this is called directly */
    if (num_g1_monomial_bytes != NUM_G1_POINTS * BYTES_PER_G1 ||
        num_g1_lagrange_bytes != NUM_G1_POINTS * BYTES_PER_G1 ||
        num_g2_monomial_bytes != NUM_G2_POINTS * BYTES_PER_G2) {
        ret = C_KZG_BADARGS;
        goto out_error;
    }

    /* 1<<max_scale is the smallest power of 2 >= n1 */
    uint32_t max_scale = 0;
    while ((1ULL << max_scale) < NUM_G1_POINTS)
        max_scale++;

    /* Set the max_width */
    out->max_width = 1ULL << max_scale;

    /* For DAS reconstruction */
    out->max_width *= 2;

    /* Allocate all of our arrays */
    ret = new_fr_array(&out->roots_of_unity, out->max_width);
    if (ret != C_KZG_OK) goto out_error;
    ret = new_fr_array(&out->expanded_roots_of_unity, out->max_width + 1);
    if (ret != C_KZG_OK) goto out_error;
    ret = new_fr_array(&out->reverse_roots_of_unity, out->max_width + 1);
    if (ret != C_KZG_OK) goto out_error;
    ret = new_g1_array(&out->g1_values_monomial, NUM_G1_POINTS);
    if (ret != C_KZG_OK) goto out_error;
    ret = new_g1_array(&out->g1_values_lagrange_brp, NUM_G1_POINTS);
    if (ret != C_KZG_OK) goto out_error;
    ret = new_g2_array(&out->g2_values_monomial, NUM_G2_POINTS);
    if (ret != C_KZG_OK) goto out_error;

    /* Convert all g1 monomial bytes to g1 points */
    for (uint64_t i = 0; i < NUM_G1_POINTS; i++) {
        blst_p1_affine g1_affine;
        BLST_ERROR err = blst_p1_uncompress(&g1_affine, &g1_monomial_bytes[BYTES_PER_G1 * i]);
        if (err != BLST_SUCCESS) {
            ret = C_KZG_BADARGS;
            goto out_error;
        }
        blst_p1_from_affine(&out->g1_values_monomial[i], &g1_affine);
    }

    /* Convert all g1 Lagrange bytes to g1 points */
    for (uint64_t i = 0; i < NUM_G1_POINTS; i++) {
        blst_p1_affine g1_affine;
        BLST_ERROR err = blst_p1_uncompress(&g1_affine, &g1_lagrange_bytes[BYTES_PER_G1 * i]);
        if (err != BLST_SUCCESS) {
            ret = C_KZG_BADARGS;
            goto out_error;
        }
        blst_p1_from_affine(&out->g1_values_lagrange_brp[i], &g1_affine);
    }

    /* Convert all g2 bytes to g2 points */
    for (uint64_t i = 0; i < NUM_G2_POINTS; i++) {
        blst_p2_affine g2_affine;
        BLST_ERROR err = blst_p2_uncompress(&g2_affine, &g2_monomial_bytes[BYTES_PER_G2 * i]);
        if (err != BLST_SUCCESS) {
            ret = C_KZG_BADARGS;
            goto out_error;
        }
        blst_p2_from_affine(&out->g2_values_monomial[i], &g2_affine);
    }

    /* Make sure the trusted setup was loaded in Lagrange form */
    ret = is_trusted_setup_in_lagrange_form(out, NUM_G1_POINTS, NUM_G2_POINTS);
    if (ret != C_KZG_OK) goto out_error;

    /* Compute roots of unity and permute the G1 trusted setup */
    ret = compute_roots_of_unity(out);
    if (ret != C_KZG_OK) goto out_error;

    /* Bit reverse the Lagrange form points */
    ret = bit_reversal_permutation(out->g1_values_lagrange_brp, sizeof(g1_t), NUM_G1_POINTS);
    if (ret != C_KZG_OK) goto out_error;

    /* Setup for FK20 proof computation */
    ret = init_fk20_multi_settings(out);
    if (ret != C_KZG_OK) goto out_error;

    goto out_success;

out_error:
    /*
     * Note: this only frees the fields in the KZGSettings structure. It does not free the
     * KZGSettings structure memory. If necessary, that must be done by the caller.
     */
    free_trusted_setup(out);
out_success:
    return ret;
}

/**
 * Load trusted setup from a file.
 *
 * @param[out]  out         Pointer to the loaded trusted setup data
 * @param[in]   in          File handle for input
 * @param[in]   precompute  Configurable value between 0-15
 *
 * @remark See also load_trusted_setup().
 * @remark The input file will not be closed.
 * @remark The file format is `n1 n2 g1_1 g1_2 ... g1_n1 g2_1 ... g2_n2` where the first two numbers
 * are in decimal and the remainder are hexstrings and any whitespace can be used as separators.
 */
C_KZG_RET load_trusted_setup_file(KZGSettings *out, FILE *in, size_t precompute) {
    C_KZG_RET ret;
    int num_matches;
    uint64_t i;
    uint8_t *g1_monomial_bytes = NULL;
    uint8_t *g1_lagrange_bytes = NULL;
    uint8_t *g2_monomial_bytes = NULL;

    /* Allocate space for points */
    ret = c_kzg_calloc((void **)&g1_monomial_bytes, NUM_G1_POINTS, BYTES_PER_G1);
    if (ret != C_KZG_OK) goto out;
    ret = c_kzg_calloc((void **)&g1_lagrange_bytes, NUM_G1_POINTS, BYTES_PER_G1);
    if (ret != C_KZG_OK) goto out;
    ret = c_kzg_calloc((void **)&g2_monomial_bytes, NUM_G2_POINTS, BYTES_PER_G2);
    if (ret != C_KZG_OK) goto out;

    /* Read the number of g1 points */
    num_matches = fscanf(in, "%" SCNu64, &i);
    if (num_matches != 1 || i != NUM_G1_POINTS) {
        ret = C_KZG_BADARGS;
        goto out;
    }

    /* Read the number of g2 points */
    num_matches = fscanf(in, "%" SCNu64, &i);
    if (num_matches != 1 || i != NUM_G2_POINTS) {
        ret = C_KZG_BADARGS;
        goto out;
    }

    /* Read all of the g1 points in Lagrange form, byte by byte */
    for (i = 0; i < NUM_G1_POINTS * BYTES_PER_G1; i++) {
        num_matches = fscanf(in, "%2hhx", &g1_lagrange_bytes[i]);
        if (num_matches != 1) {
            ret = C_KZG_BADARGS;
            goto out;
        }
    }

    /* Read all of the g2 points in monomial form, byte by byte */
    for (i = 0; i < NUM_G2_POINTS * BYTES_PER_G2; i++) {
        num_matches = fscanf(in, "%2hhx", &g2_monomial_bytes[i]);
        if (num_matches != 1) {
            ret = C_KZG_BADARGS;
            goto out;
        }
    }

    /* Read all of the g1 points in monomial form, byte by byte */
    /* Note: this is last because it is an extension for EIP-7594 */
    for (i = 0; i < NUM_G1_POINTS * BYTES_PER_G1; i++) {
        num_matches = fscanf(in, "%2hhx", &g1_monomial_bytes[i]);
        if (num_matches != 1) {
            ret = C_KZG_BADARGS;
            goto out;
        }
    }

    ret = load_trusted_setup(
        out,
        g1_monomial_bytes,
        NUM_G1_POINTS * BYTES_PER_G1,
        g1_lagrange_bytes,
        NUM_G1_POINTS * BYTES_PER_G1,
        g2_monomial_bytes,
        NUM_G2_POINTS * BYTES_PER_G2,
        precompute
    );

out:
    c_kzg_free(g1_monomial_bytes);
    c_kzg_free(g1_lagrange_bytes);
    c_kzg_free(g2_monomial_bytes);
    return ret;
}
