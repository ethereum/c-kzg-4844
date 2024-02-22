/**
 * The public interface of this module exposes the functions as specified by
 * https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/polynomial-commitments.md#kzg
 */
export type Bytes32 = Uint8Array; // 32 bytes
export type Bytes48 = Uint8Array; // 48 bytes
export type KZGProof = Uint8Array; // 48 bytes
export type KZGCommitment = Uint8Array; // 48 bytes
export type Blob = Uint8Array; // 4096 * 32 bytes
export type ProofResult = [KZGProof, Bytes32];
export interface TrustedSetupJson {
  setup_G1: string[];
  setup_G2: string[];
  setup_G1_lagrange: string[];
  roots_of_unity: string[];
}

export const BYTES_PER_BLOB: number;
export const BYTES_PER_COMMITMENT: number;
export const BYTES_PER_FIELD_ELEMENT: number;
export const BYTES_PER_PROOF: number;
export const FIELD_ELEMENTS_PER_BLOB: number;

/**
 * Factory function that passes trusted setup to the bindings
 *
 * @param {string} filePath
 *
 * @throws {TypeError} - Non-String input
 * @throws {Error} - For all other errors. See error message for more info
 */
export function loadTrustedSetup(filePath: string): void;

/**
 * Convert a blob to a KZG commitment.
 *
 * @param {Blob} blob - The blob representing the polynomial to be committed to
 *
 * @return {KZGCommitment} - The resulting commitment
 *
 * @throws {TypeError} - For invalid arguments or failure of the native library
 */
export function blobToKzgCommitment(blob: Blob): KZGCommitment;

/**
 * Compute KZG proof for polynomial in Lagrange form at position z.
 *
 * @param {Blob}    blob - The blob (polynomial) to generate a proof for
 * @param {Bytes32} zBytes - The generator z-value for the evaluation points
 *
 * @return {ProofResult} - Tuple containing the resulting proof and evaluation
 *                         of the polynomial at the evaluation point z
 *
 * @throws {TypeError} - For invalid arguments or failure of the native library
 */
export function computeKzgProof(blob: Blob, zBytes: Bytes32): ProofResult;

/**
 * Given a blob, return the KZG proof that is used to verify it against the
 * commitment.
 *
 * @param {Blob}    blob - The blob (polynomial) to generate a proof for
 * @param {Bytes48} commitmentBytes - Commitment to verify
 *
 * @return {KZGProof} - The resulting proof
 *
 * @throws {TypeError} - For invalid arguments or failure of the native library
 */
export function computeBlobKzgProof(blob: Blob, commitmentBytes: Bytes48): KZGProof;

/**
 * Verify a KZG poof claiming that `p(z) == y`.
 *
 * @param {Bytes48} commitmentBytes - The serialized commitment corresponding to polynomial p(x)
 * @param {Bytes32} zBytes - The serialized evaluation point
 * @param {Bytes32} yBytes - The serialized claimed evaluation result
 * @param {Bytes48} proofBytes - The serialized KZG proof
 *
 * @return {boolean} - true/false depending on proof validity
 *
 * @throws {TypeError} - For invalid arguments or failure of the native library
 */
export function verifyKzgProof(
  commitmentBytes: Bytes48,
  zBytes: Bytes32,
  yBytes: Bytes32,
  proofBytes: Bytes48
): boolean;

/**
 * Given a blob and its proof, verify that it corresponds to the provided
 * commitment.
 *
 * @param {Blob}    blob - The serialized blob to verify
 * @param {Bytes48} commitmentBytes - The serialized commitment to verify
 * @param {Bytes48} proofBytes - The serialized KZG proof for verification
 *
 * @return {boolean} - true/false depending on proof validity
 *
 * @throws {TypeError} - For invalid arguments or failure of the native library
 */
export function verifyBlobKzgProof(blob: Blob, commitmentBytes: Bytes48, proofBytes: Bytes48): boolean;

/**
 * Given an array of blobs and their proofs, verify that they correspond to their
 * provided commitment.
 *
 * Note: blobs[0] relates to commitmentBytes[0] and proofBytes[0]
 *
 * @param {Blob}    blobs - An array of serialized blobs to verify
 * @param {Bytes48} commitmentsBytes - An array of serialized commitments to verify
 * @param {Bytes48} proofsBytes - An array of serialized KZG proofs for verification
 *
 * @return {boolean} - true/false depending on batch validity
 *
 * @throws {TypeError} - For invalid arguments or failure of the native library
 */
export function verifyBlobKzgProofBatch(blobs: Blob[], commitmentsBytes: Bytes48[], proofsBytes: Bytes48[]): boolean;
