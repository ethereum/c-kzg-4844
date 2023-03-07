/**
 * The public interface of this module exposes the functions as specified by
 * https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/polynomial-commitments.md#kzg
 */
const kzg: KZG = require("./kzg.node");
import * as fs from "fs";
import * as path from "path";

export type Bytes32 = Uint8Array; // 32 bytes
export type Bytes48 = Uint8Array; // 48 bytes
export type KZGProof = Buffer; // 48 bytes
export type KZGCommitment = Buffer; // 48 bytes
export type Blob = Uint8Array; // 4096 * 32 bytes
export interface TrustedSetupJson {
  setup_G1: string[];
  setup_G2: string[];
  setup_G1_lagrange: string[];
  roots_of_unity: string[];
}
// The C++ native addon interface
interface KZG {
  BYTES_PER_BLOB: number;
  BYTES_PER_COMMITMENT: number;
  BYTES_PER_FIELD_ELEMENT: number;
  BYTES_PER_PROOF: number;
  FIELD_ELEMENTS_PER_BLOB: number;

  loadTrustedSetup: (filePath: string) => void;

  blobToKzgCommitment: (blob: Blob) => KZGCommitment;

  computeKzgProof: (blob: Blob, zBytes: Bytes32) => KZGProof;

  computeBlobKzgProof: (blob: Blob) => KZGProof;

  verifyKzgProof: (
    commitmentBytes: Bytes48,
    zBytes: Bytes32,
    yBytes: Bytes32,
    proofBytes: Bytes48,
  ) => boolean;

  verifyBlobKzgProof: (
    blob: Blob,
    commitmentBytes: Bytes48,
    proofBytes: Bytes48,
  ) => boolean;

  verifyBlobKzgProofBatch: (
    blobs: Blob[],
    commitmentsBytes: Bytes48[],
    proofsBytes: Bytes48[],
  ) => boolean;
}

export const BYTES_PER_BLOB = kzg.BYTES_PER_BLOB;
export const BYTES_PER_COMMITMENT = kzg.BYTES_PER_COMMITMENT;
export const BYTES_PER_FIELD_ELEMENT = kzg.BYTES_PER_FIELD_ELEMENT;
export const BYTES_PER_PROOF = kzg.BYTES_PER_PROOF;
export const FIELD_ELEMENTS_PER_BLOB = kzg.FIELD_ELEMENTS_PER_BLOB;

/**
 * Converts JSON formatted trusted setup into the native format that
 * the native library requires.  Returns the absolute file path to the
 * the formatted file.  The path will be the same as the origin
 * file but with a ".txt" extension.
 *
 * @param {string} filePath - The absolute path of JSON formatted trusted setup
 *
 * @return {string} - The absolute path of the re-formatted trusted setup
 *
 * @throws {Error} - For invalid file operations
 */
function transformTrustedSetupJson(filePath: string): string {
  const data: TrustedSetupJson = JSON.parse(fs.readFileSync(filePath, "utf8"));
  const textFilePath = filePath.replace(".json", ".txt");
  const setupText =
    kzg.FIELD_ELEMENTS_PER_BLOB +
    "\n65\n" +
    data.setup_G1.map((p) => p.substring(2)).join("\n") +
    "\n" +
    data.setup_G2.map((p) => p.substring(2)).join("\n");
  fs.writeFileSync(textFilePath, setupText);
  return textFilePath;
}

/**
 * Sets up the c-kzg library. Pass in a properly formatted trusted setup file
 * to configure the library.  File must be in json format, see or {@link TrustedSetupJson}
 * interface for more details, or as a properly formatted utf-8 encoded file.
 *
 * @remark This function must be run before any other functions in this
 *         library can be run.
 *
 * @param {string} filePath - The absolute path of the trusted setup
 *
 * @return {void}
 *
 * @throws {Error} - For invalid file operations
 */
export function loadTrustedSetup(filePath: string): void {
  if (!(filePath && typeof filePath === "string")) {
    throw new TypeError(
      "must initialize kzg with the filePath to a txt/json trusted setup",
    );
  }
  if (!fs.existsSync(filePath)) {
    throw new Error(`no trusted setup found: ${filePath}`);
  }
  if (path.parse(filePath).ext === ".json") {
    filePath = transformTrustedSetupJson(filePath);
  }
  return kzg.loadTrustedSetup(filePath);
}

/**
 * Convert a blob to a KZG commitment.
 *
 * @param {Blob} blob - The blob representing the polynomial to be committed to
 *
 * @return {KZGCommitment} - The resulting commitment
 *
 * @throws {TypeError} - For invalid arguments or failure of the native library
 */
export function blobToKzgCommitment(blob: Blob): KZGCommitment {
  return kzg.blobToKzgCommitment(blob);
}

/**
 * Compute KZG proof for polynomial in Lagrange form at position z.
 *
 * @param {Blob}    blob - The blob (polynomial) to generate a proof for
 * @param {Bytes32} zBytes - The generator z-value for the evaluation points
 *
 * @return {KZGProof} - The resulting proof
 *
 * @throws {TypeError} - For invalid arguments or failure of the native library
 */
export function computeKzgProof(blob: Blob, zBytes: Bytes32): KZGProof {
  return kzg.computeKzgProof(blob, zBytes);
}

/**
 * Given a blob, return the KZG proof that is used to verify it against the
 * commitment.
 *
 * @param {Blob} blob - The blob (polynomial) to generate a proof for
 *
 * @return {KZGProof} - The resulting proof
 *
 * @throws {TypeError} - For invalid arguments or failure of the native library
 */
export function computeBlobKzgProof(blob: Blob): KZGProof {
  return kzg.computeBlobKzgProof(blob);
}

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
  proofBytes: Bytes48,
): boolean {
  return kzg.verifyKzgProof(commitmentBytes, zBytes, yBytes, proofBytes);
}

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
export function verifyBlobKzgProof(
  blob: Blob,
  commitmentBytes: Bytes48,
  proofBytes: Bytes48,
): boolean {
  return kzg.verifyBlobKzgProof(blob, commitmentBytes, proofBytes);
}

/**
 * Given an array of blobs and their proofs, verify that they corresponds to their
 * provided commitment.
 *
 * Note: blobs[0] relates to commitmentBytes[0] and proofBytes[0]
 *
 * @param {Blob}    blobs - An array of serialized blobs to verify
 * @param {Bytes48} commitmentBytes - An array of serialized commitments to verify
 * @param {Bytes48} proofBytes - An array of serialized KZG proofs for verification
 *
 * @return {boolean} - true/false depending on batch validity
 *
 * @throws {TypeError} - For invalid arguments or failure of the native library
 */
export function verifyBlobKzgProofBatch(
  blobs: Blob[],
  commitmentsBytes: Bytes48[],
  proofsBytes: Bytes48[],
): boolean {
  return kzg.verifyBlobKzgProofBatch(blobs, commitmentsBytes, proofsBytes);
}
