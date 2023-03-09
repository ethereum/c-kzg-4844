/**
 * The public interface of this module exposes the functions as specified by
 * https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/polynomial-commitments.md#kzg
 */
const kzg: KZG = require("bindings")("kzg");
const fs = require("fs");

export type Bytes32 = Uint8Array; // 32 bytes
export type Bytes48 = Uint8Array; // 48 bytes
export type KZGProof = Buffer; // 48 bytes
export type KZGCommitment = Buffer; // 48 bytes
export type Blob = Uint8Array; // 4096 * 32 bytes

type SetupHandle = Object;

// The C++ native addon interface
type KZG = {
  BYTES_PER_BLOB: number;
  BYTES_PER_COMMITMENT: number;
  BYTES_PER_FIELD_ELEMENT: number;
  BYTES_PER_PROOF: number;
  FIELD_ELEMENTS_PER_BLOB: number;

  loadTrustedSetup: (filePath: string) => SetupHandle;

  freeTrustedSetup: (setupHandle: SetupHandle) => void;

  blobToKzgCommitment: (blob: Blob, setupHandle: SetupHandle) => KZGCommitment;

  computeKzgProof: (
    blob: Blob,
    zBytes: Bytes32,
    setupHandle: SetupHandle,
  ) => KZGProof;

  computeBlobKzgProof: (blob: Blob, setupHandle: SetupHandle) => KZGProof;

  verifyKzgProof: (
    commitmentBytes: Bytes48,
    zBytes: Bytes32,
    yBytes: Bytes32,
    proofBytes: Bytes48,
    setupHandle: SetupHandle,
  ) => boolean;

  verifyBlobKzgProof: (
    blob: Blob,
    commitmentBytes: Bytes48,
    proofBytes: Bytes48,
    setupHandle: SetupHandle,
  ) => boolean;

  verifyBlobKzgProofBatch: (
    blobs: Blob[],
    commitmentsBytes: Bytes48[],
    proofsBytes: Bytes48[],
    setupHandle: SetupHandle,
  ) => boolean;
};

type TrustedSetupJSON = {
  setup_G1: string[];
  setup_G2: string[];
  setup_G1_lagrange: string[];
  roots_of_unity: string[];
};

export const BYTES_PER_BLOB = kzg.BYTES_PER_BLOB;
export const BYTES_PER_COMMITMENT = kzg.BYTES_PER_COMMITMENT;
export const BYTES_PER_FIELD_ELEMENT = kzg.BYTES_PER_FIELD_ELEMENT;
export const BYTES_PER_PROOF = kzg.BYTES_PER_PROOF;
export const FIELD_ELEMENTS_PER_BLOB = kzg.FIELD_ELEMENTS_PER_BLOB;

// Stored as internal state
let setupHandle: SetupHandle | undefined;

function requireSetupHandle(): SetupHandle {
  if (!setupHandle) {
    throw new Error("You must call loadTrustedSetup to initialize KZG.");
  }
  return setupHandle;
}

export async function transformTrustedSetupJSON(
  filePath: string,
): Promise<string> {
  const data: TrustedSetupJSON = JSON.parse(fs.readFileSync(filePath));

  const textFilePath = filePath.replace(".json", "") + ".txt";

  try {
    fs.unlinkSync(textFilePath);
  } catch {}

  const file = fs.createWriteStream(textFilePath);
  file.write(`${FIELD_ELEMENTS_PER_BLOB}\n65\n`);
  file.write(data.setup_G1.map((p) => p.replace("0x", "")).join("\n"));
  file.write("\n");
  file.write(data.setup_G2.map((p) => p.replace("0x", "")).join("\n"));
  file.end();

  const p = new Promise((resolve) => {
    file.close(resolve);
  });

  await p;
  return textFilePath;
}

export function loadTrustedSetup(filePath: string): void {
  if (setupHandle) {
    throw new Error(
      "Call freeTrustedSetup before loading a new trusted setup.",
    );
  }

  setupHandle = kzg.loadTrustedSetup(filePath);
}

export function freeTrustedSetup(): void {
  kzg.freeTrustedSetup(requireSetupHandle());
  setupHandle = undefined;
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
  return kzg.blobToKzgCommitment(blob, requireSetupHandle());
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
  return kzg.computeKzgProof(blob, zBytes, requireSetupHandle());
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
  return kzg.computeBlobKzgProof(blob, requireSetupHandle());
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
  return kzg.verifyKzgProof(
    commitmentBytes,
    zBytes,
    yBytes,
    proofBytes,
    requireSetupHandle(),
  );
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
  return kzg.verifyBlobKzgProof(
    blob,
    commitmentBytes,
    proofBytes,
    requireSetupHandle(),
  );
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
  return kzg.verifyBlobKzgProofBatch(
    blobs,
    commitmentsBytes,
    proofsBytes,
    requireSetupHandle(),
  );
}
