/**
 * The public interface of this module exposes the functions as specified by
 * https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/polynomial-commitments.md#kzg
 */
const kzg: KZG = require("./kzg.node");
const fs = require("fs");

export type Bytes32 = Uint8Array; // 32 bytes
export type Bytes48 = Uint8Array; // 48 bytes
export type KZGProof = Uint8Array; // 48 bytes
export type KZGCommitment = Uint8Array; // 48 bytes
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

function checkBlob(blob: Blob) {
  if (blob.length != BYTES_PER_BLOB) {
    throw new Error(
      `Expected blob to be UInt8Array of ${BYTES_PER_BLOB} bytes.`,
    );
  }
}

function checkBlobs(blobs: Blob[]) {
  for (let blob of blobs) {
    checkBlob(blob);
  }
}

function checkCommitment(commitment: KZGCommitment) {
  if (commitment.length != BYTES_PER_COMMITMENT) {
    throw new Error(
      `Expected commitment to be UInt8Array of ${BYTES_PER_COMMITMENT} bytes.`,
    );
  }
}

function checkCommitments(commitments: KZGCommitment[]) {
  for (let commitment of commitments) {
    checkCommitment(commitment);
  }
}

function checkProof(proof: KZGProof) {
  if (proof.length != BYTES_PER_PROOF) {
    throw new Error(
      `Expected proof to be UInt8Array of ${BYTES_PER_PROOF} bytes.`,
    );
  }
}

function checkProofs(proofs: KZGProof[]) {
  for (let proof of proofs) {
    checkProof(proof);
  }
}

function checkFieldElement(field: Bytes32) {
  if (field.length != BYTES_PER_FIELD_ELEMENT) {
    throw new Error(
      `Expected field element to be UInt8Array of ${BYTES_PER_FIELD_ELEMENT} bytes.`,
    );
  }
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

export function blobToKzgCommitment(blob: Blob): KZGCommitment {
  checkBlob(blob);
  return kzg.blobToKzgCommitment(blob, requireSetupHandle());
}

export function computeKzgProof(blob: Blob, zBytes: Bytes32): KZGProof {
  checkBlob(blob);
  checkFieldElement(zBytes);
  return kzg.computeKzgProof(blob, zBytes, requireSetupHandle());
}

export function computeBlobKzgProof(blob: Blob): KZGProof {
  checkBlob(blob);
  return kzg.computeBlobKzgProof(blob, requireSetupHandle());
}

export function verifyKzgProof(
  commitmentBytes: Bytes48,
  zBytes: Bytes32,
  yBytes: Bytes32,
  proofBytes: Bytes48,
): boolean {
  checkCommitment(commitmentBytes);
  checkFieldElement(zBytes);
  checkFieldElement(yBytes);
  checkProof(proofBytes);
  return kzg.verifyKzgProof(
    commitmentBytes,
    zBytes,
    yBytes,
    proofBytes,
    requireSetupHandle(),
  );
}

export function verifyBlobKzgProof(
  blob: Blob,
  commitmentBytes: Bytes48,
  proofBytes: Bytes48,
): boolean {
  checkBlob(blob);
  checkCommitment(commitmentBytes);
  checkProof(proofBytes);
  return kzg.verifyBlobKzgProof(
    blob,
    commitmentBytes,
    proofBytes,
    requireSetupHandle(),
  );
}

export function verifyBlobKzgProofBatch(
  blobs: Blob[],
  commitmentsBytes: Bytes48[],
  proofsBytes: Bytes48[],
): boolean {
  checkBlobs(blobs);
  checkCommitments(commitmentsBytes);
  checkProofs(proofsBytes);
  return kzg.verifyBlobKzgProofBatch(
    blobs,
    commitmentsBytes,
    proofsBytes,
    requireSetupHandle(),
  );
}
