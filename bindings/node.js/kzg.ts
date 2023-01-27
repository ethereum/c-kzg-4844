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
  FIELD_ELEMENTS_PER_BLOB: number;
  BYTES_PER_FIELD_ELEMENT: number;

  loadTrustedSetup: (filePath: string) => SetupHandle;

  freeTrustedSetup: (setupHandle: SetupHandle) => void;

  blobToKzgCommitment: (blob: Blob, setupHandle: SetupHandle) => KZGCommitment;

  computeKzgProof: (
    blob: Blob,
    zBytes: Bytes32,
    setupHandle: SetupHandle,
  ) => KZGProof;

  computeAggregateKzgProof: (
    blobs: Blob[],
    setupHandle: SetupHandle,
  ) => KZGProof;

  verifyAggregateKzgProof: (
    blobs: Blob[],
    commitmentsBytes: Bytes48[],
    aggregatedProofBytes: Bytes48,
    setupHandle: SetupHandle,
  ) => boolean;

  verifyKzgProof: (
    commitmentBytes: Bytes48,
    zBytes: Bytes32,
    yBytes: Bytes32,
    proofBytes: Bytes48,
    setupHandle: SetupHandle,
  ) => boolean;
};

type TrustedSetupJSON = {
  setup_G1: string[];
  setup_G2: string[];
  setup_G1_lagrange: string[];
  roots_of_unity: string[];
};

export const FIELD_ELEMENTS_PER_BLOB = kzg.FIELD_ELEMENTS_PER_BLOB;
export const BYTES_PER_FIELD_ELEMENT = kzg.BYTES_PER_FIELD_ELEMENT;

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

export function blobToKzgCommitment(blob: Blob): KZGCommitment {
  return kzg.blobToKzgCommitment(blob, requireSetupHandle());
}

export function computeKzgProof(blob: Blob, zBytes: Bytes32): KZGProof {
  return kzg.computeKzgProof(blob, zBytes, requireSetupHandle());
}

export function computeAggregateKzgProof(blobs: Blob[]): KZGProof {
  return kzg.computeAggregateKzgProof(blobs, requireSetupHandle());
}

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

export function verifyAggregateKzgProof(
  blobs: Blob[],
  commitmentsBytes: Bytes48[],
  proofBytes: Bytes48,
): boolean {
  return kzg.verifyAggregateKzgProof(
    blobs,
    commitmentsBytes,
    proofBytes,
    requireSetupHandle(),
  );
}
