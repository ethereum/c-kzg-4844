// @ts-expect-error
import bindings from "bindings";

export const BLOB_SIZE = 4096;
export const NUMBER_OF_FIELDS = 32;

export type SetupHandle = Object;

export type BLSFieldElement = Uint8Array;
export type KZGProof = Uint8Array;
export type KZGCommitment = Uint8Array;
export type Blob = Uint8Array;

type KZG = {
  loadTrustedSetup: (filePath: string) => SetupHandle;

  freeTrustedSetup: (setupHandle: SetupHandle) => void;

  blobToKzgCommitment: (blob: Blob, setupHandle: SetupHandle) => KZGCommitment;

  computeAggregateKzgProof: (
    blobs: Blob[],
    setupHandle: SetupHandle
  ) => KZGProof;

  verifyAggregateKzgProof: (
    blobs: Blob[],
    expectedKzgCommitments: KZGCommitment[],
    kzgAggregatedProof: KZGProof,
    setupHandle: SetupHandle
  ) => boolean;

  verifyKzgProof: (
    polynomialKzg: KZGCommitment,
    z: BLSFieldElement,
    y: BLSFieldElement,
    kzgProof: KZGProof,
    setupHandle: SetupHandle
  ) => boolean;
};

const kzg: KZG = bindings("kzg.node");

// Stored as internal state
let setupHandle: SetupHandle | undefined;

export function loadTrustedSetup(filePath: string) {
  if (setupHandle) {
    throw new Error(
      "Call freeTrustedSetup before loading a new trusted setup."
    );
  }
  setupHandle = kzg.loadTrustedSetup(filePath);
}

export function freeTrustedSetup() {
  if (!setupHandle) {
    throw new Error("You must call loadTrustedSetup before freeTrustedSetup.");
  }
  kzg.freeTrustedSetup(setupHandle);
  setupHandle = undefined;
}

export function blobToKzgCommitment(blob: Blob) {
  if (!setupHandle) {
    throw new Error("You must call loadTrustedSetup to initialize KZG.");
  }
  return kzg.blobToKzgCommitment(blob, setupHandle);
}

export function computeAggregateKzgProof(blobs: Blob[]) {
  if (!setupHandle) {
    throw new Error("You must call loadTrustedSetup to initialize KZG.");
  }
  return kzg.computeAggregateKzgProof(blobs, setupHandle);
}

/**
 * Verify KZG proof that ``p(z) == y`` where ``p(z)`` is the polynomial represented by ``polynomialKzg``.
 */
export function verifyKzgProof(
  polynomialKzg: KZGCommitment,
  z: BLSFieldElement,
  y: BLSFieldElement,
  kzgProof: KZGProof
) {
  if (!setupHandle) {
    throw new Error("You must call loadTrustedSetup to initialize KZG.");
  }
  return kzg.verifyKzgProof(polynomialKzg, z, y, kzgProof, setupHandle);
}

export function verifyAggregateKzgProof(
  blobs: Blob[],
  expectedKzgCommitments: KZGCommitment[],
  kzgAggregatedProof: KZGProof
) {
  if (!setupHandle) {
    throw new Error("You must call loadTrustedSetup to initialize KZG.");
  }
  return kzg.verifyAggregateKzgProof(
    blobs,
    expectedKzgCommitments,
    kzgAggregatedProof,
    setupHandle
  );
}
