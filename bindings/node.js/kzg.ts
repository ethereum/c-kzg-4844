// @ts-expect-error
import bindings from 'bindings';

// Consider making this internal state of the native code
// so we don't have to pass it around in the application layer
export type SetupHandle = Object;

export enum ReturnValue {
  /** Success! */
  OK = 0,
  /** The supplied data is invalid in some way */
  BADARGS,
  /** Internal error - this should never occur and may indicate a bug in the library */
  ERROR,
  /** Could not allocate memory */
  MALLOC,
}

export const BLOB_SIZE = 4096;
export const NUMBER_OF_FIELDS = 32;

export type Point = Uint8Array;
export type KZGProof = Uint8Array;
export type KZGCommitment = Uint8Array;
export type Blob = Uint8Array;
export type Blobs = Blob[];

type KZG = {
  loadTrustedSetup: (path: string) => SetupHandle;
  freeTrustedSetup: (setupHandle: SetupHandle) => void;
  blobToKzgCommitment: (blob: Blob, setupHandle: SetupHandle) => KZGCommitment;
  verifyAggregateKzgProof: (blobs: Blobs) => ReturnValue;
  computeAggregateKzgProof: (
    blobs: Blobs,
    size: number,
    setupHandle: SetupHandle,
  ) => KZGProof;
  verifyKzgProof: (
    commitment: KZGCommitment,
    x: Point,
    y: Point,
    proof: KZGProof,
    setupHandle: SetupHandle,
  ) => ReturnValue;
};

const kzg: KZG = bindings('kzg.node');

export const loadTrustedSetup = kzg.loadTrustedSetup;
export const freeTrustedSetup = kzg.freeTrustedSetup;
export const blobToKzgCommitment = kzg.blobToKzgCommitment;
export const verifyAggregateKzgProof = kzg.verifyAggregateKzgProof;
export const computeAggregateKzgProof = kzg.computeAggregateKzgProof;
export const verifyKzgProof = kzg.verifyKzgProof;

export default kzg;
