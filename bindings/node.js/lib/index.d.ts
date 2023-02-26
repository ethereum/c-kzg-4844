/**
 * The public interface of this module exposes the functions as specified by
 * https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/polynomial-commitments.md#kzg
 */
export type Bytes32 = Uint8Array; // 32 bytes
export type Bytes48 = Uint8Array; // 48 bytes
export type KZGProof = Uint8Array; // 48 bytes
export type KZGCommitment = Uint8Array; // 48 bytes
export type Blob = Uint8Array; // 4096 * 32 bytes
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

export function blobToKzgCommitment(blob: Blob): KZGCommitment;
export function computeKzgProof(blob: Blob, zBytes: Bytes32): KZGProof;
export function computeBlobKzgProof(blob: Blob): KZGProof;
export function verifyBlobKzgProof(blob: Blob, commitmentBytes: Bytes48, proofBytes: Bytes48): boolean;
export function verifyBlobKzgProofBatch(blobs: Blob[], commitmentsBytes: Bytes48[], proofsBytes: Bytes48[]): boolean;
export function verifyKzgProof(
  commitmentBytes: Bytes48,
  zBytes: Bytes32,
  yBytes: Bytes32,
  proofBytes: Bytes48
): boolean;
