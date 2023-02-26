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
export interface KzgBindings {
  BYTES_PER_BLOB: number;
  BYTES_PER_COMMITMENT: number;
  BYTES_PER_FIELD_ELEMENT: number;
  BYTES_PER_PROOF: number;
  FIELD_ELEMENTS_PER_BLOB: number;
  blobToKzgCommitment(blob: Blob): KZGCommitment;
  computeKzgProof(blob: Blob, zBytes: Bytes32): KZGProof;
  computeBlobKzgProof(blob: Blob): KZGProof;
  verifyBlobKzgProof(blob: Blob, commitmentBytes: Bytes48, proofBytes: Bytes48): boolean;
  verifyBlobKzgProofBatch(blobs: Blob[], commitmentsBytes: Bytes48[], proofsBytes: Bytes48[]): boolean;
  verifyKzgProof(commitmentBytes: Bytes48, zBytes: Bytes32, yBytes: Bytes32, proofBytes: Bytes48): boolean;
}
declare const setup: (filePath: string) => KzgBindings;
export default setup;
