import { randomBytes } from 'crypto';
import {
  loadTrustedSetup,
  freeTrustedSetup,
  verifyKzgProof,
  blobToKzgCommitment,
  ReturnValue,
  SetupHandle,
  Blob,
  BLOB_SIZE,
  NUMBER_OF_FIELDS,
  computeAggregateKzgProof,
} from './kzg';

const SETUP_FILE_PATH = '../../src/trusted_setup.txt';

const COMMITMENT_BYTE_LENGTH = 48;

function generateRandomBlob(): Blob {
  return new Uint8Array(randomBytes(NUMBER_OF_FIELDS * BLOB_SIZE));
}

describe('C-KZG', () => {
  let sharedSetupHandle: SetupHandle;

  beforeAll(() => {
    sharedSetupHandle = loadTrustedSetup(SETUP_FILE_PATH);
  });

  describe('setup', () => {
    it('can both load and free', () => {
      expect(
        freeTrustedSetup(loadTrustedSetup(SETUP_FILE_PATH)),
      ).toBeUndefined();
    });
  });

  describe('computing a KZG commitment from a blob', () => {
    it('returns data with the correct length', () => {
      const blob = generateRandomBlob();
      const commitment = blobToKzgCommitment(blob, sharedSetupHandle);
      expect(commitment.length).toBe(COMMITMENT_BYTE_LENGTH);
    });
  });

  describe('verifying a KZG proof', () => {
    it.only('returns the expected value', () => {
      const byteEncoder = new TextEncoder();

      const blob = generateRandomBlob();
      const commitment = blobToKzgCommitment(blob, sharedSetupHandle);
      const proof = computeAggregateKzgProof([blob], sharedSetupHandle);

      const x = byteEncoder.encode(
        '0345f802a75a6c0d9cc5b8a1e71642b8fa80b0a78938edc6da1e591149578d1a',
      );
      const y = byteEncoder.encode(
        '3b17cab634c3795d311380f3bc93ce8e768efc0e2b9e79496cfc8f351594b472',
      );

      const result = verifyKzgProof(commitment, y, x, proof, sharedSetupHandle);
      console.log({ result });
      expect(result).toBe(ReturnValue.OK);
    });
  });

  describe('computing an aggregate KZG proof', () => {
    it('returns the expected value', () => {
      const blob = generateRandomBlob();
      const commitment = blobToKzgCommitment(blob, sharedSetupHandle);
      const proof = computeAggregateKzgProof([blob], sharedSetupHandle);
    });
  });

  describe('verifying an aggregate KZG proof', () => {
    it('returns the expected value', () => {
      expect(true).toBe(false);
    });
  });
});
