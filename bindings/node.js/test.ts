import {
  loadTrustedSetup,
  freeTrustedSetup,
  verifyKzgProof,
  ReturnValue,
  SetupHandle,
} from './kzg';

describe('C-KZG', () => {
  let setupHandle: SetupHandle;

  beforeAll(() => {
    setupHandle = loadTrustedSetup('../../src/trusted_setup.txt');
  });

  describe('setup', () => {
    it('can both load and free', () => {
      expect(freeTrustedSetup(setupHandle)).toBeUndefined();
    });
  });

  describe('computing a KZG commitment from a blob', () => {
    it('returns the expected value', () => {
      expect(true).toBe(ReturnValue.OK);
    });
  });

  describe('verifying a KZG proof', () => {
    it.only('returns the expected value', () => {
      const byteEncoder = new TextEncoder();

      const commitment = byteEncoder.encode(
        'b91c022acf7bd3b63be69a4c19b781ea7a3d5df1cd66ceb7dd0f399610f0ee04695dace82e04bfb83af2b17d7319f87f',
      );
      console.log({ commitment });
      const x = byteEncoder.encode(
        '0345f802a75a6c0d9cc5b8a1e71642b8fa80b0a78938edc6da1e591149578d1a',
      );
      const y = byteEncoder.encode(
        '3b17cab634c3795d311380f3bc93ce8e768efc0e2b9e79496cfc8f351594b472',
      );
      const proof = byteEncoder.encode(
        'a5ddd6da04c47a9cd4628beb8d55ebd2e930a64dfa29f876ebf393cfd6574d48a3ce96ac5a2af4a4f9ec9caa47d304d3',
      );

      const result = verifyKzgProof(commitment, y, x, proof, setupHandle);
      console.log({ result });
      expect(result).toBe(ReturnValue.OK);
    });
  });

  describe('computing an aggregate KZG proof', () => {
    it('returns the expected value', () => {
      expect(true).toBe(false);
    });
  });

  describe('verifying an aggregate KZG proof', () => {
    it('returns the expected value', () => {
      expect(true).toBe(false);
    });
  });
});
