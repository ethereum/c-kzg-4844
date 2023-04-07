import {randomBytes} from "crypto";
import {readFileSync} from "fs";
import {resolve} from "path";
import {globSync} from "glob";

const yaml = require("js-yaml");

interface TestMeta<I extends Record<string, any>, O extends boolean | string | string[] | Record<string, any>> {
  input: I;
  output: O;
}

import {
  loadTrustedSetup,
  blobToKzgCommitment,
  computeKzgProof,
  computeBlobKzgProof,
  verifyKzgProof,
  verifyBlobKzgProof,
  verifyBlobKzgProofBatch,
  BYTES_PER_BLOB,
  BYTES_PER_COMMITMENT,
  BYTES_PER_PROOF,
  BYTES_PER_FIELD_ELEMENT,
  ProofResult,
} from "../lib/kzg";

const SETUP_FILE_PATH = resolve(__dirname, "__fixtures__", "testing_trusted_setups.json");

const MAX_TOP_BYTE = 114;

const BLOB_TO_KZG_COMMITMENT_TESTS = "../../tests/blob_to_kzg_commitment/*/*/data.yaml";
const COMPUTE_KZG_PROOF_TESTS = "../../tests/compute_kzg_proof/*/*/data.yaml";
const COMPUTE_BLOB_KZG_PROOF_TESTS = "../../tests/compute_blob_kzg_proof/*/*/data.yaml";
const VERIFY_KZG_PROOF_TESTS = "../../tests/verify_kzg_proof/*/*/data.yaml";
const VERIFY_BLOB_KZG_PROOF_TESTS = "../../tests/verify_blob_kzg_proof/*/*/data.yaml";
const VERIFY_BLOB_KZG_PROOF_BATCH_TESTS = "../../tests/verify_blob_kzg_proof_batch/*/*/data.yaml";

type BlobToKzgCommitmentTest = TestMeta<{blob: string}, string>;
type ComputeKzgProofTest = TestMeta<{blob: string; z: string}, string[]>;
type ComputeBlobKzgProofTest = TestMeta<{blob: string; commitment: string}, string>;
type VerifyKzgProofTest = TestMeta<{commitment: string; y: string; z: string; proof: string}, boolean>;
type VerifyBlobKzgProofTest = TestMeta<{blob: string; commitment: string; proof: string}, boolean>;
type VerifyBatchKzgProofTest = TestMeta<{blobs: string[]; commitments: string[]; proofs: string[]}, boolean>;

const generateRandomBlob = (): Uint8Array => {
  return new Uint8Array(
    randomBytes(BYTES_PER_BLOB).map((x, i) => {
      // Set the top byte to be low enough that the field element doesn't overflow the BLS modulus
      if (x > MAX_TOP_BYTE && i % BYTES_PER_FIELD_ELEMENT == 31) {
        return Math.floor(Math.random() * MAX_TOP_BYTE);
      }
      return x;
    })
  );
};

const blobValidLength = randomBytes(BYTES_PER_BLOB);
const blobBadLength = randomBytes(BYTES_PER_BLOB - 1);
const commitmentValidLength = randomBytes(BYTES_PER_COMMITMENT);
const commitmentBadLength = randomBytes(BYTES_PER_COMMITMENT - 1);
const proofValidLength = randomBytes(BYTES_PER_PROOF);
const proofBadLength = randomBytes(BYTES_PER_PROOF - 1);
const fieldElementValidLength = randomBytes(BYTES_PER_FIELD_ELEMENT);
const fieldElementBadLength = randomBytes(BYTES_PER_FIELD_ELEMENT - 1);

function bytesFromHex(hexString: string): Uint8Array {
  if (hexString.startsWith("0x")) {
    hexString = hexString.slice(2);
  }
  return Uint8Array.from(Buffer.from(hexString, "hex"));
}

function bytesEqual(a: Uint8Array | Buffer, b: Uint8Array | Buffer): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

describe("C-KZG", () => {
  beforeAll(async () => {
    loadTrustedSetup(SETUP_FILE_PATH);
  });

  describe("reference tests should pass", () => {
    it("reference tests for blobToKzgCommitment should pass", () => {
      const tests = globSync(BLOB_TO_KZG_COMMITMENT_TESTS);
      expect(tests.length).toBeGreaterThan(0);

      tests.forEach((testFile: string) => {
        const test: BlobToKzgCommitmentTest = yaml.load(readFileSync(testFile, "ascii"));

        let commitment: Uint8Array;
        const blob = bytesFromHex(test.input.blob);

        try {
          commitment = blobToKzgCommitment(blob);
        } catch (err) {
          expect(test.output).toBeNull();
          return;
        }

        expect(test.output).not.toBeNull();
        const expectedCommitment = bytesFromHex(test.output);
        expect(bytesEqual(commitment, expectedCommitment));
      });
    });

    it("reference tests for computeKzgProof should pass", () => {
      const tests = globSync(COMPUTE_KZG_PROOF_TESTS);
      expect(tests.length).toBeGreaterThan(0);

      tests.forEach((testFile: string) => {
        const test: ComputeKzgProofTest = yaml.load(readFileSync(testFile, "ascii"));

        let proof: ProofResult;
        const blob = bytesFromHex(test.input.blob);
        const z = bytesFromHex(test.input.z);

        try {
          proof = computeKzgProof(blob, z);
        } catch (err) {
          expect(test.output).toBeNull();
          return;
        }

        expect(test.output).not.toBeNull();

        const [proofBytes, yBytes] = proof;
        const [expectedProofBytes, expectedYBytes] = test.output.map((out) => bytesFromHex(out));

        expect(bytesEqual(proofBytes, expectedProofBytes));
        expect(bytesEqual(yBytes, expectedYBytes));
      });
    });

    it("reference tests for computeBlobKzgProof should pass", () => {
      const tests = globSync(COMPUTE_BLOB_KZG_PROOF_TESTS);
      expect(tests.length).toBeGreaterThan(0);

      tests.forEach((testFile: string) => {
        const test: ComputeBlobKzgProofTest = yaml.load(readFileSync(testFile, "ascii"));

        let proof: Uint8Array;
        const blob = bytesFromHex(test.input.blob);
        const commitment = bytesFromHex(test.input.commitment);

        try {
          proof = computeBlobKzgProof(blob, commitment);
        } catch (err) {
          expect(test.output).toBeNull();
          return;
        }

        expect(test.output).not.toBeNull();
        const expectedProof = bytesFromHex(test.output);
        expect(bytesEqual(proof, expectedProof));
      });
    });

    it("reference tests for verifyKzgProof should pass", () => {
      const tests = globSync(VERIFY_KZG_PROOF_TESTS);
      expect(tests.length).toBeGreaterThan(0);

      tests.forEach((testFile: string) => {
        const test: VerifyKzgProofTest = yaml.load(readFileSync(testFile, "ascii"));

        let valid;
        const commitment = bytesFromHex(test.input.commitment);
        const z = bytesFromHex(test.input.z);
        const y = bytesFromHex(test.input.y);
        const proof = bytesFromHex(test.input.proof);

        try {
          valid = verifyKzgProof(commitment, z, y, proof);
        } catch (err) {
          expect(test.output).toBeNull();
          return;
        }

        expect(valid).toEqual(test.output);
      });
    });

    it("reference tests for verifyBlobKzgProof should pass", () => {
      const tests = globSync(VERIFY_BLOB_KZG_PROOF_TESTS);
      expect(tests.length).toBeGreaterThan(0);

      tests.forEach((testFile: string) => {
        const test: VerifyBlobKzgProofTest = yaml.load(readFileSync(testFile, "ascii"));

        let valid;
        const blob = bytesFromHex(test.input.blob);
        const commitment = bytesFromHex(test.input.commitment);
        const proof = bytesFromHex(test.input.proof);

        try {
          valid = verifyBlobKzgProof(blob, commitment, proof);
        } catch (err) {
          expect(test.output).toBeNull();
          return;
        }

        expect(valid).toEqual(test.output);
      });
    });

    it("reference tests for verifyBlobKzgProofBatch should pass", () => {
      const tests = globSync(VERIFY_BLOB_KZG_PROOF_BATCH_TESTS);
      expect(tests.length).toBeGreaterThan(0);

      tests.forEach((testFile: string) => {
        const test: VerifyBatchKzgProofTest = yaml.load(readFileSync(testFile, "ascii"));

        let valid;
        const blobs = test.input.blobs.map(bytesFromHex);
        const commitments = test.input.commitments.map(bytesFromHex);
        const proofs = test.input.proofs.map(bytesFromHex);

        try {
          valid = verifyBlobKzgProofBatch(blobs, commitments, proofs);
        } catch (err) {
          expect(test.output).toBeNull();
          return;
        }

        expect(valid).toEqual(test.output);
      });
    });
  });

  describe("edge cases for blobToKzgCommitment", () => {
    it("throws as expected when given an argument of invalid type", () => {
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-expect-error
      expect(() => blobToKzgCommitment("wrong type")).toThrowError("Expected blob to be a Uint8Array");
    });

    it("throws as expected when given an argument of invalid length", () => {
      expect(() => blobToKzgCommitment(blobBadLength)).toThrowError("Expected blob to be 131072 bytes");
    });
  });

  // TODO: add more tests for this function.
  describe("edge cases for computeKzgProof", () => {
    it("computes a proof from blob/field element", () => {
      const blob = generateRandomBlob();
      const zBytes = new Uint8Array(BYTES_PER_FIELD_ELEMENT).fill(0);
      computeKzgProof(blob, zBytes);
    });
    it("throws as expected when given an argument of invalid length", () => {
      expect(() => computeKzgProof(blobBadLength, fieldElementValidLength)).toThrowError(
        "Expected blob to be 131072 bytes"
      );
      expect(() => computeKzgProof(blobValidLength, fieldElementBadLength)).toThrowError(
        "Expected zBytes to be 32 bytes"
      );
    });
  });

  // TODO: add more tests for this function.
  describe("edge cases for computeBlobKzgProof", () => {
    it("computes a proof from blob", () => {
      const blob = generateRandomBlob();
      const commitment = blobToKzgCommitment(blob);
      computeBlobKzgProof(blob, commitment);
    });
    it("throws as expected when given an argument of invalid length", () => {
      expect(() => computeBlobKzgProof(blobBadLength, blobToKzgCommitment(generateRandomBlob()))).toThrowError(
        "Expected blob to be 131072 bytes"
      );
    });
  });

  describe("edge cases for verifyKzgProof", () => {
    it("valid proof should result in true", () => {
      const commitment = new Uint8Array(BYTES_PER_COMMITMENT).fill(0);
      commitment[0] = 0xc0;
      const z = new Uint8Array(BYTES_PER_FIELD_ELEMENT).fill(0);
      const y = new Uint8Array(BYTES_PER_FIELD_ELEMENT).fill(0);
      const proof = new Uint8Array(BYTES_PER_PROOF).fill(0);
      proof[0] = 0xc0;

      expect(verifyKzgProof(commitment, z, y, proof)).toBe(true);
    });

    it("invalid proof should result in false", () => {
      const commitment = new Uint8Array(BYTES_PER_COMMITMENT).fill(0);
      commitment[0] = 0xc0;
      const z = new Uint8Array(BYTES_PER_FIELD_ELEMENT).fill(1);
      const y = new Uint8Array(BYTES_PER_FIELD_ELEMENT).fill(1);
      const proof = new Uint8Array(BYTES_PER_PROOF).fill(0);
      proof[0] = 0xc0;

      expect(verifyKzgProof(commitment, z, y, proof)).toBe(false);
    });
    it("throws as expected when given an argument of invalid length", () => {
      expect(() =>
        verifyKzgProof(commitmentBadLength, fieldElementValidLength, fieldElementValidLength, proofValidLength)
      ).toThrowError("Expected commitmentBytes to be 48 bytes");
      expect(() =>
        verifyKzgProof(commitmentValidLength, fieldElementBadLength, fieldElementValidLength, proofValidLength)
      ).toThrowError("Expected zBytes to be 32 bytes");
      expect(() =>
        verifyKzgProof(commitmentValidLength, fieldElementValidLength, fieldElementBadLength, proofValidLength)
      ).toThrowError("Expected yBytes to be 32 bytes");
      expect(() =>
        verifyKzgProof(commitmentValidLength, fieldElementValidLength, fieldElementValidLength, proofBadLength)
      ).toThrowError("Expected proofBytes to be 48 bytes");
    });
  });

  describe("edge cases for verifyBlobKzgProof", () => {
    it("correct blob/commitment/proof should verify as true", () => {
      const blob = generateRandomBlob();
      const commitment = blobToKzgCommitment(blob);
      const proof = computeBlobKzgProof(blob, commitment);
      expect(verifyBlobKzgProof(blob, commitment, proof)).toBe(true);
    });

    it("incorrect commitment should verify as false", () => {
      const blob = generateRandomBlob();
      const commitment = blobToKzgCommitment(generateRandomBlob());
      const proof = computeBlobKzgProof(blob, commitment);
      expect(verifyBlobKzgProof(blob, commitment, proof)).toBe(false);
    });

    it("incorrect proof should verify as false", () => {
      const blob = generateRandomBlob();
      const commitment = blobToKzgCommitment(blob);
      const randomBlob = generateRandomBlob();
      const randomCommitment = blobToKzgCommitment(randomBlob);
      const proof = computeBlobKzgProof(randomBlob, randomCommitment);
      expect(verifyBlobKzgProof(blob, commitment, proof)).toBe(false);
    });
    it("throws as expected when given an argument of invalid length", () => {
      expect(() => verifyBlobKzgProof(blobBadLength, commitmentValidLength, proofValidLength)).toThrowError(
        "Expected blob to be 131072 bytes"
      );
      expect(() => verifyBlobKzgProof(blobValidLength, commitmentBadLength, proofValidLength)).toThrowError(
        "Expected commitmentBytes to be 48 bytes"
      );
      expect(() => verifyBlobKzgProof(blobValidLength, commitmentValidLength, proofBadLength)).toThrowError(
        "Expected proofBytes to be 48 bytes"
      );
    });
  });

  describe("edge cases for verifyBlobKzgProofBatch", () => {
    it("should reject non-array args", () => {
      expect(() =>
        verifyBlobKzgProofBatch(
          2 as unknown as Uint8Array[],
          [commitmentValidLength, commitmentValidLength],
          [proofValidLength, proofValidLength]
        )
      ).toThrowError("Blobs, commitments, and proofs must all be arrays");
    });
    it("should reject non-bytearray blob", () => {
      expect(() =>
        verifyBlobKzgProofBatch(
          ["foo", "bar"] as unknown as Uint8Array[],
          [commitmentValidLength, commitmentValidLength],
          [proofValidLength, proofValidLength]
        )
      ).toThrowError("Expected blob to be a Uint8Array");
    });
    it("throws as expected when given an argument of invalid length", () => {
      expect(() =>
        verifyBlobKzgProofBatch(
          [blobBadLength, blobValidLength],
          [commitmentValidLength, commitmentValidLength],
          [proofValidLength, proofValidLength]
        )
      ).toThrowError("Expected blob to be 131072 bytes");
      expect(() =>
        verifyBlobKzgProofBatch(
          [blobValidLength, blobValidLength],
          [commitmentBadLength, commitmentValidLength],
          [proofValidLength, proofValidLength]
        )
      ).toThrowError("Expected commitmentBytes to be 48 bytes");
      expect(() =>
        verifyBlobKzgProofBatch(
          [blobValidLength, blobValidLength],
          [commitmentValidLength, commitmentValidLength],
          [proofValidLength, proofBadLength]
        )
      ).toThrowError("Expected proofBytes to be 48 bytes");
    });

    it("zero blobs/commitments/proofs should verify as true", () => {
      expect(verifyBlobKzgProofBatch([], [], [])).toBe(true);
    });

    it("mismatching blobs/commitments/proofs should throw error", () => {
      const count = 3;
      const blobs = new Array(count);
      const commitments = new Array(count);
      const proofs = new Array(count);

      for (const [i] of blobs.entries()) {
        blobs[i] = generateRandomBlob();
        commitments[i] = blobToKzgCommitment(blobs[i]);
        proofs[i] = computeBlobKzgProof(blobs[i], commitments[i]);
      }

      expect(verifyBlobKzgProofBatch(blobs, commitments, proofs)).toBe(true);
      expect(() => verifyBlobKzgProofBatch(blobs.slice(0, 1), commitments, proofs)).toThrowError(
        "Requires equal number of blobs/commitments/proofs"
      );
      expect(() => verifyBlobKzgProofBatch(blobs, commitments.slice(0, 1), proofs)).toThrowError(
        "Requires equal number of blobs/commitments/proofs"
      );
      expect(() => verifyBlobKzgProofBatch(blobs, commitments, proofs.slice(0, 1))).toThrowError(
        "Requires equal number of blobs/commitments/proofs"
      );
    });
  });
});
