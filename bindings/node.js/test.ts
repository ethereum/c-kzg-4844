import { randomBytes } from "crypto";
import { existsSync, readFileSync } from "fs";
import { join } from "path";
import { globSync } from "glob";

const yaml = require("js-yaml");

import {
  loadTrustedSetup,
  freeTrustedSetup,
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
  transformTrustedSetupJSON,
} from "./kzg";

const setupFileName = "testing_trusted_setups.json";

const SETUP_FILE_PATH = existsSync(setupFileName)
  ? setupFileName
  : `../../src/${setupFileName}`;

const MAX_TOP_BYTE = 114;

const TEST_DIR = "../../newtests";
const BLOB_TO_KZG_COMMITMENT_TESTS = join(
  TEST_DIR,
  "blob_to_kzg_commitment/*/*/data.yaml",
);
const COMPUTE_KZG_PROOF_TESTS = join(
  TEST_DIR,
  "compute_kzg_proof/*/*/data.yaml",
);
const COMPUTE_BLOB_KZG_PROOF_TESTS = join(
  TEST_DIR,
  "compute_blob_kzg_proof/*/*/data.yaml",
);
const VERIFY_KZG_PROOF_TESTS = join(TEST_DIR, "verify_kzg_proof/*/*/data.yaml");
const VERIFY_BLOB_KZG_PROOF_TESTS = join(
  TEST_DIR,
  "verify_blob_kzg_proof/*/*/data.yaml",
);
const VERIFY_BLOB_KZG_PROOF_BATCH_TESTS = join(
  TEST_DIR,
  "verify_blob_kzg_proof_batch/*/*/data.yaml",
);

const generateRandomBlob = () => {
  return new Uint8Array(
    randomBytes(BYTES_PER_BLOB).map((x, i) => {
      // Set the top byte to be low enough that the field element doesn't overflow the BLS modulus
      if (x > MAX_TOP_BYTE && i % BYTES_PER_FIELD_ELEMENT == 31) {
        return Math.floor(Math.random() * MAX_TOP_BYTE);
      }
      return x;
    }),
  );
};

function bytesFromHex(hexstring: string): Buffer {
  return Buffer.from(hexstring.slice(2), "hex");
}

describe("C-KZG", () => {
  beforeAll(async () => {
    const file = await transformTrustedSetupJSON(SETUP_FILE_PATH);
    loadTrustedSetup(file);
  });

  afterAll(() => {
    freeTrustedSetup();
  });

  describe("reference tests should pass", () => {
    it("reference tests for blobToKzgCommitment should pass", () => {
      let tests = globSync(BLOB_TO_KZG_COMMITMENT_TESTS);
      tests.forEach((testFile: string) => {
        const test = yaml.load(readFileSync(testFile, "ascii"));

        let commitment = new Uint8Array();
        let blob = bytesFromHex(test.input.blob);

        try {
          commitment = blobToKzgCommitment(blob);
        } catch (err) {
          expect(test.output).toBeNull();
          return;
        }

        expect(test.output).not.toBeNull();
        let expectedCommitment = bytesFromHex(test.output);
        expect(commitment.buffer).toEqual(expectedCommitment.buffer);
      });
    });

    it("reference tests for computeKzgProof should pass", () => {
      let tests = globSync(COMPUTE_KZG_PROOF_TESTS);
      tests.forEach((testFile: string) => {
        const test = yaml.load(readFileSync(testFile, "ascii"));

        let proof = new Uint8Array();
        let blob = bytesFromHex(test.input.blob);
        let z = bytesFromHex(test.input.z);

        try {
          proof = computeKzgProof(blob, z);
        } catch (err) {
          expect(test.output).toBeNull();
          return;
        }

        expect(test.output).not.toBeNull();
        let expectedProof = bytesFromHex(test.output);
        expect(proof.buffer).toEqual(expectedProof.buffer);
      });
    });

    it("reference tests for computeBlobKzgProof should pass", () => {
      let tests = globSync(COMPUTE_BLOB_KZG_PROOF_TESTS);
      tests.forEach((testFile: string) => {
        const test = yaml.load(readFileSync(testFile, "ascii"));

        let proof = new Uint8Array();
        let blob = bytesFromHex(test.input.blob);

        try {
          proof = computeBlobKzgProof(blob);
        } catch (err) {
          expect(test.output).toBeNull();
          return;
        }

        expect(test.output).not.toBeNull();
        let expectedProof = bytesFromHex(test.output);
        expect(proof.buffer).toEqual(expectedProof.buffer);
      });
    });

    it("reference tests for verifyKzgProof should pass", () => {
      let tests = globSync(VERIFY_KZG_PROOF_TESTS);
      tests.forEach((testFile: string) => {
        const test = yaml.load(readFileSync(testFile, "ascii"));

        let valid;
        let commitment = bytesFromHex(test.input.commitment);
        let z = bytesFromHex(test.input.z);
        let y = bytesFromHex(test.input.y);
        let proof = bytesFromHex(test.input.proof);

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
      let tests = globSync(VERIFY_BLOB_KZG_PROOF_TESTS);
      tests.forEach((testFile: string) => {
        const test = yaml.load(readFileSync(testFile, "ascii"));

        let valid;
        let blob = bytesFromHex(test.input.blob);
        let commitment = bytesFromHex(test.input.commitment);
        let proof = bytesFromHex(test.input.proof);

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
      let tests = globSync(VERIFY_BLOB_KZG_PROOF_BATCH_TESTS);
      tests.forEach((testFile: string) => {
        const test = yaml.load(readFileSync(testFile, "ascii"));

        let valid;
        let blobs = test.input.blobs.map(bytesFromHex);
        let commitments = test.input.commitments.map(bytesFromHex);
        let proofs = test.input.proofs.map(bytesFromHex);

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
      // @ts-expect-error
      expect(() => blobToKzgCommitment("wrong type")).toThrowError(
        "Expected blob to be a UInt8Array",
      );
    });

    it("throws as expected when given an argument of invalid length", () => {
      expect(() =>
        blobToKzgCommitment(randomBytes(BYTES_PER_BLOB - 1)),
      ).toThrowError("Expected blob to be 131072 bytes");
    });
  });

  // TODO: add more tests for this function.
  describe("edge cases for computeKzgProof", () => {
    it("computes a proof from blob/field element", () => {
      let blob = generateRandomBlob();
      const zBytes = new Uint8Array(BYTES_PER_FIELD_ELEMENT).fill(0);
      computeKzgProof(blob, zBytes);
    });
  });

  // TODO: add more tests for this function.
  describe("edge cases for computeBlobKzgProof", () => {
    it("computes a proof from blob", () => {
      let blob = generateRandomBlob();
      computeBlobKzgProof(blob);
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
  });

  describe("edge cases for verifyBlobKzgProof", () => {
    it("correct blob/commitment/proof should verify as true", () => {
      let blob = generateRandomBlob();
      let commitment = blobToKzgCommitment(blob);
      let proof = computeBlobKzgProof(blob);
      expect(verifyBlobKzgProof(blob, commitment, proof)).toBe(true);
    });

    it("incorrect commitment should verify as false", () => {
      let blob = generateRandomBlob();
      let commitment = blobToKzgCommitment(generateRandomBlob());
      let proof = computeBlobKzgProof(blob);
      expect(verifyBlobKzgProof(blob, commitment, proof)).toBe(false);
    });

    it("incorrect proof should verify as false", () => {
      let blob = generateRandomBlob();
      let commitment = blobToKzgCommitment(blob);
      let proof = computeBlobKzgProof(generateRandomBlob());
      expect(verifyBlobKzgProof(blob, commitment, proof)).toBe(false);
    });
  });

  describe("edge cases for verifyBlobKzgProofBatch", () => {
    it("should reject non-bytearray blob", () => {
      expect(() =>
        // @ts-expect-error
        verifyBlobKzgProofBatch(["foo", "bar"], [], []),
      ).toThrowError("Expected blob to be a UInt8Array");
    });

    it("zero blobs/commitments/proofs should verify as true", () => {
      expect(verifyBlobKzgProofBatch([], [], [])).toBe(true);
    });

    it("mismatching blobs/commitments/proofs should throw error", () => {
      let count = 3;
      let blobs = new Array(count);
      let commitments = new Array(count);
      let proofs = new Array(count);

      for (let [i, _] of blobs.entries()) {
        blobs[i] = generateRandomBlob();
        commitments[i] = blobToKzgCommitment(blobs[i]);
        proofs[i] = computeBlobKzgProof(blobs[i]);
      }

      expect(verifyBlobKzgProofBatch(blobs, commitments, proofs)).toBe(true);
      expect(() =>
        verifyBlobKzgProofBatch(blobs.slice(0, 1), commitments, proofs),
      ).toThrowError("requires equal number of blobs/commitments/proofs");
      expect(() =>
        verifyBlobKzgProofBatch(blobs, commitments.slice(0, 1), proofs),
      ).toThrowError("requires equal number of blobs/commitments/proofs");
      expect(() =>
        verifyBlobKzgProofBatch(blobs, commitments, proofs.slice(0, 1)),
      ).toThrowError("requires equal number of blobs/commitments/proofs");
    });
  });
});
