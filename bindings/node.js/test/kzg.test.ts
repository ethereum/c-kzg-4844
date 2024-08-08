import {readFileSync, existsSync} from "fs";
import {resolve} from "path";
import {globSync} from "glob";

const yaml = require("js-yaml");

interface TestMeta<I extends Record<string, any>, O extends boolean | string | string[] | Record<string, any>> {
  input: I;
  output: O;
}

import kzg from "../lib/kzg";
import type {ProofResult} from "../lib/kzg";
const {
  // EIP-4844
  loadTrustedSetup,
  blobToKzgCommitment,
  computeKzgProof,
  computeBlobKzgProof,
  verifyKzgProof,
  verifyBlobKzgProof,
  verifyBlobKzgProofBatch,

  // EIP-7594
  computeCellsAndKzgProofs,
  verifyCellKzgProofBatch,
  recoverCellsAndKzgProofs,
} = kzg;

// Not exported by types, only exported for testing purposes
const getTrustedSetupFilepath = (kzg as any).getTrustedSetupFilepath as (filePath?: string) => string;
const DEFAULT_TRUSTED_SETUP_PATH = (kzg as any).DEFAULT_TRUSTED_SETUP_PATH as string;
const TEST_SETUP_FILE_PATH_JSON = resolve(__dirname, "__fixtures__", "trusted_setup.json");
const TEST_SETUP_FILE_PATH_TXT = resolve(__dirname, "__fixtures__", "trusted_setup.txt");

const BLOB_TO_KZG_COMMITMENT_TESTS = "../../tests/blob_to_kzg_commitment/*/*/data.yaml";
const COMPUTE_KZG_PROOF_TESTS = "../../tests/compute_kzg_proof/*/*/data.yaml";
const COMPUTE_BLOB_KZG_PROOF_TESTS = "../../tests/compute_blob_kzg_proof/*/*/data.yaml";
const VERIFY_KZG_PROOF_TESTS = "../../tests/verify_kzg_proof/*/*/data.yaml";
const VERIFY_BLOB_KZG_PROOF_TESTS = "../../tests/verify_blob_kzg_proof/*/*/data.yaml";
const VERIFY_BLOB_KZG_PROOF_BATCH_TESTS = "../../tests/verify_blob_kzg_proof_batch/*/*/data.yaml";
const COMPUTE_CELLS_AND_KZG_PROOFS_TESTS = "../../tests/compute_cells_and_kzg_proofs/*/*/data.yaml";
const RECOVER_CELLS_AND_KZG_PROOFS_TESTS = "../../tests/recover_cells_and_kzg_proofs/*/*/data.yaml";
const VERIFY_CELL_KZG_PROOF_BATCH_TESTS = "../../tests/verify_cell_kzg_proof_batch/*/*/data.yaml";

type BlobToKzgCommitmentTest = TestMeta<{blob: string}, string>;
type ComputeKzgProofTest = TestMeta<{blob: string; z: string}, string[]>;
type ComputeBlobKzgProofTest = TestMeta<{blob: string; commitment: string}, string>;
type VerifyKzgProofTest = TestMeta<{commitment: string; y: string; z: string; proof: string}, boolean>;
type VerifyBlobKzgProofTest = TestMeta<{blob: string; commitment: string; proof: string}, boolean>;
type VerifyBatchKzgProofTest = TestMeta<{blobs: string[]; commitments: string[]; proofs: string[]}, boolean>;
type ComputeCellsAndKzgProofsTest = TestMeta<{blob: string}, string[][]>;
type RecoverCellsAndKzgProofsTest = TestMeta<{cell_indices: number[]; cells: string[]}, string[][]>;
type VerifyCellKzgProofBatchTest = TestMeta<
  {commitments: string[]; cell_indices: number[]; cells: string[]; proofs: string[]},
  boolean
>;

/**
 * Converts hex string to binary Uint8Array
 *
 * @param {string} hexString Hex string to convert
 *
 * @return {Uint8Array}
 */
function bytesFromHex(hexString: string): Uint8Array {
  if (hexString.startsWith("0x")) {
    hexString = hexString.slice(2);
  }
  return Uint8Array.from(Buffer.from(hexString, "hex"));
}

/**
 * Verifies that two Uint8Arrays are bitwise equivalent
 *
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 *
 * @return {void}
 *
 * @throws {Error} If arrays are not equal length or byte values are unequal
 */
function assertBytesEqual(a: Uint8Array | Buffer, b: Uint8Array | Buffer): void {
  if (a.length !== b.length) {
    throw new Error("unequal Uint8Array lengths");
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) throw new Error(`unequal Uint8Array byte at index ${i}`);
  }
}

describe("C-KZG", () => {
  beforeAll(async () => {
    loadTrustedSetup(0, TEST_SETUP_FILE_PATH_JSON);
  });

  describe("locating trusted setup file", () => {
    it("should return a txt path if a json file is provided and exists", () => {
      expect(getTrustedSetupFilepath(TEST_SETUP_FILE_PATH_JSON)).toEqual(TEST_SETUP_FILE_PATH_TXT);
    });
    /**
     * No guarantee that the test above runs first, however the json file should
     * have already been loaded by the beforeAll so a valid .txt test setup
     * should be available to expect
     */
    it("should return the same txt path if provided and exists", () => {
      expect(getTrustedSetupFilepath(TEST_SETUP_FILE_PATH_TXT)).toEqual(TEST_SETUP_FILE_PATH_TXT);
    });
    describe("default setups", () => {
      beforeAll(() => {
        if (!existsSync(DEFAULT_TRUSTED_SETUP_PATH)) {
          throw new Error("Default deps/c-kzg/trusted_setup.txt not found for testing");
        }
      });
      it("should return default trusted_setup filepath", () => {
        expect(getTrustedSetupFilepath()).toEqual(DEFAULT_TRUSTED_SETUP_PATH);
      });
    });
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
        expect(assertBytesEqual(commitment, expectedCommitment));
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

        expect(assertBytesEqual(proofBytes, expectedProofBytes));
        expect(assertBytesEqual(yBytes, expectedYBytes));
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
        expect(assertBytesEqual(proof, expectedProof));
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

    it("reference tests for computeCellsAndKzgProofs should pass", () => {
      const tests = globSync(COMPUTE_CELLS_AND_KZG_PROOFS_TESTS);
      expect(tests.length).toBeGreaterThan(0);

      tests.forEach((testFile: string) => {
        const test: ComputeCellsAndKzgProofsTest = yaml.load(readFileSync(testFile, "ascii"));

        let cells;
        let proofs;
        const blob = bytesFromHex(test.input.blob);

        try {
          [cells, proofs] = computeCellsAndKzgProofs(blob);
        } catch (err) {
          expect(test.output).toBeNull();
          return;
        }

        expect(test.output).not.toBeNull();
        expect(test.output.length).toBe(2);
        const expectedCells = test.output[0].map(bytesFromHex);
        const expectedProofs = test.output[1].map(bytesFromHex);
        expect(cells.length).toBe(expectedCells.length);
        for (let i = 0; i < cells.length; i++) {
          assertBytesEqual(cells[i], expectedCells[i]);
        }
        expect(proofs.length).toBe(expectedProofs.length);
        for (let i = 0; i < proofs.length; i++) {
          assertBytesEqual(proofs[i], expectedProofs[i]);
        }
      });
    });

    it("reference tests for recoverCellsAndKzgProofs should pass", () => {
      const tests = globSync(RECOVER_CELLS_AND_KZG_PROOFS_TESTS);
      expect(tests.length).toBeGreaterThan(0);

      tests.forEach((testFile: string) => {
        const test: RecoverCellsAndKzgProofsTest = yaml.load(readFileSync(testFile, "ascii"));

        let recoveredCells;
        let recoveredProofs;
        const cellIndices = test.input.cell_indices;
        const cells = test.input.cells.map(bytesFromHex);

        try {
          [recoveredCells, recoveredProofs] = recoverCellsAndKzgProofs(cellIndices, cells);
        } catch (err) {
          expect(test.output).toBeNull();
          return;
        }

        expect(test.output).not.toBeNull();
        expect(test.output.length).toBe(2);
        const expectedCells = test.output[0].map(bytesFromHex);
        const expectedProofs = test.output[1].map(bytesFromHex);
        expect(recoveredCells.length).toBe(expectedCells.length);
        for (let i = 0; i < recoveredCells.length; i++) {
          assertBytesEqual(recoveredCells[i], expectedCells[i]);
        }
        expect(recoveredProofs.length).toBe(expectedProofs.length);
        for (let i = 0; i < recoveredProofs.length; i++) {
          assertBytesEqual(recoveredProofs[i], expectedProofs[i]);
        }
      });
    });

    it("reference tests for verifyCellKzgProofBatch should pass", () => {
      const tests = globSync(VERIFY_CELL_KZG_PROOF_BATCH_TESTS);
      expect(tests.length).toBeGreaterThan(0);

      tests.forEach((testFile: string) => {
        const test: VerifyCellKzgProofBatchTest = yaml.load(readFileSync(testFile, "ascii"));

        let valid;
        const commitments = test.input.commitments.map(bytesFromHex);
        const cellIndices = test.input.cell_indices;
        const cells = test.input.cells.map(bytesFromHex);
        const proofs = test.input.proofs.map(bytesFromHex);

        try {
          valid = verifyCellKzgProofBatch(commitments, cellIndices, cells, proofs);
        } catch (err) {
          expect(test.output).toBeNull();
          return;
        }

        expect(valid).toEqual(test.output);
      });
    });
  });
});
