import fs from "fs";
import path from "path";
import {expect} from "chai";
import {generateRandomBlob, getBindings, getBoolean, getBytes} from "./utils";
import {VERIFY_BLOB_KZG_PROOF_TESTS} from "./constants";

const {verifyBlobKzgProof, blobToKzgCommitment, computeBlobKzgProof} = getBindings();

describe("verifyBlobKzgProof", () => {
  it("should exist", () => {
    expect(verifyBlobKzgProof).to.be.a("function");
  });

  it("reference tests for verifyBlobKzgProof should pass", () => {
    const tests = fs.readdirSync(VERIFY_BLOB_KZG_PROOF_TESTS);
    tests.forEach((test) => {
      const testPath = path.join(VERIFY_BLOB_KZG_PROOF_TESTS, test);
      const blob = getBytes(path.join(testPath, "blob.txt"));
      const commitment = getBytes(path.join(testPath, "commitment.txt"));
      const proof = getBytes(path.join(testPath, "proof.txt"));
      try {
        const ok = verifyBlobKzgProof(blob, commitment, proof);
        const expectedOk = getBoolean(path.join(testPath, "ok.txt"));
        expect(ok).to.equal(expectedOk);
      } catch (err) {
        expect(fs.existsSync(path.join(testPath, "ok.txt"))).to.be.false;
      }
    });
  });

  describe("edge cases for verifyBlobKzgProof", () => {
    it("correct blob/commitment/proof should verify as true", () => {
      const blob = generateRandomBlob();
      const commitment = blobToKzgCommitment(blob);
      const proof = computeBlobKzgProof(blob);
      expect(verifyBlobKzgProof(blob, commitment, proof)).to.be.true;
    });

    it("incorrect commitment should verify as false", () => {
      const blob = generateRandomBlob();
      const commitment = blobToKzgCommitment(generateRandomBlob());
      const proof = computeBlobKzgProof(blob);
      expect(verifyBlobKzgProof(blob, commitment, proof)).to.be.false;
    });

    it("incorrect proof should verify as false", () => {
      const blob = generateRandomBlob();
      const commitment = blobToKzgCommitment(blob);
      const proof = computeBlobKzgProof(generateRandomBlob());
      expect(verifyBlobKzgProof(blob, commitment, proof)).to.be.false;
    });
  });
});
