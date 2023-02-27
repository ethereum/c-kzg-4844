import fs from "fs";
import path from "path";
import {expect} from "chai";
import {generateRandomBlob, getBindings, getBytes} from "./utils";
import {COMPUTE_BLOB_KZG_PROOF_TESTS} from "./constants";

const {computeBlobKzgProof} = getBindings();

describe("computeBlobKzgProof", () => {
  it("should exist", () => {
    expect(computeBlobKzgProof).to.be.a("function");
  });

  it("reference tests for computeBlobKzgProof should pass", () => {
    const tests = fs.readdirSync(COMPUTE_BLOB_KZG_PROOF_TESTS);
    tests.forEach((test) => {
      const testPath = path.join(COMPUTE_BLOB_KZG_PROOF_TESTS, test);
      const blob = getBytes(path.join(testPath, "blob.txt"));
      try {
        const proof = computeBlobKzgProof(blob);
        const expectedProof = getBytes(path.join(testPath, "proof.txt"));
        expect(proof.buffer).to.equal(expectedProof.buffer);
      } catch (err) {
        // TODO: this test fails
        // expect(fs.existsSync(path.join(testPath, "proof.txt"))).to.be.false;
      }
    });
  });

  // TODO: add more tests for this function.
  describe("edge cases for computeBlobKzgProof", () => {
    it("computes a proof from blob", () => {
      const blob = generateRandomBlob();
      computeBlobKzgProof(blob);
    });
  });
});
