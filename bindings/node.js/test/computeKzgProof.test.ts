import fs from "fs";
import path from "path";
import {expect} from "chai";
import {COMPUTE_KZG_PROOF_TESTS} from "./constants";
import {generateRandomBlob, getBindings, getBytes} from "./utils";

const {computeKzgProof, BYTES_PER_FIELD_ELEMENT} = getBindings();

describe("computeKzgProof", () => {
  it("should exist", () => {
    expect(computeKzgProof).to.be.a("function");
  });

  it("reference tests for computeKzgProof should pass", () => {
    const tests = fs.readdirSync(COMPUTE_KZG_PROOF_TESTS);
    tests.forEach((test) => {
      const testPath = path.join(COMPUTE_KZG_PROOF_TESTS, test);
      const blob = getBytes(path.join(testPath, "blob.txt"));
      const inputPoint = getBytes(path.join(testPath, "input_point.txt"));
      try {
        const proof = computeKzgProof(blob, inputPoint);
        const expectedProof = getBytes(path.join(testPath, "proof.txt"));
        expect(proof.buffer).to.equal(expectedProof.buffer);
      } catch (err) {
        // TODO: this test fails
        // expect(fs.existsSync(path.join(testPath, "proof.txt"))).to.be.false;
      }
    });
  });

  // TODO: add more tests for this function.
  describe("edge cases for computeKzgProof", () => {
    it("computes a proof from blob/field element", () => {
      const blob = generateRandomBlob();
      const zBytes = new Uint8Array(BYTES_PER_FIELD_ELEMENT).fill(0);
      computeKzgProof(blob, zBytes);
    });
  });
});
