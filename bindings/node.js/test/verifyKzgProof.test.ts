import fs from "fs";
import path from "path";
import {expect} from "chai";
import bindings from "../lib";
import {TRUSTED_SETUP_JSON, VERIFY_KZG_PROOF_TESTS} from "./constants";
import {getBoolean, getBytes} from "./utils";

const {verifyKzgProof, BYTES_PER_COMMITMENT, BYTES_PER_FIELD_ELEMENT, BYTES_PER_PROOF} = bindings(TRUSTED_SETUP_JSON);
const tests: any[] = fs.readdirSync(VERIFY_KZG_PROOF_TESTS);

describe("verifyKzgProof", () => {
  it("should exist", () => {
    expect(verifyKzgProof).to.be.a("function");
  });
  it("reference tests for verifyKzgProof should pass", () => {
    tests.forEach((test) => {
      const testPath = path.join(VERIFY_KZG_PROOF_TESTS, test);
      const commitment = getBytes(path.join(testPath, "commitment.txt"));
      const inputPoint = getBytes(path.join(testPath, "input_point.txt"));
      const claimedValue = getBytes(path.join(testPath, "claimed_value.txt"));
      const proof = getBytes(path.join(testPath, "proof.txt"));
      try {
        const ok = verifyKzgProof(commitment, inputPoint, claimedValue, proof);
        const expectedOk = getBoolean(path.join(testPath, "ok.txt"));
        expect(ok).to.equal(expectedOk);
      } catch (err) {
        expect(fs.existsSync(path.join(testPath, "ok.txt"))).to.be.false;
      }
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

      expect(verifyKzgProof(commitment, z, y, proof)).to.be.true;
    });

    it("invalid proof should result in false", () => {
      const commitment = new Uint8Array(BYTES_PER_COMMITMENT).fill(0);
      commitment[0] = 0xc0;
      const z = new Uint8Array(BYTES_PER_FIELD_ELEMENT).fill(1);
      const y = new Uint8Array(BYTES_PER_FIELD_ELEMENT).fill(1);
      const proof = new Uint8Array(BYTES_PER_PROOF).fill(0);
      proof[0] = 0xc0;

      expect(verifyKzgProof(commitment, z, y, proof)).to.be.false;
    });
  });
});
