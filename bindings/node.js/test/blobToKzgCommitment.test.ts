import fs from "fs";
import path from "path";
import {expect} from "chai";
import {BYTES_PER_BLOB} from "../lib";
import {BLOB_TO_KZG_COMMITMENT_TESTS} from "./constants";
import {getBindings, getBytes} from "./utils";
import {randomBytes} from "crypto";

const {blobToKzgCommitment} = getBindings();
const tests = fs.readdirSync(BLOB_TO_KZG_COMMITMENT_TESTS);

describe("blobToKzgCommitment", () => {
  it("should exist", () => {
    expect(blobToKzgCommitment).to.be.a("function");
  });
  it("reference tests for blobToKzgCommitment should pass", () => {
    tests.forEach((test) => {
      const testPath = path.join(BLOB_TO_KZG_COMMITMENT_TESTS, test);
      const blob = getBytes(path.join(testPath, "blob.txt"));
      expect(fs.existsSync(path.join(testPath, "commitment.txt"))).to.be.true;
      const commitment = blobToKzgCommitment(blob);
      const expectedCommitment = getBytes(path.join(testPath, "commitment.txt"));
      expect(commitment.toString("hex")).to.equal(Buffer.from(expectedCommitment).toString("hex"));
    });
  });
  describe("edge cases for blobToKzgCommitment", () => {
    it("throws as expected when given an argument of invalid type", () => {
      expect(() => blobToKzgCommitment("wrong type" as unknown as Uint8Array)).to.throw("blob must be a Uint8Array");
    });

    it("throws as expected when given an argument of invalid length", () => {
      expect(() => blobToKzgCommitment(randomBytes(BYTES_PER_BLOB - 1))).to.throw("blob must be 131072 bytes long");
    });
  });
});
