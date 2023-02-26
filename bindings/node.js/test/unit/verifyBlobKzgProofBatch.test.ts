import {expect} from "chai";
import {verifyBlobKzgProofBatch} from "../../lib";

describe("verifyBlobKzgProofBatch", () => {
  it("should exist", () => {
    expect(verifyBlobKzgProofBatch).to.be.a("function");
  });
});
