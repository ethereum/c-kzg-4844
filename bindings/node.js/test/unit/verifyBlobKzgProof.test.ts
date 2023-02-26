import {expect} from "chai";
import {verifyBlobKzgProof} from "../../lib";

describe("verifyBlobKzgProof", () => {
  it("should exist", () => {
    expect(verifyBlobKzgProof).to.be.a("function");
  });
});
