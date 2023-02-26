import {expect} from "chai";
import {verifyKzgProof} from "../../lib";

describe("verifyKzgProof", () => {
  it("should exist", () => {
    expect(verifyKzgProof).to.be.a("function");
  });
});
