import {expect} from "chai";
import {computeKzgProof} from "../../lib";

describe("computeKzgProof", () => {
  it("should exist", () => {
    expect(computeKzgProof).to.be.a("function");
  });
});
