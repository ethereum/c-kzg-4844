import {expect} from "chai";
import {computeBlobKzgProof} from "../../lib";

describe("computeBlobKzgProof", () => {
  it("should exist", () => {
    expect(computeBlobKzgProof).to.be.a("function");
  });
});
