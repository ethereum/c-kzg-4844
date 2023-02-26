import {expect} from "chai";
import {blobToKzgCommitment} from "../../lib";

describe("blobToKzgCommitment", () => {
  it("should exist", () => {
    expect(blobToKzgCommitment).to.be.a("function");
  });
});
