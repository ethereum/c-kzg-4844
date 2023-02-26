import {expect} from "chai";
import bindings from "../../lib";
import {TRUSTED_SETUP_JSON} from "../constants";

const {blobToKzgCommitment} = bindings(TRUSTED_SETUP_JSON);

describe("blobToKzgCommitment", () => {
  it("should exist", () => {
    expect(blobToKzgCommitment).to.be.a("function");
  });
});
