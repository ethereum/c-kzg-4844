import {expect} from "chai";
import bindings from "../../lib";
import {TRUSTED_SETUP_JSON} from "../constants";

const {verifyBlobKzgProofBatch} = bindings(TRUSTED_SETUP_JSON);

describe("verifyBlobKzgProofBatch", () => {
  it("should exist", () => {
    expect(verifyBlobKzgProofBatch).to.be.a("function");
  });
});
