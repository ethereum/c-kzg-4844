import {expect} from "chai";
import bindings from "../../lib";
import {TRUSTED_SETUP_JSON} from "../constants";

const {verifyBlobKzgProof} = bindings(TRUSTED_SETUP_JSON);

describe("verifyBlobKzgProof", () => {
  it("should exist", () => {
    expect(verifyBlobKzgProof).to.be.a("function");
  });
});
