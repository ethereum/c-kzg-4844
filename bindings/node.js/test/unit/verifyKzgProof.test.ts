import {expect} from "chai";
import bindings from "../../lib";
import {TRUSTED_SETUP_JSON} from "../constants";

const {verifyKzgProof} = bindings(TRUSTED_SETUP_JSON);

describe("verifyKzgProof", () => {
  it("should exist", () => {
    expect(verifyKzgProof).to.be.a("function");
  });
});
