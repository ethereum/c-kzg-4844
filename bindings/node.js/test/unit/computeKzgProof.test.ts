import {expect} from "chai";
import bindings from "../../lib";
import {TRUSTED_SETUP_JSON} from "../constants";

const {computeKzgProof} = bindings(TRUSTED_SETUP_JSON);

describe("computeKzgProof", () => {
  it("should exist", () => {
    expect(computeKzgProof).to.be.a("function");
  });
});
