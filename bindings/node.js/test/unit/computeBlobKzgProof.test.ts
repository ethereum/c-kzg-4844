import {expect} from "chai";
import bindings from "../../lib";
import {TRUSTED_SETUP_JSON} from "../constants";

const {computeBlobKzgProof} = bindings(TRUSTED_SETUP_JSON);

describe("computeBlobKzgProof", () => {
  it("should exist", () => {
    expect(computeBlobKzgProof).to.be.a("function");
  });
});
