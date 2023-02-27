import {expect} from "chai";
import bindings from "../lib";
import {TRUSTED_SETUP_JSON} from "./constants";

const kzg = bindings(TRUSTED_SETUP_JSON);
describe("bindings", () => {
  const {BYTES_PER_BLOB, BYTES_PER_COMMITMENT, BYTES_PER_FIELD_ELEMENT, BYTES_PER_PROOF, FIELD_ELEMENTS_PER_BLOB} = kzg;
  it("DST", () => {
    expect(BYTES_PER_BLOB).to.be.a("number");
  });
  it("SECRET_KEY_LENGTH", () => {
    expect(BYTES_PER_COMMITMENT).to.be.a("number");
  });
  it("PUBLIC_KEY_LENGTH_UNCOMPRESSED", () => {
    expect(BYTES_PER_FIELD_ELEMENT).to.be.a("number");
  });
  it("PUBLIC_KEY_LENGTH_COMPRESSED", () => {
    expect(BYTES_PER_PROOF).to.be.a("number");
  });
  it("SIGNATURE_LENGTH_COMPRESSED", () => {
    expect(FIELD_ELEMENTS_PER_BLOB).to.be.a("number");
  });
});
