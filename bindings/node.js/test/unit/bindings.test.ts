import {expect} from "chai";
import * as bindings from "../../lib";

describe("bindings", () => {
  describe("constants", () => {
    const {BYTES_PER_BLOB, BYTES_PER_COMMITMENT, BYTES_PER_FIELD_ELEMENT, BYTES_PER_PROOF, FIELD_ELEMENTS_PER_BLOB} =
      bindings;
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
});
