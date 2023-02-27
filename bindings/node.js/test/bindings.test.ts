import {expect} from "chai";
import {
  BYTES_PER_BLOB,
  BYTES_PER_COMMITMENT,
  BYTES_PER_FIELD_ELEMENT,
  BYTES_PER_PROOF,
  FIELD_ELEMENTS_PER_BLOB,
} from "../lib";
import {getBindings} from "./utils";

describe("constants on function object", () => {
  it("BYTES_PER_BLOB", () => {
    expect(BYTES_PER_BLOB).to.be.a("number");
  });
  it("BYTES_PER_COMMITMENT", () => {
    expect(BYTES_PER_COMMITMENT).to.be.a("number");
  });
  it("BYTES_PER_FIELD_ELEMENT", () => {
    expect(BYTES_PER_FIELD_ELEMENT).to.be.a("number");
  });
  it("BYTES_PER_PROOF", () => {
    expect(BYTES_PER_PROOF).to.be.a("number");
  });
  it("FIELD_ELEMENTS_PER_BLOB", () => {
    expect(FIELD_ELEMENTS_PER_BLOB).to.be.a("number");
  });
});
describe("constants on the initialized bindings", () => {
  const {BYTES_PER_BLOB, BYTES_PER_COMMITMENT, BYTES_PER_FIELD_ELEMENT, BYTES_PER_PROOF, FIELD_ELEMENTS_PER_BLOB} =
    getBindings();
  it("BYTES_PER_BLOB", () => {
    expect(BYTES_PER_BLOB).to.be.a("number");
  });
  it("BYTES_PER_COMMITMENT", () => {
    expect(BYTES_PER_COMMITMENT).to.be.a("number");
  });
  it("BYTES_PER_FIELD_ELEMENT", () => {
    expect(BYTES_PER_FIELD_ELEMENT).to.be.a("number");
  });
  it("BYTES_PER_PROOF", () => {
    expect(BYTES_PER_PROOF).to.be.a("number");
  });
  it("FIELD_ELEMENTS_PER_BLOB", () => {
    expect(FIELD_ELEMENTS_PER_BLOB).to.be.a("number");
  });
});
describe("Trusted Setup", () => {
  it("should load newline delimited utf8 text files", () => {});
  it("should load json files", () => {});
});
