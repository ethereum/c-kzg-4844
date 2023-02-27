/**
 * The public interface of this module exposes the functions as specified by
 * https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/polynomial-commitments.md#kzg
 */
const fs = require("fs");
const path = require("path");
const bindings = require("bindings")("kzg_bindings");

/**
 * Converts JSON formatted trusted_setup into the native format that
 * the native library requires
 *
 * @param {string} filePath is the absolute path of trusted_setup.json
 * @returns {Promise<string>}
 */
function transformTrustedSetupJson(filePath) {
  const data = fs.readFileSync(filePath, "utf8");
  const trustedSetup = JSON.parse(data);
  // QUESTION: is this safe to write to an os temp directory?
  // const outputPath = path.resolve(os.tmpdir(), path.parse(filePath).name + ".txt");
  const outputPath = path.resolve(__dirname, path.parse(filePath).name + ".txt");
  const setupText =
    bindings.FIELD_ELEMENTS_PER_BLOB +
    "\n65\n" +
    trustedSetup.setup_G1.map((p) => p.substring(2)).join("\n") +
    "\n" +
    trustedSetup.setup_G2.map((p) => p.substring(2)).join("\n");
  fs.writeFileSync(outputPath, setupText);
  return outputPath;
}

/**
 * Factory function that passes trusted setup to the bindings
 * @param {string} filePath
 * @typedef {import('./index').KzgBindings} KzgBindings
 * @returns {KzgBindings}
 */
const setup = (filePath) => {
  if (!(filePath && typeof filePath === "string")) {
    throw new TypeError("must initialize kzg with the filePath to a txt/json trusted setup");
  }
  if (!fs.existsSync(filePath)) {
    throw new Error(`no trusted setup found: ${filePath}`);
  }
  if (path.parse(filePath).ext === ".json") {
    filePath = transformTrustedSetupJson(filePath);
  }
  bindings.setup(filePath);
  return bindings;
};

/**
 * Add bindings constants to function object as a helper.  don't have to run trusted
 * setup to get to them;
 */
const {BYTES_PER_BLOB, BYTES_PER_COMMITMENT, BYTES_PER_FIELD_ELEMENT, BYTES_PER_PROOF, FIELD_ELEMENTS_PER_BLOB} =
  bindings;
setup.BYTES_PER_BLOB = BYTES_PER_BLOB;
setup.BYTES_PER_COMMITMENT = BYTES_PER_COMMITMENT;
setup.BYTES_PER_FIELD_ELEMENT = BYTES_PER_FIELD_ELEMENT;
setup.BYTES_PER_PROOF = BYTES_PER_PROOF;
setup.FIELD_ELEMENTS_PER_BLOB = FIELD_ELEMENTS_PER_BLOB;

module.exports = exports = setup;
