/**
 * The public interface of this module exposes the functions as specified by
 * https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/polynomial-commitments.md#kzg
 */
const fs = require("fs");
const path = require("path");
const bindings = require("bindings")("kzg");

/**
 * Converts JSON formatted trusted setup into the native format that
 * the native library requires.  Returns the absolute file path to the
 * the formatted file.  The path will be the same as the origin
 * file but with a ".txt" extension.
 *
 * @param {string} filePath - The absolute path of JSON formatted trusted setup
 *
 * @return {string} - The absolute path of the re-formatted trusted setup
 *
 * @throws {Error} - For invalid file operations
 */
function transformTrustedSetupJson(filePath) {
  const trustedSetup = JSON.parse(fs.readFileSync(filePath, "utf8"));
  const setupText =
    bindings.FIELD_ELEMENTS_PER_BLOB +
    "\n65\n" +
    trustedSetup.setup_G1.map((p) => p.substring(2)).join("\n") +
    "\n" +
    trustedSetup.setup_G2.map((p) => p.substring(2)).join("\n");
  const outputPath = filePath.replace(".json", ".txt");
  // QUESTION: is this safe to write to an os temp directory?
  // const outputPath = path.resolve(
  //   os.tmpdir(),
  //   path.parse(filePath).name + ".txt",
  // );
  fs.writeFileSync(outputPath, setupText);
  return outputPath;
}

// docstring in ./kzg.d.ts with exported definition
const loadTrustedSetup = (filePath) => {
  if (!(filePath && typeof filePath === "string")) {
    throw new TypeError(
      "must initialize kzg with the filePath to a txt/json trusted setup",
    );
  }
  if (!fs.existsSync(filePath)) {
    throw new Error(`no trusted setup found: ${filePath}`);
  }
  if (path.parse(filePath).ext === ".json") {
    filePath = transformTrustedSetupJson(filePath);
  }
  bindings.loadTrustedSetup(filePath);
  return bindings;
};

/**
 * Add bindings constants to function object as a helper.  don't have to run trusted
 * setup to get to them;
 */
loadTrustedSetup.BYTES_PER_BLOB = bindings.BYTES_PER_BLOB;
loadTrustedSetup.BYTES_PER_COMMITMENT = bindings.BYTES_PER_COMMITMENT;
loadTrustedSetup.BYTES_PER_FIELD_ELEMENT = bindings.BYTES_PER_FIELD_ELEMENT;
loadTrustedSetup.BYTES_PER_PROOF = bindings.BYTES_PER_PROOF;
loadTrustedSetup.FIELD_ELEMENTS_PER_BLOB = bindings.FIELD_ELEMENTS_PER_BLOB;

module.exports = exports = loadTrustedSetup;
