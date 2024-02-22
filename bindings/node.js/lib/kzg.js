/**
 * The public interface of this module exposes the functions as specified by
 * https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/polynomial-commitments.md#kzg
 */
const fs = require("fs");
const path = require("path");
const bindings = require("bindings")("kzg");

/**
 * Converts JSON formatted trusted setup into the native format that
 * the native library requires.  Returns the absolute file path to
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
    trustedSetup.g1_lagrange.map((p) => p.substring(2)).join("\n") +
    "\n" +
    trustedSetup.g2_monomial.map((p) => p.substring(2)).join("\n");
  const outputPath = filePath.replace(".json", ".txt");
  fs.writeFileSync(outputPath, setupText);
  return outputPath;
}

const originalLoadTrustedSetup = bindings.loadTrustedSetup;
// docstring in ./kzg.d.ts with exported definition
bindings.loadTrustedSetup = function loadTrustedSetup(filePath) {
  if (!(filePath && typeof filePath === "string")) {
    throw new TypeError("must initialize kzg with the filePath to a txt/json trusted setup");
  }
  if (!fs.existsSync(filePath)) {
    throw new Error(`no trusted setup found: ${filePath}`);
  }
  if (path.parse(filePath).ext === ".json") {
    filePath = transformTrustedSetupJson(filePath);
  }
  originalLoadTrustedSetup(filePath);
};

module.exports = exports = bindings;
