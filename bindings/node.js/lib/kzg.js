/**
 * The public interface of this module exposes the functions as specified by
 * https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/polynomial-commitments.md#kzg
 */
const fs = require("fs");
const path = require("path");
const bindings = require("bindings")("kzg");

/**
 * Looks in the default locations for the trusted setup file.  This is for cases
 * where the library is loaded without passing a trusted setup.  Should only be
 * used for cases where the Ethereum official mainnet kzg setup is acceptable.
 *
 * @returns {string | undefined} - Filepath for trusted_setup.txt if found
 */
function getDefaultTrustedSetupFilepath() {
  const locationsToSearch = [
    // check the production bundle case first (this file in lib)
    path.resolve(__dirname, "..", "deps", "c-kzg", "trusted_setup.txt"),
    // check the development in-repo case second (this file in bindings/node.js/lib)
    path.resolve(__dirname, "..", "..", "..", "src", "trusted_setup.txt"),
  ];

  for (const filepath of locationsToSearch) {
    if (fs.existsSync(filepath)) {
      return filepath;
    }
  }
}

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

/**
 * Gets location for trusted setup file. Uses user provided location first. If
 * one is not provided then defaults to the official Ethereum mainnet setup from
 * the kzg ceremony.
 *
 * @param {string} filePath - User provided filePath to check for trusted setup
 *
 * @returns {string} - Location of a trusted setup file. Validity is checked by
 *                     the native bindings.loadTrustedSetup
 *
 * @throws {TypeError} - Invalid file type
 * @throws {Error} - Invalid location or no default trusted setup found
 *
 * @remarks - This function is only exported for testing purposes.  It should
 *            not be used directly. Not included in the kzg.d.ts types for that
 *            reason.
 */
bindings.getTrustedSetupFilepath = function getTrustedSetupFilepath(filePath) {
  if (filePath) {
    if (typeof filePath !== "string") {
      throw new TypeError("Must initialize kzg with the filePath to a txt/json trusted setup");
    }
    if (!fs.existsSync(filePath)) {
      throw new Error(`No trusted setup found: ${filePath}`);
    }
  } else {
    filePath = getDefaultTrustedSetupFilepath();
    if (!filePath) {
      throw new Error("Default trusted setup not found. Must pass a valid filepath to load c-kzg library");
    }
  }

  if (path.parse(filePath).ext === ".json") {
    filePath = transformTrustedSetupJson(filePath);
  }

  return filePath;
};

const originalLoadTrustedSetup = bindings.loadTrustedSetup;
// docstring in ./kzg.d.ts with exported definition
bindings.loadTrustedSetup = function loadTrustedSetup(filePath) {
  originalLoadTrustedSetup(bindings.getTrustedSetupFilepath(filePath));
};

module.exports = exports = bindings;
