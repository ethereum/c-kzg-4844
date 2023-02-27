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

module.exports = exports = (filePath) => {
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
