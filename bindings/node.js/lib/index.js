/**
 * The public interface of this module exposes the functions as specified by
 * https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/polynomial-commitments.md#kzg
 */
const path = require("path");
const os = require("os");
const fs = require("fs");
const bindings = require("bindings")("kzg_bindings");

/**
 * Converts JSON formatted trusted_setup into the native format that
 * the native library requires
 *
 * @param {string} filePath is the absolute path of trusted_setup.json
 * @returns {Promise<string>}
 */
async function transformTrustedSetupJson(filePath) {
  const data = await fs.promises.readFile(filePath, "utf8");
  const trustedSetup = JSON.parse(data);
  const outputPath = path.resolve(os.tmpdir(), path.parse(filePath).name + ".txt");
  const setupText =
    bindings.FIELD_ELEMENTS_PER_BLOB +
    "\n65\n" +
    trustedSetup.setup_G1.map((p) => p.substring(2)).join("\n") +
    "\n" +
    trustedSetup.setup_G2.map((p) => p.substring(2)).join("\n");
  await fs.promises.writeFile(outputPath, setupText);
  return outputPath;
}

module.exports = exports = {
  ...bindings,
  transformTrustedSetupJson,
};
