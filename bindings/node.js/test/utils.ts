import { randomBytes } from "crypto";

export function getBytes(file: String): Uint8Array {
  const data = require("fs").readFileSync(file, "ascii");
  return Buffer.from(data, "hex");
}

export function getBoolean(file: String): boolean {
  const data = require("fs").readFileSync(file, "ascii");
  return data.includes("true");
}

export function generateRandomBlob() {
  return new Uint8Array(
    randomBytes(BYTES_PER_BLOB).map((x, i) => {
      // Set the top byte to be low enough that the field element doesn't overflow the BLS modulus
      if (x > MAX_TOP_BYTE && i % BYTES_PER_FIELD_ELEMENT == 31) {
        return Math.floor(Math.random() * MAX_TOP_BYTE);
      }
      return x;
    })
  );
};
