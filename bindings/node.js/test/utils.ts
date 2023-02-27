import fs from "fs";
import {randomBytes} from "crypto";
import bindings, {KzgBindings} from "../lib";
import {TRUSTED_SETUP_JSON, MAX_TOP_BYTE} from "./constants";

let kzg: KzgBindings | undefined;
export function getBindings(): KzgBindings {
  if (!kzg) {
    kzg = bindings(TRUSTED_SETUP_JSON);
  }
  return kzg;
}

export function getBytes(file: string): Uint8Array {
  const data = fs.readFileSync(file, "ascii");
  return Buffer.from(data, "hex");
}

export function getBoolean(file: string): boolean {
  const data = fs.readFileSync(file, "ascii");
  return data.includes("true");
}

function generateRandomUint8Array(length: number): Uint8Array {
  const {BYTES_PER_FIELD_ELEMENT} = getBindings();
  return new Uint8Array(
    randomBytes(length).map((x, i) => {
      // Set the top byte to be low enough that the field element doesn't overflow the BLS modulus
      if (x > MAX_TOP_BYTE && i % BYTES_PER_FIELD_ELEMENT == 31) {
        return Math.floor(Math.random() * MAX_TOP_BYTE);
      }
      return x;
    })
  );
}
export function generateRandomBlob(): Uint8Array {
  const {BYTES_PER_BLOB} = getBindings();
  return generateRandomUint8Array(BYTES_PER_BLOB);
}
export function generateRandomCommitment(): Uint8Array {
  const {BYTES_PER_COMMITMENT} = getBindings();
  return generateRandomUint8Array(BYTES_PER_COMMITMENT);
}
export function generateRandomProof(): Uint8Array {
  const {BYTES_PER_PROOF} = getBindings();
  return generateRandomUint8Array(BYTES_PER_PROOF);
}
