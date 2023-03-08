#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sstream>  // std::ostringstream
#include <algorithm> // std::copy
#include <iterator> // std::ostream_iterator
#include <string_view>
#include <napi.h>
#include "c_kzg_4844.h"
#include "blst.h"

Napi::Value throw_invalid_arguments_count(
  const unsigned int expected,
  const unsigned int actual,
  const Napi::Env env
) {
  Napi::RangeError::New(
    env,
    "Wrong number of arguments. Expected: "
    + std::to_string(expected)
    + ", received " + std::to_string(actual)
  ).ThrowAsJavaScriptException();

  return env.Null();
}

Napi::Value throw_invalid_argument_type(const Napi::Env env, std::string name, std::string expectedType) {
  Napi::TypeError::New(
    env,
    "Invalid argument type: " + name + ". Expected " + expectedType
  ).ThrowAsJavaScriptException();

  return env.Null();
}

/**
 * Get kzg_settings from a Napi::External
 * 
 * Checks for:
 * - arg IsExternal
 * 
 * Built to pass in a raw Napi::Value so it can be used like
 * `get_kzg_settings(env, info[0])`.
 * 
 * Designed to raise the correct javascript exception and return a
 * valid pointer to the calling context to avoid native stack-frame
 * unwinds.  Calling context can check for `nullptr` to see if an
 * exception was raised or a valid pointer was returned from V8.
 * 
 * @param[in] env    Passed from calling context
 * @param[in] val    Napi::Value to validate and get pointer from
 * 
 * @return - Pointer to the KZGSettings
 */
KZGSettings *get_kzg_settings(const Napi::Env &env, const Napi::Value &val) {
  if (!val.IsExternal()) {
     Napi::TypeError::New(env, "Must pass setupHandle as the last function argument").ThrowAsJavaScriptException();
     return nullptr;
  }
  return val.As<Napi::External<KZGSettings>>().Data();
}

/**
 * Checks for:
 * - arg is Uint8Array or Buffer (inherits from Uint8Array)
 * - underlying ArrayBuffer length is correct
 * 
 * Internal function for argument validation. Prefer to use
 * the helpers below that already have the reinterpreted casts:
 * - get_blob
 * - get_bytes32
 * - get_bytes48
 * 
 * Built to pass in a raw Napi::Value so it can be used like
 * `get_bytes(env, info[0])` or can also be used to pull props from
 * arrays like `get_bytes(env, passed_napi_array[2])`.
 * 
 * Designed to raise the correct javascript exception and return a
 * valid pointer to the calling context to avoid native stack-frame
 * unwinds.  Calling context can check for `nullptr` to see if an
 * exception was raised or a valid pointer was returned from V8.
 * 
 * @param[in] env    Passed from calling context
 * @param[in] val    Napi::Value to validate and get pointer from
 * @param[in] length Byte length to validate Uint8Array data against
 * @param[in] name   Name of prop being validated for error reporting
 * 
 * @return - native pointer to first byte in ArrayBuffer
 */
inline uint8_t *get_bytes(
    const Napi::Env &env,
    const Napi::Value &val,
    size_t length,
    std::string_view name)
{
  if (!val.IsTypedArray() || val.As<Napi::TypedArray>().TypedArrayType() != napi_uint8_array) {
    std::ostringstream msg;
    msg << "Expected " << name << " to be a Uint8Array";
    Napi::TypeError::New(env, msg.str()).ThrowAsJavaScriptException();
    return nullptr;
  }
  Napi::Uint8Array array = val.As<Napi::Uint8Array>();
  if (array.ByteLength() != length) {
    std::ostringstream msg;
    msg << "Expected " << name << " to be " << length << " bytes";
    Napi::TypeError::New(env, msg.str()).ThrowAsJavaScriptException();
    return nullptr;
  }
  return array.Data();
}
inline Blob *get_blob(const Napi::Env &env, const Napi::Value &val) {
  return reinterpret_cast<Blob *>(get_bytes(env, val, BYTES_PER_BLOB, "blob"));
}
inline Bytes32 *get_bytes32(const Napi::Env &env, const Napi::Value &val, std::string_view name) {
  return reinterpret_cast<Bytes32 *>(get_bytes(env, val, BYTES_PER_FIELD_ELEMENT, name));
}
inline Bytes48 *get_bytes48(const Napi::Env &env, const Napi::Value &val, std::string_view name) {
  return reinterpret_cast<Bytes48 *>(get_bytes(env, val, BYTES_PER_COMMITMENT, name));
}

// loadTrustedSetup: (filePath: string) => SetupHandle;
Napi::Value LoadTrustedSetup(const Napi::CallbackInfo& info) {
  auto env = info.Env();

  size_t argument_count = info.Length();
  size_t expected_argument_count = 1;
  if (argument_count != expected_argument_count) {
    return throw_invalid_arguments_count(expected_argument_count, argument_count, env);
  }

  if (!info[0].IsString()) {
    return throw_invalid_argument_type(env, "filePath", "string");
  }

  const std::string file_path = info[0].ToString().Utf8Value();

  KZGSettings* kzg_settings = (KZGSettings*)malloc(sizeof(KZGSettings));

  if (kzg_settings == NULL) {
    Napi::Error::New(env, "Error while allocating memory for KZG settings").ThrowAsJavaScriptException();
    return env.Null();
  }

  FILE* f = fopen(file_path.c_str(), "r");

  if (f == NULL) {
    free(kzg_settings);
    Napi::Error::New(env, "Error opening trusted setup file: " + file_path).ThrowAsJavaScriptException();
    return env.Null();
  }

  if (load_trusted_setup_file(kzg_settings, f) != C_KZG_OK) {
    free(kzg_settings);
    Napi::Error::New(env, "Error loading trusted setup file").ThrowAsJavaScriptException();
    return env.Null();
  }

  return Napi::External<KZGSettings>::New(info.Env(), kzg_settings);
}

// freeTrustedSetup: (setupHandle: SetupHandle) => void;
Napi::Value FreeTrustedSetup(const Napi::CallbackInfo& info) {
  auto env = info.Env();

  size_t argument_count = info.Length();
  size_t expected_argument_count = 1;
  if (argument_count != expected_argument_count) {
    return throw_invalid_arguments_count(expected_argument_count, argument_count, env);
  }
  KZGSettings *kzg_settings = get_kzg_settings(env, info[0]);
  if (kzg_settings == nullptr) {
    return env.Null();
  }

  free_trusted_setup(kzg_settings);
  free(kzg_settings);
  return env.Undefined();
}

/**
 * Convert a blob to a KZG commitment.
 *
 * @param[in] {Blob} blob - The blob representing the polynomial to be committed to
 *
 * @return {KZGCommitment} - The resulting commitment
 *
 * @throws {TypeError} - For invalid arguments or failure of the native library
 */
Napi::Value BlobToKzgCommitment(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  size_t argument_count = info.Length();
  size_t expected_argument_count = 2;
  if (argument_count != expected_argument_count) {
    return throw_invalid_arguments_count(expected_argument_count, argument_count, env);
  }
  Blob *blob = get_blob(env, info[0]);
  if (blob == nullptr) {
    return env.Null();
  }
  KZGSettings *kzg_settings = get_kzg_settings(env, info[1]);
  if (kzg_settings == nullptr) {
    return env.Null();
  }

  KZGCommitment commitment;
  C_KZG_RET ret = blob_to_kzg_commitment(&commitment, blob, kzg_settings);
  if (ret != C_KZG_OK) {
     Napi::Error::New(env, "Failed to convert blob to commitment")
      .ThrowAsJavaScriptException();
    return env.Null();
  }

  return Napi::Buffer<uint8_t>::Copy(env, reinterpret_cast<uint8_t *>(&commitment), BYTES_PER_COMMITMENT);
}

/**
 * Compute KZG proof for polynomial in Lagrange form at position z.
 *
 * @param[in] {Blob}    blob - The blob (polynomial) to generate a proof for
 * @param[in] {Bytes32} zBytes - The generator z-value for the evaluation points
 * 
 * @return {ComputationProof} - Tuple containing the resulting proof and evaluation
 *                              of the polynomial at the evaluation point z
 *
 * @throws {TypeError} - for invalid arguments or failure of the native library
 */
Napi::Value ComputeKzgProof(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  size_t argument_count = info.Length();
  size_t expected_argument_count = 3;
  if (argument_count != expected_argument_count) {
    return throw_invalid_arguments_count(expected_argument_count, argument_count, env);
  }
  Blob *blob = get_blob(env, info[0]);
  if (blob == nullptr) {
    return env.Null();
  }
  Bytes32 *z_bytes = get_bytes32(env, info[1], "zBytes");
  if (z_bytes == nullptr) {
    return env.Null();
  }
  KZGSettings *kzg_settings = get_kzg_settings(env, info[2]);
  if (kzg_settings == nullptr) {
    return env.Null();
  }

  KZGProof proof;
  Bytes32 y_out;
  C_KZG_RET ret = compute_kzg_proof(
    &proof,
    &y_out,
    blob,
    z_bytes,
    kzg_settings
  );

  if (ret != C_KZG_OK) {
     Napi::Error::New(env, "Failed to compute proof")
      .ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Array tuple = Napi::Array::New(env, 2);
  tuple[(uint32_t)0] = Napi::Buffer<uint8_t>::Copy(env, reinterpret_cast<uint8_t *>(&proof), BYTES_PER_PROOF);
  tuple[(uint32_t)1] = Napi::Buffer<uint8_t>::Copy(env, reinterpret_cast<uint8_t *>(&y_out), BYTES_PER_FIELD_ELEMENT);
  return tuple;
}


/**
 * Given a blob, return the KZG proof that is used to verify it against the
 * commitment.
 * 
 * @param[in] {Blob}    blob - The blob (polynomial) to generate a proof for
 * @param[in] {Bytes48} commitmentBytes - Commitment to verify
 * 
 * @return {KZGProof} - The resulting proof
 *
 * @throws {TypeError} - for invalid arguments or failure of the native library
 */
Napi::Value ComputeBlobKzgProof(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  size_t argument_count = info.Length();
  size_t expected_argument_count = 3;
  if (argument_count != expected_argument_count) {
    return throw_invalid_arguments_count(expected_argument_count, argument_count, env);
  }
  Blob *blob = get_blob(env, info[0]);
  if (blob == nullptr) {
    return env.Null();
  }
  Bytes48 *commitment_bytes = get_bytes48(env, info[1], "commitmentBytes");
  if (commitment_bytes == nullptr) {
    return env.Null();
  }
  KZGSettings *kzg_settings = get_kzg_settings(env, info[2]);
  if (kzg_settings == nullptr) {
    return env.Null();
  }

  KZGProof proof;
  C_KZG_RET ret = compute_blob_kzg_proof(
    &proof,
    blob,
    commitment_bytes,
    kzg_settings
  );

  if (ret != C_KZG_OK) {
     Napi::Error::New(env, "Error in computeBlobKzgProof")
      .ThrowAsJavaScriptException();
    return env.Null();
  }

  return Napi::Buffer<uint8_t>::Copy(env, reinterpret_cast<uint8_t *>(&proof), BYTES_PER_PROOF);
}

/**
 * Verify a KZG poof claiming that `p(z) == y`.
 * 
 * @param[in] {Bytes48} commitmentBytes - The serialized commitment corresponding to polynomial p(x)
 * @param[in] {Bytes32} zBytes - The serialized evaluation point 
 * @param[in] {Bytes32} yBytes - The serialized claimed evaluation result
 * @param[in] {Bytes48} proofBytes - The serialized KZG proof
 * 
 * @return {boolean} - true/false depending on proof validity
 * 
 * @throws {TypeError} - for invalid arguments or failure of the native library
 */
Napi::Value VerifyKzgProof(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  size_t argument_count = info.Length();
  size_t expected_argument_count = 5;
  if (argument_count != expected_argument_count) {
    return throw_invalid_arguments_count(expected_argument_count, argument_count, env);
  }
  Bytes48 *commitment_bytes = get_bytes48(env, info[0], "commitmentBytes");
  if (commitment_bytes == nullptr) {
    return env.Null();
  }
  Bytes32 *z_bytes = get_bytes32(env, info[1], "zBytes");
  if (z_bytes == nullptr) {
    return env.Null();
  }
  Bytes32 *y_bytes = get_bytes32(env, info[2], "yBytes");
  if (y_bytes == nullptr) {
    return env.Null();
  }
  Bytes48 *proof_bytes = get_bytes48(env, info[3], "proofBytes");
  if (proof_bytes == nullptr) {
    return env.Null();
  }
  KZGSettings *kzg_settings = get_kzg_settings(env, info[4]);
  if (kzg_settings == nullptr) {
    return env.Null();
  }

  bool out;
  C_KZG_RET ret = verify_kzg_proof(
    &out,
    commitment_bytes,
    z_bytes,
    y_bytes,
    proof_bytes,
    kzg_settings
  );

  if (ret != C_KZG_OK) {
    Napi::TypeError::New(env, "Failed to verify KZG proof").ThrowAsJavaScriptException();
    return env.Null();
  }

  return Napi::Boolean::New(env, out);
}

/**
 * Given a blob and its proof, verify that it corresponds to the provided
 * commitment.
 * 
 * @param[in] {Blob}    blob - The serialized blob to verify
 * @param[in] {Bytes48} commitmentBytes - The serialized commitment to verify
 * @param[in] {Bytes48} proofBytes - The serialized KZG proof for verification
 * 
 * @return {boolean} - true/false depending on proof validity
 * 
 * @throws {TypeError} - for invalid arguments or failure of the native library
 */
Napi::Value VerifyBlobKzgProof(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  size_t argument_count = info.Length();
  size_t expected_argument_count = 4;
  if (argument_count != expected_argument_count) {
    return throw_invalid_arguments_count(expected_argument_count, argument_count, env);
  }
  Blob *blob_bytes = get_blob(env, info[0]);
  if (blob_bytes == nullptr) {
    return env.Null();
  }
  Bytes48 *commitment_bytes = get_bytes48(env, info[1], "commitmentBytes");
  if (commitment_bytes == nullptr) {
    return env.Null();
  }
  Bytes48 *proof_bytes = get_bytes48(env, info[2], "proofBytes");
  if (proof_bytes == nullptr) {
    return env.Null();
  }
  KZGSettings *kzg_settings = get_kzg_settings(env, info[3]);
  if (kzg_settings == nullptr) {
    return env.Null();
  }
  
  bool out;
  C_KZG_RET ret = verify_blob_kzg_proof(
    &out,
    blob_bytes,
    commitment_bytes,
    proof_bytes,
    kzg_settings);

  if (ret != C_KZG_OK) {
    Napi::TypeError::New(env, "Error in verifyBlobKzgProof").ThrowAsJavaScriptException();
    return env.Null();
  }

  return Napi::Boolean::New(env, out);
}

/**
 * Given an array of blobs and their proofs, verify that they corresponds to their
 * provided commitment.
 * 
 * @remark blobs[0] relates to commitmentBytes[0] and proofBytes[0]
 * 
 * @param[in] {Blob}    blobs - An array of serialized blobs to verify
 * @param[in] {Bytes48} commitmentBytes - An array of serialized commitments to verify
 * @param[in] {Bytes48} proofBytes - An array of serialized KZG proofs for verification
 * 
 * @return {boolean} - true/false depending on batch validity
 * 
 * @throws {TypeError} - for invalid arguments or failure of the native library
 */
Napi::Value VerifyBlobKzgProofBatch(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  size_t argument_count = info.Length();
  size_t expected_argument_count = 4;
  if (argument_count != expected_argument_count) {
    return throw_invalid_arguments_count(expected_argument_count, argument_count, env);
  }
  C_KZG_RET ret;
  Blob *blobs = NULL;
  Bytes48 *commitments = NULL;
  Bytes48 *proofs = NULL;
  Napi::Value result = env.Null();
  if (!(info[0].IsArray() && info[1].IsArray() && info[2].IsArray())) {
    Napi::Error::New(env, "blobs, commitments, and proofs must all be arrays").ThrowAsJavaScriptException();
    return result;
  }
  Napi::Array blobs_param = info[0].As<Napi::Array>();
  Napi::Array commitments_param = info[1].As<Napi::Array>();
  Napi::Array proofs_param = info[2].As<Napi::Array>();
  KZGSettings *kzg_settings = get_kzg_settings(env, info[3]);
  if (kzg_settings == nullptr) {
    return env.Null();
  }
  uint32_t count = blobs_param.Length();
  if (count != commitments_param.Length() || count != proofs_param.Length()) {
    Napi::Error::New(env, "requires equal number of blobs/commitments/proofs").ThrowAsJavaScriptException();
    return result;
  }
  blobs = (Blob *)calloc(count, sizeof(Blob));
  if (blobs == nullptr) {
    Napi::Error::New(env, "Error while allocating memory for blobs").ThrowAsJavaScriptException();
    goto out;
  }
  commitments = (Bytes48 *)calloc(count, sizeof(Bytes48));
  if (commitments == nullptr) {
    Napi::Error::New(env, "Error while allocating memory for commitments").ThrowAsJavaScriptException();
    goto out;
  }
  proofs = (Bytes48 *)calloc(count, sizeof(Bytes48));
  if (proofs == nullptr) {
    Napi::Error::New(env, "Error while allocating memory for proofs").ThrowAsJavaScriptException();
    goto out;
  }

  for (uint32_t index = 0; index < count; index++) {
    // add HandleScope here to release reference to temp values
    // after each iteration since data is being memcpy
    Napi::HandleScope scope{env};
    Blob *blob = get_blob(env, blobs_param[index]);
    if (blob == nullptr) {
      goto out;
    }
    memcpy(&blobs[index], blob, BYTES_PER_BLOB);
    Bytes48 *commitment = get_bytes48(env, commitments_param[index], "commitmentBytes");
    if (commitment == nullptr) {
      goto out;
    }
    memcpy(&commitments[index], commitment, BYTES_PER_COMMITMENT);
    Bytes48 *proof = get_bytes48(env, proofs_param[index], "proofBytes");
    if (proof == nullptr) {
      goto out;
    }
    memcpy(&proofs[index], proof, BYTES_PER_PROOF);
  }

  bool out;
  ret = verify_blob_kzg_proof_batch(
    &out,
    blobs,
    commitments,
    proofs,
    count,
    kzg_settings
  );

  if (ret != C_KZG_OK) {
    Napi::TypeError::New(env, "Error in verifyBlobKzgProofBatch").ThrowAsJavaScriptException();
    goto out;
  }

  result = Napi::Boolean::New(env, out);

out:
  free(blobs);
  free(commitments);
  free(proofs);
  return result;
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  // Functions
  exports["loadTrustedSetup"] = Napi::Function::New(env, LoadTrustedSetup);
  exports["freeTrustedSetup"] = Napi::Function::New(env, FreeTrustedSetup);
  exports["blobToKzgCommitment"] = Napi::Function::New(env, BlobToKzgCommitment);
  exports["computeKzgProof"] = Napi::Function::New(env, ComputeKzgProof);
  exports["computeBlobKzgProof"] = Napi::Function::New(env, ComputeBlobKzgProof);
  exports["verifyKzgProof"] = Napi::Function::New(env, VerifyKzgProof);
  exports["verifyBlobKzgProof"] = Napi::Function::New(env, VerifyBlobKzgProof);
  exports["verifyBlobKzgProofBatch"] = Napi::Function::New(env, VerifyBlobKzgProofBatch);

  // Constants
  exports["BYTES_PER_BLOB"] = Napi::Number::New(env, BYTES_PER_BLOB);
  exports["BYTES_PER_COMMITMENT"] = Napi::Number::New(env, BYTES_PER_COMMITMENT);
  exports["BYTES_PER_FIELD_ELEMENT"] = Napi::Number::New(env, BYTES_PER_FIELD_ELEMENT);
  exports["BYTES_PER_PROOF"] = Napi::Number::New(env, BYTES_PER_PROOF);
  exports["FIELD_ELEMENTS_PER_BLOB"] = Napi::Number::New(env, FIELD_ELEMENTS_PER_BLOB);

  return exports;
}

NODE_API_MODULE(addon, Init)
