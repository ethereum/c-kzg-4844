#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sstream>  // std::ostringstream
#include <algorithm> // std::copy
#include <iterator> // std::ostream_iterator
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

Napi::TypedArrayOf<uint8_t> napi_typed_array_from_bytes(uint8_t* array, size_t length, Napi::Env env) {
  // Create std::vector<uint8_t> out of array.
  // We allocate it on the heap to allow wrapping it up into ArrayBuffer.
  std::unique_ptr<std::vector<uint8_t>> vector =
      std::make_unique<std::vector<uint8_t>>(length, 0);

  for (size_t i = 0; i < length; ++i) {
    (*vector)[i] = array[i];
  }

  // Wrap up the std::vector into the ArrayBuffer.
  Napi::ArrayBuffer buffer = Napi::ArrayBuffer::New(
      env,
      vector->data(),
      length /* size in bytes */,
      [](Napi::Env /*env*/, void* /*data*/, std::vector<uint8_t>* hint) {
        std::unique_ptr<std::vector<uint8_t>> vectorPtrToDelete(hint);
      },
      vector.get());

  // The finalizer is responsible for deleting the vector: release the
  // unique_ptr ownership.
  vector.release();

  return Napi::Uint8Array::New(env, length, buffer, 0);
}

const uint8_t * extract_byte_array_from_param(const Napi::CallbackInfo& info, const int index, const std::string name) {
  auto param = info[index].As<Napi::TypedArray>();
  if (!param.IsTypedArray() || param.TypedArrayType() != napi_uint8_array) {
    throw_invalid_argument_type(info.Env(), name, "UInt8Array");
  }
  return param.As<Napi::Uint8Array>().Data();
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
  };

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

  auto kzg_settings = info[0].As<Napi::External<KZGSettings>>().Data();
  free_trusted_setup(kzg_settings);
  free(kzg_settings);
  return env.Undefined();
}

// blobToKzgCommitment: (blob: Blob, setupHandle: SetupHandle) => KZGCommitment;
Napi::Value BlobToKzgCommitment(const Napi::CallbackInfo& info) {
  auto env = info.Env();

  size_t argument_count = info.Length();
  size_t expected_argument_count = 2;
  if (argument_count != expected_argument_count) {
    return throw_invalid_arguments_count(expected_argument_count, argument_count, env);
  }

  Blob *blob = (Blob *)extract_byte_array_from_param(info, 0, "blob");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  auto kzg_settings = info[1].As<Napi::External<KZGSettings>>().Data();

  KZGCommitment commitment;
  C_KZG_RET ret = blob_to_kzg_commitment(&commitment, blob, kzg_settings);
  if (ret != C_KZG_OK) {
     Napi::Error::New(env, "Failed to convert blob to commitment")
      .ThrowAsJavaScriptException();
    return env.Undefined();
  };

  return napi_typed_array_from_bytes((uint8_t *)(&commitment), BYTES_PER_COMMITMENT, env);
}

// computeKzgProof: (blob: Blob, zBytes: Bytes32, setupHandle: SetupHandle) => KZGProof;
Napi::Value ComputeKzgProof(const Napi::CallbackInfo& info) {
  auto env = info.Env();

  size_t argument_count = info.Length();
  size_t expected_argument_count = 3;
  if (argument_count != expected_argument_count) {
    return throw_invalid_arguments_count(expected_argument_count, argument_count, env);
  }

  auto blob = extract_byte_array_from_param(info, 0, "blob");
  auto z_bytes = extract_byte_array_from_param(info, 1, "zBytes");
  auto kzg_settings = info[2].As<Napi::External<KZGSettings>>().Data();

  if (env.IsExceptionPending()) {
    return env.Null();
  }

  KZGProof proof;
  C_KZG_RET ret = compute_kzg_proof(
    &proof,
    (Blob *)blob,
    (Bytes32 *)z_bytes,
    kzg_settings
  );

  if (ret != C_KZG_OK) {
     Napi::Error::New(env, "Failed to compute proof")
      .ThrowAsJavaScriptException();
    return env.Undefined();
  };

  return napi_typed_array_from_bytes((uint8_t *)(&proof), BYTES_PER_PROOF, env);
}

// computeBlobKzgProof: (blob: Blob, setupHandle: SetupHandle) => KZGProof;
Napi::Value ComputeBlobKzgProof(const Napi::CallbackInfo& info) {
  auto env = info.Env();

  size_t argument_count = info.Length();
  size_t expected_argument_count = 2;
  if (argument_count != expected_argument_count) {
    return throw_invalid_arguments_count(expected_argument_count, argument_count, env);
  }

  auto blob = extract_byte_array_from_param(info, 0, "blob");
  auto kzg_settings = info[1].As<Napi::External<KZGSettings>>().Data();

  if (env.IsExceptionPending()) {
    return env.Null();
  }

  KZGProof proof;
  C_KZG_RET ret = compute_blob_kzg_proof(
    &proof,
    (Blob *)blob,
    kzg_settings
  );

  if (ret != C_KZG_OK) {
     Napi::Error::New(env, "Error in computeBlobKzgProof")
      .ThrowAsJavaScriptException();
    return env.Undefined();
  };

  return napi_typed_array_from_bytes((uint8_t *)(&proof), BYTES_PER_PROOF, env);
}

// verifyKzgProof: (commitmentBytes: Bytes48, zBytes: Bytes32, yBytes: Bytes32, proofBytes: Bytes48, setupHandle: SetupHandle) => boolean;
Napi::Value VerifyKzgProof(const Napi::CallbackInfo& info) {
  auto env = info.Env();

  size_t argument_count = info.Length();
  size_t expected_argument_count = 5;
  if (argument_count != expected_argument_count) {
    return throw_invalid_arguments_count(expected_argument_count, argument_count, env);
  }

  auto commitment_bytes = extract_byte_array_from_param(info, 0, "commitmentBytes");
  auto z_bytes = extract_byte_array_from_param(info, 1, "zBytes");
  auto y_bytes = extract_byte_array_from_param(info, 2, "yBytes");
  auto proof_bytes = extract_byte_array_from_param(info, 3, "proofBytes");
  auto kzg_settings = info[4].As<Napi::External<KZGSettings>>().Data();

  if (env.IsExceptionPending()) {
    return env.Null();
  }

  C_KZG_RET ret = verify_kzg_proof(
    (Bytes48 *)commitment_bytes,
    (Bytes32 *)z_bytes,
    (Bytes32 *)y_bytes,
    (Bytes48 *)proof_bytes,
    kzg_settings
  );

  if (ret == C_KZG_BAD_VERIFY) {
    return Napi::Boolean::New(env, false);
  }

  if (ret != C_KZG_OK) {
    Napi::TypeError::New(env, "Failed to verify KZG proof").ThrowAsJavaScriptException();
    return env.Null();
  }

  return Napi::Boolean::New(env, true);
}

// verifyBlobKzgProof: (blob: Blob, commitmentBytes: Bytes48, proofBytes: Bytes48, setupHandle: SetupHandle) => boolean;
Napi::Value VerifyBlobKzgProof(const Napi::CallbackInfo& info) {
  auto env = info.Env();

  size_t argument_count = info.Length();
  size_t expected_argument_count = 4;
  if (argument_count != expected_argument_count) {
    return throw_invalid_arguments_count(expected_argument_count, argument_count, env);
  }

  auto blob_bytes = extract_byte_array_from_param(info, 0, "blob");
  auto commitment_bytes = extract_byte_array_from_param(info, 1, "commitmentBytes");
  auto proof_bytes = extract_byte_array_from_param(info, 2, "proofBytes");
  auto kzg_settings = info[3].As<Napi::External<KZGSettings>>().Data();

  if (env.IsExceptionPending()) {
    return env.Null();
  }

  C_KZG_RET ret = verify_blob_kzg_proof(
    (Blob *)blob_bytes,
    (Bytes48 *)commitment_bytes,
    (Bytes48 *)proof_bytes,
    kzg_settings
  );

  if (ret == C_KZG_BAD_VERIFY) {
    return Napi::Boolean::New(env, false);
  }

  if (ret != C_KZG_OK) {
    Napi::TypeError::New(env, "Error in verifyBlobKzgProof").ThrowAsJavaScriptException();
    return env.Null();
  }

  return Napi::Boolean::New(env, true);
}

// verifyBlobKzgProofBatch: (blobs: Blob[], commitmentsBytes: Bytes48[], proofsBytes: Bytes48[], setupHandle: SetupHandle) => boolean;
Napi::Value VerifyBlobKzgProofBatch(const Napi::CallbackInfo& info) {
  auto env = info.Env();

  C_KZG_RET ret;
  Blob *blobs = NULL;
  Bytes48 *commitments = NULL;
  Bytes48 *proofs = NULL;
  Napi::Value result = env.Null();

  size_t argument_count = info.Length();
  size_t expected_argument_count = 4;
  if (argument_count != expected_argument_count) {
    return throw_invalid_arguments_count(expected_argument_count, argument_count, env);
  }

  auto blobs_param = info[0].As<Napi::Array>();
  auto commitments_param = info[1].As<Napi::Array>();
  auto proofs_param = info[2].As<Napi::Array>();
  auto kzg_settings = info[3].As<Napi::External<KZGSettings>>().Data();

  auto blobs_count = blobs_param.Length();
  auto commitments_count = commitments_param.Length();
  auto proofs_count = proofs_param.Length();

  if (blobs_count != commitments_count || blobs_count != proofs_count) {
    Napi::Error::New(env, "verifyBlobKzgProofBatch requires equal number of blobs/commitments/proofs")
      .ThrowAsJavaScriptException();
    result = env.Null();
    goto out;
  }

  blobs = (Blob *)calloc(blobs_count, sizeof(Blob));
   if (blobs == NULL) {
     Napi::Error::New(env, "Error while allocating memory for blobs").ThrowAsJavaScriptException();
     result = env.Null();
     goto out;
   };

   commitments = (Bytes48 *)calloc(commitments_count, sizeof(Bytes48));
   if (commitments == NULL) {
     free(blobs);
     Napi::Error::New(env, "Error while allocating memory for commitments").ThrowAsJavaScriptException();
     result = env.Null();
     goto out;
   };

   proofs = (Bytes48 *)calloc(proofs_count, sizeof(Bytes48));
   if (proofs == NULL) {
     Napi::Error::New(env, "Error while allocating memory for proofs").ThrowAsJavaScriptException();
     result = env.Null();
     goto out;
   };

  for (uint32_t index = 0; index < blobs_count; index++) {
    // Extract blob bytes from parameter
    Napi::Value blob = blobs_param[index];
    auto blob_bytes = blob.As<Napi::Uint8Array>().Data();
    memcpy(blobs[index].bytes, blob_bytes, BYTES_PER_BLOB);

    // Extract commitment from parameter
    Napi::Value commitment = commitments_param[index];
    auto commitment_bytes = commitment.As<Napi::Uint8Array>().Data();
    memcpy(&commitments[index], commitment_bytes, BYTES_PER_COMMITMENT);

    // Extract proof from parameter
    Napi::Value proof = proofs_param[index];
    auto proof_bytes = proof.As<Napi::Uint8Array>().Data();
    memcpy(&proofs[index], proof_bytes, BYTES_PER_PROOF);
  }

  ret = verify_blob_kzg_proof_batch(
    blobs,
    commitments,
    proofs,
    blobs_count,
    kzg_settings
  );

  if (ret == C_KZG_BAD_VERIFY) {
    return Napi::Boolean::New(env, false);
  }

  if (ret != C_KZG_OK) {
    Napi::TypeError::New(env, "Error in verifyBlobKzgProofBatch").ThrowAsJavaScriptException();
    result = env.Null();
    goto out;
  }

  result = Napi::Boolean::New(env, true);

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
