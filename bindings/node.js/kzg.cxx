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

  auto blob_param = info[0].As<Napi::TypedArray>();
  if (!blob_param.IsTypedArray() || blob_param.TypedArrayType() != napi_uint8_array) {
     return throw_invalid_argument_type(env, "blob", "UInt8Array");
  }
  auto blob = blob_param.As<Napi::Uint8Array>().Data();

  auto kzg_settings = info[1].As<Napi::External<KZGSettings>>().Data();

  KZGCommitment commitment;
  blob_to_kzg_commitment(&commitment, blob, kzg_settings);

  uint8_t commitment_bytes[BYTES_PER_COMMITMENT];
  bytes_from_g1(commitment_bytes, &commitment);
  return napi_typed_array_from_bytes(commitment_bytes, BYTES_PER_COMMITMENT, env);
}

// computeAggregateKzgProof: (blobs: Blob[], setupHandle: SetupHandle) => KZGProof;
Napi::Value ComputeAggregateKzgProof(const Napi::CallbackInfo& info) {
  auto env = info.Env();

  size_t argument_count = info.Length();
  size_t expected_argument_count = 2;
  if (argument_count != expected_argument_count) {
    return throw_invalid_arguments_count(expected_argument_count, argument_count, env);
  }

  auto blobs_param = info[0].As<Napi::Array>();
  auto kzg_settings = info[1].As<Napi::External<KZGSettings>>().Data();

  auto blobs_count = blobs_param.Length();

  auto blobs = (Blob*)calloc(blobs_count, sizeof(Blob));

  for (uint32_t blob_index = 0; blob_index < blobs_count; blob_index++) {
    Napi::Value blob = blobs_param[blob_index];
    auto blob_bytes = blob.As<Napi::Uint8Array>().Data();
    memcpy(blobs[blob_index], blob_bytes, BYTES_PER_BLOB);
  }

  KZGProof proof;
  C_KZG_RET ret = compute_aggregate_kzg_proof(
    &proof,
    blobs,
    blobs_count,
    kzg_settings
  );
  free(blobs);

  if (ret != C_KZG_OK) {
     Napi::Error::New(env, "Failed to compute proof")
      .ThrowAsJavaScriptException();
    return env.Undefined();
  };

  uint8_t proof_bytes[BYTES_PER_PROOF];
  bytes_from_g1(proof_bytes, &proof);
  return napi_typed_array_from_bytes(proof_bytes, BYTES_PER_PROOF, env);
}

// verifyAggregateKzgProof: (blobs: Blob[], expectedKzgCommitments: KZGCommitment[], kzgAggregatedProof: KZGProof, setupHandle: SetupHandle) => boolean;
Napi::Value VerifyAggregateKzgProof(const Napi::CallbackInfo& info) {
  auto env = info.Env();

  size_t argument_count = info.Length();
  size_t expected_argument_count = 4;
  if (argument_count != expected_argument_count) {
    return throw_invalid_arguments_count(expected_argument_count, argument_count, env);
  }

  auto blobs_param = info[0].As<Napi::Array>();
  auto comittments_param = info[1].As<Napi::Array>();
  auto proof_param = info[2].As<Napi::TypedArray>();
  auto kzg_settings = info[3].As<Napi::External<KZGSettings>>().Data();

  auto proof_bytes = proof_param.As<Napi::Uint8Array>().Data();
  auto blobs_count = blobs_param.Length();

  auto blobs = (Blob*)calloc(blobs_count, sizeof(Blob));
  auto commitments = (KZGCommitment*)calloc(blobs_count, sizeof(KZGCommitment));

  C_KZG_RET ret;

  for (uint32_t blob_index = 0; blob_index < blobs_count; blob_index++) {
    // Extract blob bytes from parameter
    Napi::Value blob = blobs_param[blob_index];
    auto blob_bytes = blob.As<Napi::Uint8Array>().Data();

    memcpy(blobs[blob_index], blob_bytes, BYTES_PER_BLOB);

    // Extract a G1 point for each commitment
    Napi::Value commitment = comittments_param[blob_index];
    auto commitment_bytes = commitment.As<Napi::Uint8Array>().Data();

    ret = bytes_to_g1(&commitments[blob_index], commitment_bytes);
    if (ret != C_KZG_OK) {
      std::ostringstream ss;
      std::copy(commitment_bytes, commitment_bytes + BYTES_PER_COMMITMENT, std::ostream_iterator<int>(ss, ","));

      Napi::TypeError::New(
        env,
        "Invalid commitment data"
      ).ThrowAsJavaScriptException();

      free(commitments);
      free(blobs);

      return env.Null();
    }
  }

  KZGProof proof;
  ret = bytes_to_g1(&proof, proof_bytes);
  if (ret != C_KZG_OK) {
    free(commitments);
    free(blobs);

    Napi::Error::New(env, "Invalid proof data")
      .ThrowAsJavaScriptException();
    return env.Null();
  }

  bool verification_result;
  ret = verify_aggregate_kzg_proof(
    &verification_result,
    blobs,
    commitments,
    blobs_count,
    &proof,
    kzg_settings
  );

  free(commitments);
  free(blobs);

  if (ret != C_KZG_OK) {
    Napi::Error::New(
      env,
      "verify_aggregate_kzg_proof failed with error code: " + std::to_string(ret)
    ).ThrowAsJavaScriptException();
    return env.Null();
  }

  return Napi::Boolean::New(env, verification_result);
}

// verifyKzgProof: (polynomialKzg: KZGCommitment, z: BLSFieldElement, y: BLSFieldElement, kzgProof: KZGProof, setupHandle: SetupHandle) => boolean;
Napi::Value VerifyKzgProof(const Napi::CallbackInfo& info) {
  auto env = info.Env();

  size_t argument_count = info.Length();
  size_t expected_argument_count = 5;
  if (argument_count != expected_argument_count) {
    return throw_invalid_arguments_count(expected_argument_count, argument_count, env);
  }

  auto c_param = info[0].As<Napi::TypedArray>();
  if (c_param.TypedArrayType() != napi_uint8_array) {
    return throw_invalid_argument_type(env, "polynomialKzg", "UInt8Array");
  }
  auto polynomial_kzg = c_param.As<Napi::Uint8Array>().Data();

  auto z_param = info[1].As<Napi::TypedArray>();
  if (z_param.TypedArrayType() != napi_uint8_array) {
     return throw_invalid_argument_type(env, "z", "UInt8Array");
  }
  auto z = z_param.As<Napi::Uint8Array>().Data();

  auto y_param = info[2].As<Napi::TypedArray>();
  if (y_param.TypedArrayType() != napi_uint8_array) {
    return throw_invalid_argument_type(env, "y", "UInt8Array");
  }
  auto y = y_param.As<Napi::Uint8Array>().Data();

  auto proof_param = info[3].As<Napi::TypedArray>();
  if (proof_param.TypedArrayType() != napi_uint8_array) {
     return throw_invalid_argument_type(env, "kzgProof", "UInt8Array");
  }
  auto kzg_proof = proof_param.As<Napi::Uint8Array>().Data();

  auto kzg_settings = info[4].As<Napi::External<KZGSettings>>().Data();

  KZGCommitment commitment;
  auto ret = bytes_to_g1(&commitment, polynomial_kzg);
  if (ret != C_KZG_OK) {
    std::ostringstream ss;
    std::copy(polynomial_kzg, polynomial_kzg + BYTES_PER_COMMITMENT, std::ostream_iterator<int>(ss, ","));

    Napi::TypeError::New(env, "Failed to parse argument commitment: "  + ss.str() + " Return code was: " + std::to_string(ret)).ThrowAsJavaScriptException();
    return env.Null();
  };

  KZGProof proof;
  if (bytes_to_g1(&proof, kzg_proof) != C_KZG_OK) {
    Napi::TypeError::New(env, "Invalid kzgProof").ThrowAsJavaScriptException();
    return env.Null();
  }

  bool out;
  if (verify_kzg_proof(&out, &commitment, z, y, &proof, kzg_settings) != C_KZG_OK) {
    Napi::TypeError::New(env, "Failed to verify KZG proof").ThrowAsJavaScriptException();
    return env.Null();
  }

  return Napi::Boolean::New(env, out);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  // Functions
  exports["loadTrustedSetup"] = Napi::Function::New(env, LoadTrustedSetup);
  exports["freeTrustedSetup"] = Napi::Function::New(env, FreeTrustedSetup);
  exports["verifyKzgProof"] = Napi::Function::New(env, VerifyKzgProof);
  exports["blobToKzgCommitment"] = Napi::Function::New(env, BlobToKzgCommitment);
  exports["computeAggregateKzgProof"] = Napi::Function::New(env, ComputeAggregateKzgProof);
  exports["verifyAggregateKzgProof"] = Napi::Function::New(env, VerifyAggregateKzgProof);

  // Constants
  exports["FIELD_ELEMENTS_PER_BLOB"] = Napi::Number::New(env, FIELD_ELEMENTS_PER_BLOB);
  exports["BYTES_PER_FIELD_ELEMENT"] = Napi::Number::New(env, BYTES_PER_FIELD_ELEMENT);

  return exports;
}

NODE_API_MODULE(addon, Init)
