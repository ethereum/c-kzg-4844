#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#define NAPI_EXPERIMENTAL
#include <napi.h>
#include "c_kzg_4844.h"
#include "blst.h"

#include <sstream>  // std::ostringstream
#include <algorithm>    // std::copy
#include <iterator> // std::ostream_iterator

Napi::TypedArrayOf<uint8_t> napiTypedArrayFromByteArray(uint8_t* array, size_t arrayLength, Napi::Env env) {
  // Create std::vector<uint8_t> out of array.
  // We allocate it on the heap to allow wrapping it up into ArrayBuffer.
  std::unique_ptr<std::vector<uint8_t>> nativeArray =
      std::make_unique<std::vector<uint8_t>>(arrayLength, 0);

  for (size_t i = 0; i < arrayLength; ++i) {
    (*nativeArray)[i] = array[i];
  }

  // Wrap up the std::vector into the ArrayBuffer.
  Napi::ArrayBuffer arrayBuffer = Napi::ArrayBuffer::New(
      env,
      nativeArray->data(),
      arrayLength /* size in bytes */,
      [](Napi::Env /*env*/, void* /*data*/, std::vector<uint8_t>* hint) {
        std::unique_ptr<std::vector<uint8_t>> vectorPtrToDelete(hint);
      },
      nativeArray.get());

  // The finalizer is responsible for deleting the vector: release the
  // unique_ptr ownership.
  nativeArray.release();

  return Napi::Uint8Array::New(env, arrayLength, arrayBuffer, 0);
}

// loadTrustedSetup: (filePath: string) => SetupHandle;
Napi::Value LoadTrustedSetup(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() != 1) {
    Napi::TypeError::New(env, "Wrong number of arguments")
      .ThrowAsJavaScriptException();
    return env.Null();
  }

  if (!info[0].IsString()) {
    Napi::TypeError::New(env, "Wrong arguments").ThrowAsJavaScriptException();
    return env.Null();
  }

  const std::string filePath = info[0].ToString().Utf8Value();

  KZGSettings* kzgSettings = (KZGSettings*)malloc(sizeof(KZGSettings));

  if (kzgSettings == NULL) {
    Napi::TypeError::New(env, "Error while allocating memory for KZG settings").ThrowAsJavaScriptException();
    return env.Null();
  };

  FILE* f = fopen(filePath.c_str(), "r");

  if (f == NULL) {
    free(kzgSettings);
    Napi::TypeError::New(env, "Error opening trusted setup file").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (load_trusted_setup(kzgSettings, f) != C_KZG_OK) {
    free(kzgSettings);
    Napi::TypeError::New(env, "Error loading trusted setup file").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Consider making this internal state intead
  return Napi::External<KZGSettings>::New(info.Env(), kzgSettings);
}

// freeTrustedSetup: (setupHandle: SetupHandle) => void;
void FreeTrustedSetup(const Napi::CallbackInfo& info) {
  // Maybe this can be done with a finalizer on the thing returned by LoadTrustedSetup, and then the JS garbage collector can just sort it out.
  auto kzgSettings = info[0].As<Napi::External<KZGSettings>>().Data();
  free_trusted_setup(kzgSettings);
  free(kzgSettings);
}

// blobToKzgCommitment: (blob: Blob, setupHandle: SetupHandle) => KZGCommitment;
Napi::Value BlobToKzgCommitment(const Napi::CallbackInfo& info) {
  auto env = info.Env();

  if (info.Length() != 2) {
    Napi::TypeError::New(env, "Wrong number of arguments")
      .ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::TypedArray typedArray = info[0].As<Napi::TypedArray>();
  if (typedArray.TypedArrayType() != napi_uint8_array) {
    Napi::Error::New(env, "Expected an Uint8Array")
        .ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto blob = typedArray.As<Napi::Uint8Array>().Data();

  auto kzgSettings = info[1].As<Napi::External<KZGSettings>>().Data();

  Polynomial polynomial;
  for (size_t i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++)
    bytes_to_bls_field(&polynomial[i], &blob[i * 32]);

  KZGCommitment commitment;
  blob_to_kzg_commitment(&commitment, polynomial, kzgSettings);

  // Turn it into a byte array
  uint8_t commitmentBytes[BYTES_PER_COMMITMENT];
  bytes_from_g1(commitmentBytes, &commitment);
  return napiTypedArrayFromByteArray(commitmentBytes, BYTES_PER_COMMITMENT, env);
}

// computeAggregateKzgProof: (blobs: Blob[], setupHandle: SetupHandle) => KZGProof;
Napi::Value ComputeAggregateKzgProof(const Napi::CallbackInfo& info) {
  auto env = info.Env();

  if (info.Length() != 2) {
    Napi::TypeError::New(env, "Wrong number of arguments")
      .ThrowAsJavaScriptException();
    return env.Null();
  }

  auto blobs_param = info[0].As<Napi::Array>();
  auto kzgSettings = info[1].As<Napi::External<KZGSettings>>().Data();

  auto numberOfBlobs = blobs_param.Length();

  printf("ComputeAggregateKzgProof called with %i blob(s)\n", numberOfBlobs);

  auto polynomial = (Polynomial*)calloc(numberOfBlobs, sizeof(Polynomial));

  for (uint32_t blobIndex = 0; blobIndex < numberOfBlobs; blobIndex++) {
    Napi::Value blob = blobs_param[blobIndex];
    auto blobBytes = blob.As<Napi::Uint8Array>().Data();

    printf("Iterating blob index: %i\n", blobIndex);

    for (uint32_t fieldIndex = 0; fieldIndex < FIELD_ELEMENTS_PER_BLOB; fieldIndex++) {
      bytes_to_bls_field(
        &polynomial[blobIndex][fieldIndex],
        &blobBytes[fieldIndex * BYTES_PER_FIELD]
      );
    }
  }

  KZGProof proof;
  C_KZG_RET ret = compute_aggregate_kzg_proof(
    &proof,
    polynomial,
    numberOfBlobs,
    kzgSettings
  );
  free(polynomial);

  if (ret != C_KZG_OK) {
     Napi::TypeError::New(env, "Failed to compute proof")
      .ThrowAsJavaScriptException();
    return env.Undefined();
  };

  printf("proof generated: %llu y: %llu z: %llu\n", proof.x, proof.y, proof.z);
  printf("compute_aggregate_kzg_proof ret was %i\n", ret);

  uint8_t array[48];
  bytes_from_g1(array, &proof);

  printf("Turned proof into bytes: [");
  for (int i = 0; i < sizeof(array); i++) {
    printf("%x ", array[i]);
  }
  printf("]\n");

  return napiTypedArrayFromByteArray(array, sizeof(array), env);
}

// verifyAggregateKzgProof: (blobs: Blob[], expectedKzgCommitments: KZGCommitment[], kzgAggregatedProof: KZGProof) => boolean;
Napi::Value VerifyAggregateKzgProof(const Napi::CallbackInfo& info) {
  auto env = info.Env();

  if (info.Length() != 4) {
    Napi::TypeError::New(env, "Wrong number of arguments")
      .ThrowAsJavaScriptException();
    return env.Null();
  }

  auto blobs_param = info[0].As<Napi::Array>();

  auto comittments_param = info[1].As<Napi::Array>();

  auto proof_param = info[2].As<Napi::TypedArray>();
  auto proofBytes = proof_param.As<Napi::Uint8Array>().Data();

  auto kzgSettings = info[3].As<Napi::External<KZGSettings>>().Data();

  auto numberOfBlobs = blobs_param.Length();
  auto polynomial = (Polynomial*)calloc(numberOfBlobs, sizeof(Polynomial));
  auto commitments = (KZGCommitment*)calloc(numberOfBlobs, sizeof(KZGCommitment));

  C_KZG_RET ret;

  for (uint32_t blobIndex = 0; blobIndex < numberOfBlobs; blobIndex++) {
    Napi::Value blob = blobs_param[blobIndex];
    auto blobBytes = blob.As<Napi::Uint8Array>().Data();

    Napi::Value commitment = comittments_param[blobIndex];
    auto commitmentBytes = commitment.As<Napi::Uint8Array>().Data();

    for (uint32_t fieldIndex = 0; fieldIndex < FIELD_ELEMENTS_PER_BLOB; fieldIndex++) {
       bytes_to_bls_field(&polynomial[blobIndex][fieldIndex], &blobBytes[fieldIndex * BYTES_PER_FIELD]);
    }

    ret = bytes_to_g1(&commitments[blobIndex], &commitmentBytes[blobIndex * BYTES_PER_COMMITMENT]);
    if (ret != C_KZG_OK) {
      free(commitments);
      free(polynomial);

      Napi::TypeError::New(env, "Error parsing blobs and commitments")
        .ThrowAsJavaScriptException();
      return env.Null();
    }
  }

  KZGProof proof;
  ret = bytes_to_g1(&proof, proofBytes);
  if (ret != C_KZG_OK) {
    free(commitments);
    free(polynomial);

    Napi::TypeError::New(env, "Error converting proof parameter to KZGProof")
      .ThrowAsJavaScriptException();
    return env.Null();
  }

  bool verificationResult;
  ret = verify_aggregate_kzg_proof(
    &verificationResult,
    polynomial,
    commitments,
    numberOfBlobs,
    &proof,
    kzgSettings
  );
  if (ret != C_KZG_OK) {
    free(commitments);
    free(polynomial);

    Napi::TypeError::New(env, "Error calling verify_aggregate_kzg_proof")
      .ThrowAsJavaScriptException();
    return env.Null();
  }

  free(commitments);
  free(polynomial);

  return Napi::Boolean::New(env, verificationResult);
}

// verifyKzgProof: (polynomialKzg: KZGCommitment, z: BLSFieldElement, y: BLSFieldElement, kzgProof: KZGProof, setupHandle: SetupHandle) => boolean;
Napi::Value VerifyKzgProof(const Napi::CallbackInfo& info) {
  auto env = info.Env();

  if (info.Length() != 5) {
    Napi::TypeError::New(env, "Wrong number of arguments")
      .ThrowAsJavaScriptException();
    return env.Null();
  }

  // const uint8_t c[48]
  auto c_param = info[0].As<Napi::TypedArray>();
  if (c_param.TypedArrayType() != napi_uint8_array) {
    Napi::Error::New(env, "Expected an Uint8Array")
        .ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto c = c_param.As<Napi::Uint8Array>().Data();

  // const uint8_t x[32]
  auto x_param = info[0].As<Napi::TypedArray>();
  if (x_param.TypedArrayType() != napi_uint8_array) {
    Napi::Error::New(env, "Expected an Uint8Array")
        .ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto x = x_param.As<Napi::Uint8Array>().Data();

  // const uint8_t y[32]
  auto y_param = info[0].As<Napi::TypedArray>();
  if (y_param.TypedArrayType() != napi_uint8_array) {
    Napi::Error::New(env, "Expected an Uint8Array")
        .ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto y = y_param.As<Napi::Uint8Array>().Data();

  // const uint8_t p[48]
  auto p_param = info[0].As<Napi::TypedArray>();
  if (p_param.TypedArrayType() != napi_uint8_array) {
    Napi::Error::New(info.Env(), "Expected an Uint8Array")
        .ThrowAsJavaScriptException();
    return info.Env().Undefined();
  }
  auto p = p_param.As<Napi::Uint8Array>().Data();

  // KZGSettings *s
  auto kzgSettings = info[4].As<Napi::External<KZGSettings>>().Data();

  KZGCommitment commitment;
  KZGProof proof;
  BLSFieldElement fx, fy;
  bool out;

  bytes_to_bls_field(&fx, x);
  bytes_to_bls_field(&fy, y);

  auto ret = bytes_to_g1(&commitment, c);
  if (ret != C_KZG_OK) {
    std::ostringstream ss;
    std::copy(c, c+sizeof(c), std::ostream_iterator<int>(ss, ","));
    Napi::TypeError::New(env, "Failed to parse argument commitment: "  + ss.str() + " Return code was: " + std::to_string(ret)).ThrowAsJavaScriptException();
    return env.Null();
  };

  if (bytes_to_g1(&proof, p) != C_KZG_OK) {
    Napi::TypeError::New(env, "Wrong arguments").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (verify_kzg_proof(&out, &commitment, &fx, &fy, &proof, kzgSettings) != C_KZG_OK) {
    return Napi::Boolean::New(env, false);
  }

  return Napi::Boolean::New(env, true);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set(Napi::String::New(env, "loadTrustedSetup"), Napi::Function::New(env, LoadTrustedSetup));
  exports.Set(Napi::String::New(env, "freeTrustedSetup"), Napi::Function::New(env, FreeTrustedSetup));
  exports.Set(Napi::String::New(env, "verifyKzgProof"), Napi::Function::New(env, VerifyKzgProof));


  exports.Set(Napi::String::New(env, "blobToKzgCommitment"), Napi::Function::New(env, BlobToKzgCommitment));
  exports.Set(Napi::String::New(env, "verifyAggregateKzgProof"), Napi::Function::New(env, VerifyAggregateKzgProof));
  exports.Set(Napi::String::New(env, "computeAggregateKzgProof"), Napi::Function::New(env, ComputeAggregateKzgProof));
  return exports;
}

NODE_API_MODULE(addon, Init)
