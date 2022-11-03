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

int verifyAggregateKzgProof(const uint8_t blobs[], const uint8_t commitments[], size_t n, const uint8_t proof[48], const KZGSettings *s) {
  Polynomial* p = (Polynomial*)calloc(n, sizeof(Polynomial));
  if (p == NULL) return -1;

  KZGCommitment* c = (KZGCommitment*)calloc(n, sizeof(KZGCommitment));
  if (c == NULL) { free(p); return -1; }

  C_KZG_RET ret;

  for (size_t i = 0; i < n; i++) {
    for (size_t j = 0; j < FIELD_ELEMENTS_PER_BLOB; j++)
      bytes_to_bls_field(&p[i][j], &blobs[i * FIELD_ELEMENTS_PER_BLOB * 32 + j * 32]);
    ret = bytes_to_g1(&c[i], &commitments[i * 48]);
    if (ret != C_KZG_OK) { free(c); free(p); return -1; }
  }

  KZGProof f;
  ret = bytes_to_g1(&f, proof);
  if (ret != C_KZG_OK) { free(c); free(p); return -1; }

  bool b;
  ret = verify_aggregate_kzg_proof(&b, p, c, n, &f, s);
  if (ret != C_KZG_OK) { free(c); free(p); return -1; }

  free(c); free(p);
  return b ? 0 : 1;
}

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

// Maybe this can be done with a finalizer on the thing returned by LoadTrustedSetup, and then the JS garbage collector can just sort it out.
void FreeTrustedSetup(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  KZGSettings* kzgSettings = info[0].As<Napi::External<KZGSettings>>().Data();
  free_trusted_setup(kzgSettings);
  free(kzgSettings);
}

// blobToKzgCommitment: (blob: Blob) => KZGCommitment;
Napi::Value BlobToKzgCommitment(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

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
  uint8_t* blob = typedArray.As<Napi::Uint8Array>().Data();

  KZGSettings* kzgSettings = info[1].As<Napi::External<KZGSettings>>().Data();

  Polynomial polynomial;
  for (size_t i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++)
    bytes_to_bls_field(&polynomial[i], &blob[i * 32]);

  KZGCommitment commitment;
  blob_to_kzg_commitment(&commitment, polynomial, kzgSettings);

  // Turn it into a byte array
  uint8_t array[48];
  bytes_from_g1(array, &commitment);
  return napiTypedArrayFromByteArray(array, sizeof(array), env);
}

Napi::Value VerifyAggregateKzgProof(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
}

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
  // auto blobs = blobs_param.As<Napi::Array<Napi::Uint8Array>>();

  int BYTES_PER_FIELD = 32;
  int BYTES_PER_BLOB = FIELD_ELEMENTS_PER_BLOB * BYTES_PER_FIELD;

  printf("ComputeAggregateKzgProof called with %i blobs", numberOfBlobs);

  // uint8_t blobBytes[numberOfBlobs * FIELD_ELEMENTS_PER_BLOB];
  // for(int i = 0; i < numberOfBlobs; i++)
  // {
  //   Napi::Value blob = blobs_param[i];
  //   if (blob.IsTypedArray())
  //   {
  //     auto blobBytes = blob.As<Napi::Uint8Array>().Data();
  //     memcpy(blobBytes + i * BYTES_PER_BLOB, blobBytes, BYTES_PER_BLOB);
  //   }
  // }

  // printf("ComputeAggregateKzgProof copied %i bytes", sizeof(blobBytes));

  auto polynomial = (Polynomial*)calloc(numberOfBlobs, sizeof(Polynomial));
  // if (p == NULL) return C_KZG_ERROR;

  for (uint32_t blobIndex = 0; blobIndex < numberOfBlobs; blobIndex++) {
    Napi::Value blob = blobs_param[blobIndex];
    auto blobBytes = blob.As<Napi::Uint8Array>().Data();

    printf("Iterating blob index: %i", blobIndex);

    for (uint32_t fieldIndex = 0; fieldIndex < FIELD_ELEMENTS_PER_BLOB; fieldIndex++) {
      bytes_to_bls_field(
        &polynomial[blobIndex][fieldIndex],
        &blobBytes[fieldIndex * BYTES_PER_FIELD]
      );
    }
  }

  printf("ComputeAggregateKzgProof 1");
  printf("ComputeAggregateKzgProof 1");
  printf("ComputeAggregateKzgProof 1");
  printf("ComputeAggregateKzgProof 1");

  //  return env.Null();

  KZGProof proof;
  C_KZG_RET ret = compute_aggregate_kzg_proof(
    &proof,
    polynomial,
    numberOfBlobs,
    kzgSettings
  );

 Napi::TypeError::New(env, "STOPPING HERE")
      .ThrowAsJavaScriptException();
  return env.Null();

  printf("ComputeAggregateKzgProof 2");

  free(polynomial);

  printf("ComputeAggregateKzgProof 3");

  if (ret != C_KZG_OK) {
     Napi::TypeError::New(env, "Failed to compute proof")
      .ThrowAsJavaScriptException();
    return env.Null();
  };

  printf("ComputeAggregateKzgProof 4");

  uint8_t* bytes;
  bytes_from_g1(bytes, &proof);

  printf("ComputeAggregateKzgProof 5");

  return napiTypedArrayFromByteArray(bytes, sizeof(bytes), env);
}

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
    // return -1;
  };
  if (bytes_to_g1(&proof, p) != C_KZG_OK) {
    Napi::TypeError::New(env, "Wrong arguments").ThrowAsJavaScriptException();
    return env.Null();
    // return -1;
  }

  if (verify_kzg_proof(&out, &commitment, &fx, &fy, &proof, kzgSettings) != C_KZG_OK) {
    return env.Null();
  }

  return env.Null();
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


// SCRATCH
  // Napi::Object obj = Napi::Object::New(env);

  // // Assign values to properties
  // obj.Set("hello", "world");
  // // obj.Set(uint32_t(42), "The Answer to Life, the Universe, and Everything");
  // // obj.Set("Douglas Adams", true);
  // // obj.Set("fftSettings", kzgSettings->fs);
  // // Napi::Array::Array(napi_env env, napi_value value);

  // const Napi::Array g1Values = Napi::Array::New(env, )

  // obj.Set('g1Values', kzgSettings->g1_values);
  // obj.Set('g2Values', kzgSettings->g2_values);
