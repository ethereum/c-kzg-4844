#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#define NAPI_EXPERIMENTAL
#include <napi.h>
#include "c_kzg_4844.h"
#include "blst.h"


KZGSettings* loadTrustedSetup(const char* file) {
  KZGSettings* out = (KZGSettings*)malloc(sizeof(KZGSettings));

  if (out == NULL) return NULL;

  FILE* f = fopen(file, "r");

  if (f == NULL) { free(out); return NULL; }

  if (load_trusted_setup(out, f) != C_KZG_OK) { free(out); return NULL; }

  return out;
}

void freeTrustedSetup(KZGSettings *s) {
  free_trusted_setup(s);
  free(s);
}

void blobToKzgCommitment(uint8_t out[48], const uint8_t blob[FIELD_ELEMENTS_PER_BLOB * 32], const KZGSettings *s) {
  Polynomial p;
  for (size_t i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++)
    bytes_to_bls_field(&p[i], &blob[i * 32]);

  KZGCommitment c;
  blob_to_kzg_commitment(&c, p, s);

  bytes_from_g1(out, &c);
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

C_KZG_RET computeAggregateKzgProof(uint8_t out[48], const uint8_t blobs[], size_t n, const KZGSettings *s) {
  Polynomial* p = (Polynomial*)calloc(n, sizeof(Polynomial));
  if (p == NULL) return C_KZG_ERROR;

  for (size_t i = 0; i < n; i++)
    for (size_t j = 0; j < FIELD_ELEMENTS_PER_BLOB; j++)
      bytes_to_bls_field(&p[i][j], &blobs[i * FIELD_ELEMENTS_PER_BLOB * 32 + j * 32]);

  KZGProof f;
  C_KZG_RET ret = compute_aggregate_kzg_proof(&f, p, n, s);

  free(p);
  if (ret != C_KZG_OK) return ret;

  bytes_from_g1(out, &f);
  return C_KZG_OK;
}

int verifyKzgProof(const uint8_t c[48], const uint8_t x[32], const uint8_t y[32], const uint8_t p[48], KZGSettings *s) {
  KZGCommitment commitment;
  KZGProof proof;
  BLSFieldElement fx, fy;
  bool out;

  bytes_to_bls_field(&fx, x);
  bytes_to_bls_field(&fy, y);
  if (bytes_to_g1(&commitment, c) != C_KZG_OK) return -1;
  if (bytes_to_g1(&proof, p) != C_KZG_OK) return -1;

  if (verify_kzg_proof(&out, &commitment, &fx, &fy, &proof, s) != C_KZG_OK)
    return -2;

  return out ? 0 : 1;
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

  // https://github.com/nodejs/node-addon-api/issues/667
  Napi::External<KZGSettings> kzgSettingsPointer = Napi::External<KZGSettings>::New(info.Env(), kzgSettings);
  kzgSettingsPointer.As<Napi::Object>().AddFinalizer([](Napi::Env, KZGSettings* kzgSettings) {
    printf(" finalize \n"
           " test %p   "
           "*test %x   "
           "&test %p\n", kzgSettings, *kzgSettings, &kzgSettings);
  }, kzgSettings);

  return kzgSettingsPointer;
}

void FreeTrustedSetup(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  KZGSettings* kzgSettings = info[0].As<Napi::External<KZGSettings>>().Data();
  printf("Freeing: kzgSettings %p   *kzgSettings %s   &kzgSettings %p\n", kzgSettings, *kzgSettings, &kzgSettings);

  freeTrustedSetup(kzgSettings);
}
Napi::Value BlobToKzgCommitment(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
}
Napi::Value VerifyAggregateKzgProof(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
}
Napi::Value ComputeAggregateKzgProof(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
}
Napi::Value VerifyKzgProof(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set(Napi::String::New(env, "loadTrustedSetup"), Napi::Function::New(env, LoadTrustedSetup));
  exports.Set(Napi::String::New(env, "freeTrustedSetup"), Napi::Function::New(env, FreeTrustedSetup));
  exports.Set(Napi::String::New(env, "blobToKzgCommitment"), Napi::Function::New(env, BlobToKzgCommitment));
  exports.Set(Napi::String::New(env, "verifyAggregateKzgProof"), Napi::Function::New(env, VerifyAggregateKzgProof));
  exports.Set(Napi::String::New(env, "computeAggregateKzgProof"), Napi::Function::New(env, ComputeAggregateKzgProof));
  exports.Set(Napi::String::New(env, "verifyKzgProof"), Napi::Function::New(env, VerifyKzgProof));
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
