#ifndef C_KZG_FUNCTIONS_H__
#define C_KZG_FUNCTIONS_H__

#include <iostream>

#include "napi.h"
#include "bindings.h"
#include "c_kzg_4844.h"

Napi::Value Setup(const Napi::CallbackInfo &info);
Napi::Value BlobToKzgCommitment(const Napi::CallbackInfo &info);
Napi::Value ComputeKzgProof(const Napi::CallbackInfo &info);
Napi::Value ComputeBlobKzgProof(const Napi::CallbackInfo &info);
Napi::Value VerifyKzgProof(const Napi::CallbackInfo &info);
Napi::Value VerifyBlobKzgProof(const Napi::CallbackInfo &info);
Napi::Value VerifyBlobKzgProofBatch(const Napi::CallbackInfo &info);

#endif /* C_KZG_FUNCTIONS_H__ */