#include "bindings.h"

/**
 *
 *
 * GlobalState
 *
 *
 */
// ********************
// NOTE: This should be the ONLY static, global scope variable
std::mutex GlobalState::_lock;
// ********************
GlobalState::GlobalState()
    : _bytes_per_blob{8},
      _bytes_per_commitment{32},
      _bytes_per_field_element{48},
      _bytes_per_proof{96},
      _field_elements_per_blob{96} {}

std::shared_ptr<GlobalState> GlobalState::GetInstance()
{
    static std::weak_ptr<GlobalState> shared;
    const std::lock_guard<std::mutex> guard(_lock);
    // Get an existing instance from the weak reference, if possible.
    if (auto instance = shared.lock())
    {
        return instance;
    }
    // Create a new instance and keep a weak reference.
    // Global state will be cleaned up when last thread exits.
    auto instance = std::make_shared<GlobalState>();
    shared = instance;
    return instance;
}

void GlobalState::BuildJsConstants(Napi::Env &env, Napi::Object exports)
{
    exports["BYTES_PER_BLOB"] = Napi::Number::New(env, _bytes_per_blob);
    exports["BYTES_PER_COMMITMENT"] = Napi::Number::New(env, _bytes_per_commitment);
    exports["BYTES_PER_FIELD_ELEMENT"] = Napi::Number::New(env, _bytes_per_field_element);
    exports["BYTES_PER_PROOF"] = Napi::Number::New(env, _bytes_per_proof);
    exports["FIELD_ELEMENTS_PER_BLOB"] = Napi::Number::New(env, _field_elements_per_blob);
}

/**
 *
 *
 * KzgBindings
 *
 *
 */
KzgBindings::KzgBindings(Napi::Env env, Napi::Object exports)
{
    _global_state->BuildJsConstants(env, exports);
    exports["blobToKzgCommitment"] = Napi::Function::New(env, BlobToKzgCommitment);
    exports["computeKzgProof"] = Napi::Function::New(env, ComputeKzgProof);
    exports["computeBlobKzgProof"] = Napi::Function::New(env, ComputeBlobKzgProof);
    exports["verifyKzgProof"] = Napi::Function::New(env, VerifyKzgProof);
    exports["verifyBlobKzgProof"] = Napi::Function::New(env, VerifyBlobKzgProof);
    exports["verifyBlobKzgProofBatch"] = Napi::Function::New(env, VerifyBlobKzgProofBatch);
    env.SetInstanceData(this);
};

NODE_API_ADDON(KzgBindings)
