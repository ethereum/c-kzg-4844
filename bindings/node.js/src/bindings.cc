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
    : _bytes_per_blob{BYTES_PER_BLOB},
      _bytes_per_commitment{BYTES_PER_COMMITMENT},
      _bytes_per_field_element{BYTES_PER_FIELD_ELEMENT},
      _bytes_per_proof{BYTES_PER_PROOF},
      _field_elements_per_blob{FIELD_ELEMENTS_PER_BLOB} {}

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
    : _global_state{GlobalState::GetInstance()},
      _settings{(KZGSettings *)malloc(sizeof(KZGSettings))},
      _is_setup{false}
{
    _global_state->BuildJsConstants(env, exports);
    exports["setup"] = Napi::Function::New(env, Setup, "setup", this);
    exports["blobToKzgCommitment"] = Napi::Function::New(env, BlobToKzgCommitment, "blobToKzgCommitment", this);
    exports["computeKzgProof"] = Napi::Function::New(env, ComputeKzgProof, "computeKzgProof", this);
    exports["computeBlobKzgProof"] = Napi::Function::New(env, ComputeBlobKzgProof, "computeBlobKzgProof", this);
    exports["verifyKzgProof"] = Napi::Function::New(env, VerifyKzgProof, "verifyKzgProof", this);
    exports["verifyBlobKzgProof"] = Napi::Function::New(env, VerifyBlobKzgProof, "verifyBlobKzgProof", this);
    exports["verifyBlobKzgProofBatch"] = Napi::Function::New(env, VerifyBlobKzgProofBatch, "verifyBlobKzgProofBatch", this);
    env.SetInstanceData(this);
};

KzgBindings::~KzgBindings()
{
    if (_is_setup)
    {
        free_trusted_setup(_settings.get());
        _is_setup = false;
    }
}

NODE_API_ADDON(KzgBindings)
