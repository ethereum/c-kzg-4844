#include "functions.h"

Napi::Value Setup(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    KzgBindings *bindings = static_cast<KzgBindings *>(info.Data());
    if (bindings->_is_setup)
    {
        // QUESTION: Should this throw for re-setup or just ignore like it is?
        // Napi::Error::New(env, "kzg bindings are already setup").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    // the validation checks for this happen in JS
    const std::string file_path = info[0].As<Napi::String>().Utf8Value();
    FILE *file_handle = fopen(file_path.c_str(), "r");
    if (file_handle == NULL)
    {
        Napi::Error::New(env, "Error opening trusted setup file: " + file_path).ThrowAsJavaScriptException();
        return env.Undefined();
    }
    if (load_trusted_setup_file(bindings->_settings.get(), file_handle) != C_KZG_OK)
    {
        Napi::Error::New(env, "Error loading trusted setup file: " + file_path).ThrowAsJavaScriptException();
        return env.Undefined();
    }
    bindings->_is_setup = true;
    return env.Undefined();
}

Napi::Value BlobToKzgCommitment(const Napi::CallbackInfo &info)
{
    return info.Env().Undefined();
}
Napi::Value ComputeKzgProof(const Napi::CallbackInfo &info)
{
    return info.Env().Undefined();
}
Napi::Value ComputeBlobKzgProof(const Napi::CallbackInfo &info)
{
    return info.Env().Undefined();
}
Napi::Value VerifyKzgProof(const Napi::CallbackInfo &info)
{
    return info.Env().Undefined();
}
Napi::Value VerifyBlobKzgProof(const Napi::CallbackInfo &info)
{
    return info.Env().Undefined();
}
Napi::Value VerifyBlobKzgProofBatch(const Napi::CallbackInfo &info)
{
    return info.Env().Undefined();
}
