#include "functions.h"

inline uint8_t *get_bytes(
    const Napi::Env &env,
    const KzgBindings *bindings,
    Napi::Value val,
    size_t length,
    std::string &&name)
{
    if (!(val.IsTypedArray() && val.As<Napi::TypedArray>().TypedArrayType() == napi_uint8_array))
    {
        std::ostringstream msg;
        msg << name << " must be a Uint8Array";
        Napi::TypeError::New(env, msg.str()).ThrowAsJavaScriptException();
        return nullptr;
    }
    Napi::Uint8Array array = val.As<Napi::Uint8Array>();
    if (array.ByteLength() != length)
    {
        std::ostringstream msg;
        msg << name << " must be " << length << " bytes long";
        Napi::TypeError::New(env, msg.str()).ThrowAsJavaScriptException();
        return nullptr;
    }
    return array.Data();
}

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
    Napi::Env env = info.Env();
    KzgBindings *bindings = static_cast<KzgBindings *>(info.Data());
    uint8_t *blob = get_bytes(env, bindings, info[0], bindings->_global_state->_bytes_per_blob, "blob");
    if (blob == nullptr || env.IsExceptionPending())
    {
        return env.Undefined();
    }
    KZGCommitment commitment;
    C_KZG_RET ret = blob_to_kzg_commitment(&commitment, (reinterpret_cast<Blob *>(blob)), bindings->_settings.get());
    if (ret != C_KZG_OK)
    {
        Napi::Error::New(env, "Failed to convert blob to commitment").ThrowAsJavaScriptException();
        return env.Undefined();
    };
    return Napi::Buffer<uint8_t>::Copy(env, reinterpret_cast<uint8_t *>(&commitment), bindings->_global_state->_bytes_per_commitment);
}

Napi::Value ComputeKzgProof(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    KzgBindings *bindings = static_cast<KzgBindings *>(info.Data());
    uint8_t *blob = get_bytes(env, bindings, info[0], bindings->_global_state->_bytes_per_blob, "blob");
    if (blob == nullptr || env.IsExceptionPending())
    {
        return env.Undefined();
    }
    uint8_t *z_bytes = get_bytes(env, bindings, info[1], 32, "zBytes");
    if (blob == nullptr || env.IsExceptionPending())
    {
        return env.Undefined();
    }
    KZGProof proof;
    C_KZG_RET ret = compute_kzg_proof(
        &proof,
        reinterpret_cast<Blob *>(blob),
        reinterpret_cast<Bytes32 *>(z_bytes),
        bindings->_settings.get());
    if (ret != C_KZG_OK)
    {
        Napi::Error::New(env, "Failed to compute proof").ThrowAsJavaScriptException();
        return env.Undefined();
    };
    return Napi::Buffer<uint8_t>::Copy(
        env,
        reinterpret_cast<uint8_t *>(&proof),
        bindings->_global_state->_bytes_per_proof);
}

Napi::Value ComputeBlobKzgProof(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    KzgBindings *bindings = static_cast<KzgBindings *>(info.Data());
    uint8_t *blob = get_bytes(env, bindings, info[0], bindings->_global_state->_bytes_per_blob, "blob");
    if (blob == nullptr || env.IsExceptionPending())
    {
        return env.Undefined();
    }
    KZGProof proof;
    C_KZG_RET ret = compute_blob_kzg_proof(
        &proof,
        reinterpret_cast<Blob *>(blob),
        bindings->_settings.get());
    if (ret != C_KZG_OK)
    {
        Napi::Error::New(env, "Failed to compute proof").ThrowAsJavaScriptException();
        return env.Undefined();
    };
    return Napi::Buffer<uint8_t>::Copy(
        env,
        reinterpret_cast<uint8_t *>(&proof),
        bindings->_global_state->_bytes_per_proof);
}

Napi::Value VerifyKzgProof(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    KzgBindings *bindings = static_cast<KzgBindings *>(info.Data());

    uint8_t *commitment_bytes = get_bytes(env, bindings, info[0], bindings->_global_state->_bytes_per_commitment, "commitmentBytes");
    uint8_t *z_bytes = get_bytes(env, bindings, info[1], 32, "zBytes");
    uint8_t *y_bytes = get_bytes(env, bindings, info[2], 32, "yBytes");
    uint8_t *proof_bytes = get_bytes(env, bindings, info[3], bindings->_global_state->_bytes_per_proof, "proofBytes");
    bool out;
    C_KZG_RET ret = verify_kzg_proof(
        &out,
        reinterpret_cast<Bytes48 *>(commitment_bytes),
        reinterpret_cast<Bytes32 *>(z_bytes),
        reinterpret_cast<Bytes32 *>(y_bytes),
        reinterpret_cast<Bytes48 *>(proof_bytes),
        bindings->_settings.get());
    if (ret != C_KZG_OK)
    {
        Napi::TypeError::New(env, "Failed to verify KZG proof").ThrowAsJavaScriptException();
        return env.Null();
    }
    return Napi::Boolean::New(env, out);
}

Napi::Value VerifyBlobKzgProof(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    KzgBindings *bindings = static_cast<KzgBindings *>(info.Data());
    uint8_t *blob_bytes = get_bytes(env, bindings, info[0], bindings->_global_state->_bytes_per_blob, "blob");
    uint8_t *commitment_bytes = get_bytes(env, bindings, info[1], bindings->_global_state->_bytes_per_commitment, "commitmentBytes");
    uint8_t *proof_bytes = get_bytes(env, bindings, info[2], bindings->_global_state->_bytes_per_proof, "proofBytes");
    bool out;
    C_KZG_RET ret = verify_blob_kzg_proof(
        &out,
        reinterpret_cast<Blob *>(blob_bytes),
        reinterpret_cast<Bytes48 *>(commitment_bytes),
        reinterpret_cast<Bytes48 *>(proof_bytes),
        bindings->_settings.get());
    if (ret != C_KZG_OK)
    {
        Napi::TypeError::New(env, "Error in verifyBlobKzgProof").ThrowAsJavaScriptException();
        return env.Null();
    }
    return Napi::Boolean::New(env, out);
}

Napi::Value VerifyBlobKzgProofBatch(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    KzgBindings *bindings = static_cast<KzgBindings *>(info.Data());
    if (!(info[0].IsArray() && info[1].IsArray() && info[2].IsArray()))
    {
        Napi::Error::New(env, "blobs, commitments, and proofs must all be arrays").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    Napi::Array blobs_array = info[0].As<Napi::Array>();
    Napi::Array commitments_array = info[1].As<Napi::Array>();
    Napi::Array proofs_array = info[2].As<Napi::Array>();
    uint32_t count = blobs_array.Length();
    if (!(count == commitments_array.Length() == proofs_array.Length()))
    {
        Napi::Error::New(env, "blobs, commitments, and proofs arrays must be the same length").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    Blob blobs[count];
    Bytes48 commitments[count];
    Bytes48 proofs[count];
    for (uint32_t index = 0; index < count; index++)
    {
        uint8_t *blob = get_bytes(
            env,
            bindings,
            blobs_array[index],
            bindings->_global_state->_bytes_per_blob,
            "blob");
        if (blob == nullptr || env.IsExceptionPending())
        {
            return env.Undefined();
        }
        memcpy(&blobs[index], blob, bindings->_global_state->_bytes_per_blob);
        uint8_t *commitment = get_bytes(
            env,
            bindings,
            commitments_array[index],
            bindings->_global_state->_bytes_per_commitment,
            "commitment");
        if (commitment == nullptr || env.IsExceptionPending())
        {
            return env.Undefined();
        }
        memcpy(&commitments[index], commitment, bindings->_global_state->_bytes_per_commitment);
        uint8_t *proof = get_bytes(
            env,
            bindings,
            proofs_array[index],
            bindings->_global_state->_bytes_per_proof,
            "proof");
        if (proof == nullptr || env.IsExceptionPending())
        {
            return env.Undefined();
        }
        memcpy(&proofs[index], proof, bindings->_global_state->_bytes_per_proof);
    }
    bool out;
    C_KZG_RET ret = verify_blob_kzg_proof_batch(
        &out,
        blobs,
        commitments,
        proofs,
        count,
        bindings->_settings.get());
    if (ret != C_KZG_OK)
    {
        Napi::TypeError::New(env, "Error in verifyBlobKzgProofBatch").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    return Napi::Boolean::New(env, out);
}
