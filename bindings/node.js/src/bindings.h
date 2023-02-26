#ifndef C_KZG_ADDON_H__
#define C_KZG_ADDON_H__

#include "napi.h"
#include "blst.hpp"

class KzgBindings;

/**
 * Idea for implementation of GlobalState
 * https://github.com/nodejs/node-addon-api/issues/567
 */
class GlobalState
{
public:
    size_t _bytes_per_blob;
    size_t _bytes_per_commitment;
    size_t _bytes_per_field_element;
    size_t _bytes_per_proof;
    size_t _field_elements_per_blob;

    static std::shared_ptr<GlobalState> GetInstance(KzgBindings *addon);

    GlobalState();
    GlobalState(GlobalState &&source) = delete;
    GlobalState(const GlobalState &source) = delete;
    GlobalState &operator=(GlobalState &&source) = delete;
    GlobalState &operator=(const GlobalState &source) = delete;

    void BuildJsConstants(Napi::Env &env, Napi::Object exports);

private:
    static std::mutex _lock;
};

class KzgBindings : public Napi::Addon<KzgBindings>
{
public:
    std::shared_ptr<GlobalState> _global_state = GlobalState::GetInstance(this);
    Napi::Object _js_constants;

    KzgBindings(Napi::Env env, Napi::Object exports);
    KzgBindings(KzgBindings &&source) = delete;
    KzgBindings(const KzgBindings &source) = delete;
    KzgBindings &operator=(KzgBindings &&source) = delete;
    KzgBindings &operator=(const KzgBindings &source) = delete;

    Napi::Value TestSync(const Napi::CallbackInfo &info);
    Napi::Value TestAsync(const Napi::CallbackInfo &info);
};

#endif /* C_KZG_ADDON_H__ */