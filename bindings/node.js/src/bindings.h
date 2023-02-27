#ifndef C_KZG_ADDON_H__
#define C_KZG_ADDON_H__

#include <iostream>

#include <memory>
#include <mutex>
#include "napi.h"
#include "blst.h"
#include "blst.hpp"
#include "c_kzg_4844.h"
#include "functions.h"

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

    static std::shared_ptr<GlobalState> GetInstance();

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
    std::shared_ptr<GlobalState> _global_state;
    std::unique_ptr<KZGSettings> _settings;

    KzgBindings(Napi::Env env, Napi::Object exports);
    KzgBindings(KzgBindings &&source) = delete;
    KzgBindings(const KzgBindings &source) = delete;
    ~KzgBindings();
    KzgBindings &operator=(KzgBindings &&source) = delete;
    KzgBindings &operator=(const KzgBindings &source) = delete;

    Napi::Value TestSync(const Napi::CallbackInfo &info);
    Napi::Value TestAsync(const Napi::CallbackInfo &info);
    bool IsSetup() { return _is_setup; }

private:
    friend Napi::Value Setup(const Napi::CallbackInfo &info);
    bool _is_setup;
};

#endif /* C_KZG_ADDON_H__ */