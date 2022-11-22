#ifndef ___BLS12_381_HPP___
#define ___BLS12_381_HPP___

#include <vector>

#include "../../src/c_kzg_4844.h"
#include "exception.hpp"

class Fr
{
private:
    fr_t fr;

    Fr(fr_t _fr) { fr = _fr; }

    Fr(int64_t arr[4])
    {
        blst_fr_from_uint64(&fr, (const uint64_t *)arr);
    }

public:
    static Fr from_jlongs(int64_t arr[4])
    {
        return Fr(arr);
    }

    Fr() {}

    std::vector<long long> to_longs()
    {
        std::vector<long long> ret(4);
        blst_uint64_from_fr((uint64_t *)&ret[0], &fr);
        return ret;
    }
};

class G1
{
private:
    g1_t g1;

    G1(g1_t g1_) { g1 = g1_; }

    G1(uint8_t arr[48])
    throw(KZGException)
    {
        bytes_to_g1(&g1, arr);
    }

public:
    static G1 from_compressed(uint8_t arr[48]) throw(KZGException)
    {
        return G1(arr);
    }

    G1() {}

    void to_compressed(uint8_t out[48])
    {
        bytes_from_g1(out, &g1);
    }
};

class G2
{
private:
    g2_t g2;

    G2() {}
    G2(g2_t g2_) { g2 = g2_; }
    G2(const byte arr[96])
    throw(KZGException)
    {
        blst_p2_affine p2_aff;
        BLST_TRY(blst_p2_uncompress(&p2_aff, arr));
        blst_p2_from_affine(&g2, &p2_aff);
    }

public:
    static G2 from_compressed(const signed char arr[96]) throw(KZGException)
    {
        return new G2((byte *)arr);
    }

    G2() {}

    void to_compressed(signed char out[96])
    {
        blst_p2_compress((byte *)out, &g2);
    }
};

#endif
