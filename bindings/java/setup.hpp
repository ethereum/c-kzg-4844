#ifndef ___SETUP_HPP___
#define ___SETUP_HPP___

#include <vector>

#include "c_kzg_4844.h"
#include "bls12_381.hpp"

class FFTSetup
{
private:
    uint64_t max_width;
    std::vector<Fr> expanded_roots_of_unity;
    std::vector<Fr> reverse_roots_of_unity;
    std::vector<Fr> roots_of_unity;

public:
    FFTSetup(uint64_t max_width_, std::vector<Fr> expanded_roots_of_unity_, std::vector<Fr> reverse_roots_of_unity_, std::vector<Fr> roots_of_unity_)
    {
        max_width = max_width_;
        expanded_roots_of_unity = expanded_roots_of_unity_;
        reverse_roots_of_unity = reverse_roots_of_unity_;
        roots_of_unity = roots_of_unity_;
    }

    FFTSetup() {}

    uint64_t max_width()
    {
        return max_width;
    }

    std::vector<Fr> expanded_roots_of_unity()
    {
        return expanded_roots_of_unity;
    }

    std::vector<Fr> reverse_roots_of_unity()
    {
        return reverse_roots_of_unity;
    }

    std::vector<Fr> roots_of_unity()
    {
        return roots_of_unity;
    }
};

class KZGSetup
{
private:
    FFTSetup fs;
    std::vector<G1> g1Values;
    std::vector<G2> g2Values;

public:
    KZGSetup(FFTSetup fs_, std::vector<G1> g1Values_, std::vector<G2> g2Values_)
    {
        fs = fs_;
        g1Values = g1Values_;
        g2Values = g2Values_;
    }

    KZGSetup() {}

    FFTSetup fs()
    {
        return fs;
    }

    std::vector<G1> g1Values()
    {
        return g1Values;
    }

    std::vector<G2> g2Values()
    {
        return g2Values;
    }
};

#endif
