#ifndef ___C_KZG_4844_HPP___
#define ___C_KZG_4844_HPP___

#include <vector>

#include "c_kzg_4844.h"
#include "bls12_381.hpp"
#include "setup.hpp"
#include "exception.hpp"

KZGSetup load_trusted_setup_wrap(const char *file)
{
  KZGSettings *out = malloc(sizeof(KZGSettings));

  FILE *f = fopen(file, "r");

  CKZG_TRY(load_trusted_setup(out, f));

  return KZGSetup();
}

void free_trusted_setup_wrap(KZGSetup *s)
{
  KZGSettings s_;
  CKZG_TRY(free_trusted_setup(s_))
}

#endif