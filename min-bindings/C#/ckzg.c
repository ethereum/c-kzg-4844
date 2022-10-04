#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "c_kzg_4844.h"

uint64_t hello(uint64_t a) {
  printf("Hello World! %lu\n", a);
  return 42;
}

BLSFieldElement* bytes_to_bls_field_wrap(const uint8_t bytes[]) {
  BLSFieldElement* out = (BLSFieldElement*)malloc(sizeof(BLSFieldElement));
  bytes_to_bls_field(out, bytes);
  return out;
}

uint64_t* uint64s_from_bls_field(BLSFieldElement *fr) {
  uint64_t *r = (uint64_t*)calloc(4, sizeof(uint64_t));
  uint64s_from_BLSFieldElement(r, fr);
  return r;
}
