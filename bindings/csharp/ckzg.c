#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "ckzg.h"
#include "c_kzg_4844.h"

KZGSettings* load_trusted_setup_wrap(const char* file) {
  KZGSettings* out = malloc(sizeof(KZGSettings));

  if (out == NULL) return NULL;

  FILE* f = fopen(file, "r");

  if (f == NULL) { free(out); return NULL; }

  if (load_trusted_setup_file(out, f) != C_KZG_OK) { free(out); fclose(f); return NULL; }

  fclose(f);
  return out;
}

void free_trusted_setup_wrap(KZGSettings *s) {
  free_trusted_setup(s);
  free(s);
}
