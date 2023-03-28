#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "c_kzg_4844.h"
#include "ckzg.h"

KZGSettings* load_trusted_setup_wrap(const char *file) {
  C_KZG_RET ret;
  KZGSettings *s = NULL;
  FILE *f = NULL;

  /* Allocate memory for the trusted setup */
  s = malloc(sizeof(KZGSettings));
  if (s == NULL) goto out_error;

  /* Open the trusted setup file */
  f = fopen(file, "r");
  if (f == NULL) goto out_error;

  /* Load the trusted setup */
  ret = load_trusted_setup_file(s, f);
  if (ret != C_KZG_OK) goto out_error;

  goto out_success;

out_error:
  free_trusted_setup(s);
  free(s);
  s = NULL;
out_success:
  /* Close the trusted setup file */
  if (f != NULL) {
    if (fclose(f) != 0) {
      free_trusted_setup(s);
      free(s);
      s = NULL;
    }
  }
  return s;
}

void free_trusted_setup_wrap(KZGSettings *s) {
  free_trusted_setup(s);
  free(s);
}
