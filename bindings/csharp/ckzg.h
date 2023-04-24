#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "c_kzg_4844.h"

DLLEXPORT KZGSettings* load_trusted_setup_wrap(const char* file);

DLLEXPORT void free_trusted_setup_wrap(KZGSettings *s);
