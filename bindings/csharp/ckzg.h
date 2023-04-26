#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "c_kzg_4844.h"

KZGSettings* load_trusted_setup_wrap(const char* file);

void free_trusted_setup_wrap(KZGSettings *s);
