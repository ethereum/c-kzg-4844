#include "ckzg.h"

KZGSettings *load_trusted_setup_wrap(const char *file, size_t precompute);

void free_trusted_setup_wrap(KZGSettings *s);
