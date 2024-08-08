#include "ckzg.h"

KZGSettings *load_trusted_setup_wrap(const char *file, uint64_t precompute);

void free_trusted_setup_wrap(KZGSettings *s);
