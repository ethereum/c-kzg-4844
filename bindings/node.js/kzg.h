#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "c_kzg_4844.h"

int testFunction();

KZGSettings* loadTrustedSetup(const char* file);

void freeTrustedSetup(KZGSettings *s);

// void blobToKzgCommitment(uint8_t out[48], const uint8_t blob[FIELD_ELEMENTS_PER_BLOB * 32], const KZGSettings *s);

// int verifyKzgProof(const uint8_t c[48], const uint8_t x[32], const uint8_t y[32], const uint8_t p[48], KZGSettings *s);

// int verifyAggregateKzgProof(const uint8_t blobs[], const uint8_t commitments[], size_t n, const uint8_t proof[48], const KZGSettings *s);

// C_KZG_RET computeAggregateKzgProof(uint8_t out[48], const uint8_t blobs[], size_t n, const KZGSettings *s);
