/*
 * This file contains fuzzing tests for C-KZG-4844.
 */
#pragma once
#include "../src/c_kzg_4844.c"

///////////////////////////////////////////////////////////////////////////////
// Globals
///////////////////////////////////////////////////////////////////////////////

KZGSettings s;

///////////////////////////////////////////////////////////////////////////////
// Trusted setup configuration
///////////////////////////////////////////////////////////////////////////////

static void initialize(void) {
    static bool initialized = false;
    if (!initialized) {
        FILE *fp;
        C_KZG_RET ret;

        /* Open the mainnet trusted setup file */
        fp = fopen("../src/trusted_setup.txt", "r");
        assert(fp != NULL);

        /* Load that trusted setup file */
        ret = load_trusted_setup_file(&s, fp, 0);
        assert(ret == C_KZG_OK);

        fclose(fp);
        initialized = true;
    }
}
