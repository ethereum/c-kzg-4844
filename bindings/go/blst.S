/*
 * For CGO to assemble the blst assembly files, the file MUST exist in the same
 * directory as the main.go file. Instead of copying the whole
 * blst/build/assembly.S file here, it should have the same effect to include
 * it. Keep in mind, this while not work on Windows systems compiling with
 * MSVC, but it will work with mingw32.
 */
#include "assembly.S"
