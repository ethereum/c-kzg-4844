/*
 * Copyright 2021 Benjamin Edgington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/** @file fft_common.h */

#ifndef FFT_COMMON
#define FFT_COMMON

#include "c_kzg.h"

/**
 * The first 32 roots of unity in the finite field F_r.
 *
 * For element `{A, B, C, D}`, the field element value is `A + B * 2^64 + C * 2^128 + D * 2^192`. This format may be
 * converted to an `fr_t` type via the #fr_from_uint64s library function.
 *
 * The decimal values may be calculated with the following Python code:
 * @code{.py}
 * MODULUS = 52435875175126190479447740508185965837690552500527637822603658699938581184513
 * PRIMITIVE_ROOT = 7
 * [pow(PRIMITIVE_ROOT, (MODULUS - 1) // (2**i), MODULUS) for i in range(32)]
 * @endcode
 *
 * Note: Being a "primitive root" in this context means that r^k != 1 for any k < q-1 where q is the modulus. So
 * powers of r generate the field. This is also known as being a "primitive element".
 *
 * This is easy to check for: we just require that r^((q-1)/2) != 1. Instead of 5, we could use 7, 10, 13, 14, 15, 20...
 * to create the roots of unity below. There are a lot of primitive roots:
 * https://crypto.stanford.edu/pbc/notes/numbertheory/gen.html
 */
static const uint64_t scale2_root_of_unity[][4] = {
    {0x0000000000000001L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L},
    {0xffffffff00000000L, 0x53bda402fffe5bfeL, 0x3339d80809a1d805L, 0x73eda753299d7d48L},
    {0x0001000000000000L, 0xec03000276030000L, 0x8d51ccce760304d0L, 0x0000000000000000L},
    {0x7228fd3397743f7aL, 0xb38b21c28713b700L, 0x8c0625cd70d77ce2L, 0x345766f603fa66e7L},
    {0x53ea61d87742bcceL, 0x17beb312f20b6f76L, 0xdd1c0af834cec32cL, 0x20b1ce9140267af9L},
    {0x360c60997369df4eL, 0xbf6e88fb4c38fb8aL, 0xb4bcd40e22f55448L, 0x50e0903a157988baL},
    {0x8140d032f0a9ee53L, 0x2d967f4be2f95155L, 0x14a1e27164d8fdbdL, 0x45af6345ec055e4dL},
    {0x5130c2c1660125beL, 0x98d0caac87f5713cL, 0xb7c68b4d7fdd60d0L, 0x6898111413588742L},
    {0x4935bd2f817f694bL, 0x0a0865a899e8deffL, 0x6b368121ac0cf4adL, 0x4f9b4098e2e9f12eL},
    {0x4541b8ff2ee0434eL, 0xd697168a3a6000feL, 0x39feec240d80689fL, 0x095166525526a654L},
    {0x3c28d666a5c2d854L, 0xea437f9626fc085eL, 0x8f4de02c0f776af3L, 0x325db5c3debf77a1L},
    {0x4a838b5d59cd79e5L, 0x55ea6811be9c622dL, 0x09f1ca610a08f166L, 0x6d031f1b5c49c834L},
    {0xe206da11a5d36306L, 0x0ad1347b378fbf96L, 0xfc3e8acfe0f8245fL, 0x564c0a11a0f704f4L},
    {0x6fdd00bfc78c8967L, 0x146b58bc434906acL, 0x2ccddea2972e89edL, 0x485d512737b1da3dL},
    {0x034d2ff22a5ad9e1L, 0xae4622f6a9152435L, 0xdc86b01c0d477fa6L, 0x56624634b500a166L},
    {0xfbd047e11279bb6eL, 0xc8d5f51db3f32699L, 0x483405417a0cbe39L, 0x3291357ee558b50dL},
    {0xd7118f85cd96b8adL, 0x67a665ae1fcadc91L, 0x88f39a78f1aeb578L, 0x2155379d12180caaL},
    {0x08692405f3b70f10L, 0xcd7f2bd6d0711b7dL, 0x473a2eef772c33d6L, 0x224262332d8acbf4L},
    {0x6f421a7d8ef674fbL, 0xbb97a3bf30ce40fdL, 0x652f717ae1c34bb0L, 0x2d3056a530794f01L},
    {0x194e8c62ecb38d9dL, 0xad8e16e84419c750L, 0xdf625e80d0adef90L, 0x520e587a724a6955L},
    {0xfece7e0e39898d4bL, 0x2f69e02d265e09d9L, 0xa57a6e07cb98de4aL, 0x03e1c54bcb947035L},
    {0xcd3979122d3ea03aL, 0x46b3105f04db5844L, 0xc70d0874b0691d4eL, 0x47c8b5817018af4fL},
    {0xc6e7a6ffb08e3363L, 0xe08fec7c86389beeL, 0xf2d38f10fbb8d1bbL, 0x0abe6a5e5abcaa32L},
    {0x5616c57de0ec9eaeL, 0xc631ffb2585a72dbL, 0x5121af06a3b51e3cL, 0x73560252aa0655b2L},
    {0x92cf4deb77bd779cL, 0x72cf6a8029b7d7bcL, 0x6e0bcd91ee762730L, 0x291cf6d68823e687L},
    {0xce32ef844e11a51eL, 0xc0ba12bb3da64ca5L, 0x0454dc1edc61a1a3L, 0x019fe632fd328739L},
    {0x531a11a0d2d75182L, 0x02c8118402867ddcL, 0x116168bffbedc11dL, 0x0a0a77a3b1980c0dL},
    {0xe2d0a7869f0319edL, 0xb94f1101b1d7a628L, 0xece8ea224f31d25dL, 0x23397a9300f8f98bL},
    {0xd7b688830a4f2089L, 0x6558e9e3f6ac7b41L, 0x99e276b571905a7dL, 0x52dd465e2f094256L},
    {0x474650359d8e211bL, 0x84d37b826214abc6L, 0x8da40c1ef2bb4598L, 0x0c83ea7744bf1beeL},
    {0x694341f608c9dd56L, 0xed3a181fabb30adcL, 0x1339a815da8b398fL, 0x2c6d4e4511657e1eL},
    {0x63e7cb4906ffc93fL, 0xf070bb00e28a193dL, 0xad1715b02e5713b5L, 0x4b5371495990693fL}};

/**
 * Stores the setup and parameters needed for performing FFTs.
 *
 * Initialise with #new_fft_settings. Free after use with #free_fft_settings.
 */
typedef struct {
    uint64_t max_width;            /**< The maximum size of FFT these settings support, a power of 2. */
    fr_t root_of_unity;            /**< The root of unity used to generate the lists in the structure. */
    fr_t *expanded_roots_of_unity; /**< Ascending powers of the root of unity, size `width + 1`. */
    fr_t *reverse_roots_of_unity;  /**< Descending powers of the root of unity, size `width + 1`. */
} FFTSettings;

C_KZG_RET expand_root_of_unity(fr_t *out, const fr_t *root, uint64_t width);
C_KZG_RET new_fft_settings(FFTSettings *s, unsigned int max_scale);
void free_fft_settings(FFTSettings *s);

#endif // FFT_COMMON