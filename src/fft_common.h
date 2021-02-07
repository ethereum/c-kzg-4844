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

#include "c_kzg.h"

// MODULUS = 52435875175126190479447740508185965837690552500527637822603658699938581184513
// PRIMITIVE_ROOT = 5
// [pow(PRIMITIVE_ROOT, (MODULUS - 1) // (2**i), MODULUS) for i in range(32)]
//
// These are not in `blst_fr` limb format and must be converted via `blst_fr_from_uint64()`
static const uint64_t scale2_root_of_unity[][4] = {
    {0x0000000000000001L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L},
    {0xffffffff00000000L, 0x53bda402fffe5bfeL, 0x3339d80809a1d805L, 0x73eda753299d7d48L},
    {0x0001000000000000L, 0xec03000276030000L, 0x8d51ccce760304d0L, 0x0000000000000000L},
    {0x8dd702cb688bc087L, 0xa032824078eaa4feL, 0xa733b23a98ca5b22L, 0x3f96405d25a31660L},
    {0x95df4b360411fe73L, 0x1ef4e672ebc1e1bbL, 0x6e92a9c460afca4aL, 0x4f2c596e753e4fccL},
    {0x9733f3a6ba60eaa6L, 0xbd7fdf9c77487ae7L, 0xd84f8612c8b6cc00L, 0x476fa2fb6162ffabL},
    {0xd2fc5e69ac5db47fL, 0xa12a70a615d0b8e4L, 0x293b1d67bc8de5d9L, 0x0e4840ac57f86f5eL},
    {0xb750da4cab28e208L, 0x501dff643be95635L, 0x8cbe2437f0b4b276L, 0x07d0c802a94a946eL},
    {0x2cabadec2fe322b8L, 0x752c84f315412560L, 0x32a732ae1a3b0aefL, 0x2e95da59a33dcbf2L},
    {0x33811ea1fe0c65f4L, 0x15c1ad4c687f28a2L, 0xecfbede342dee7f4L, 0x1bb466679a5d88b1L},
    {0xd58a5af42d010ff9L, 0x79efd6b0570bf109L, 0x3ed6d55a6350721dL, 0x2f27b09858f43cefL},
    {0x74a1f6718c130477L, 0xa534af14b61e0abeL, 0xeb674a1a620890d7L, 0x43527a8bca252472L},
    {0x450d9f977ea8ee05L, 0x565af17137d56fc0L, 0xe155cb4893f9e9acL, 0x110cebd0c8e9101bL},
    {0x23c9159959a0be92L, 0x87d188ce7a027759L, 0x70491431cab3c3ccL, 0x0ac00eb8b3f7f8daL},
    {0x13e96ade69583404L, 0x82c057275306243dL, 0x77e48bf529ca9f2aL, 0x50646ac81fe19595L},
    {0xe6a354dda97eccd4L, 0x39929d2e88fbbc57L, 0xa22ba63dd6e7b1c8L, 0x42c22911f5f07f43L},
    {0x137b458acfc35f7aL, 0x0caba63a29c01b06L, 0x0409ee987a02402cL, 0x6709c6cd56aa725bL},
    {0x10251f7d8831e03eL, 0x77d85a937ff858ecL, 0xebe905bd4fb9ac5cL, 0x05deb333f8727901L},
    {0xbf87b689b9009408L, 0x4f730e7ddd3ccc96L, 0xfd7f05ba4610300cL, 0x5ef5e8db0b8ac903L},
    {0x6499688417cd0c14L, 0xa672867368812f7fL, 0x2e1d9a1922cc3253L, 0x3a689e83aa0a1d80L},
    {0x20b53cbe41144deaL, 0x870c46fac2f0fcbdL, 0x556c35f6537d6971L, 0x3436287f5f686d91L},
    {0x007e082a436ba2e7L, 0x67c6630f9116e877L, 0x36f8f165fb4460f7L, 0x6eee34d57e7046e0L},
    {0xc5b670eea53a56d1L, 0x127d1f4253037d7bL, 0x57d4257ea722c2e2L, 0x03ae26a333cbd838L},
    {0x1e91484876504cf8L, 0x55bbbf1eb63edd02L, 0xbcdafec84e55aa02L, 0x5145c4cd2dc0beb0L},
    {0x5b90153a1ab70e2cL, 0x8deffa3175fb0ab8L, 0xc553ae2346900c95L, 0x1d31dcdc6bd3118cL},
    {0x801c894c59a2e8ebL, 0xbc535c5ce12fc974L, 0x95508d2747d39803L, 0x16d9d3cdac5d094fL},
    {0x810fa372cca1d8beL, 0xc67b8c2882e0bfa7L, 0xdbb4edf0e2d35bc2L, 0x712d15805087c995L},
    {0xeb162203fd88f133L, 0xac96c38ff010ea74L, 0x4307987fe64cfc70L, 0x350fe98d37b7a114L},
    {0xaba2f51842f2a254L, 0x4d7f3c3aa71efc0cL, 0x97ae418dd274a80aL, 0x2967385d5e3e7682L},
    {0x75c55c7b575a0b79L, 0x3ba4a15774a7ded1L, 0xc3974d73a04fccf3L, 0x705aba4f4a939684L},
    {0x8409a9ea14ebb608L, 0xfad0084e66bac611L, 0x04287254811c1dfbL, 0x086d072b23b30c29L},
    {0xb427c9b367e4756aL, 0xc7537fb902ebc38dL, 0x51de21becd6a205fL, 0x6064ab727923597dL}};

typedef struct {
    uint64_t max_width;
    blst_fr root_of_unity;
    blst_fr *expanded_roots_of_unity;
    blst_fr *reverse_roots_of_unity;
} FFTSettings;

bool is_power_of_two(const uint64_t n);
C_KZG_RET expand_root_of_unity(blst_fr *roots, const blst_fr *root_of_unity, const uint64_t width);
C_KZG_RET reverse(blst_fr *out, const blst_fr *roots, const uint64_t width);
C_KZG_RET new_fft_settings(FFTSettings *s, const unsigned int max_scale);
void free_fft_settings(FFTSettings *s);
