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

#include "c_kzg_4844.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

/**
 * Wrapped `malloc()` that reports failures to allocate.
 *
 * @param[out] x Pointer to the allocated space
 * @param[in]  n The number of bytes to be allocated
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
static C_KZG_RET c_kzg_malloc(void **x, size_t n) {
    if (n > 0) {
        *x = malloc(n);
        return *x != NULL ? C_KZG_OK : C_KZG_MALLOC;
    }
    *x = NULL;
    return C_KZG_OK;
}

#define CHECK(cond)                                                                                                    \
    if (!(cond)) return C_KZG_BADARGS

#define TRY(result)                                                                                                    \
    {                                                                                                                  \
        C_KZG_RET ret = (result);                                                                                      \
        if (ret == C_KZG_MALLOC) return ret;                                                                           \
        if (ret != C_KZG_OK) return C_KZG_ERROR;                                                                       \
    }

/**
 * Allocate memory for an array of G1 group elements.
 *
 * @remark Free the space later using `free()`.
 *
 * @param[out] x Pointer to the allocated space
 * @param[in]  n The number of G1 elements to be allocated
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
static C_KZG_RET new_g1_array(g1_t **x, size_t n) {
    return c_kzg_malloc((void **)x, n * sizeof **x);
}

/**
 * Allocate memory for an array of G2 group elements.
 *
 * @remark Free the space later using `free()`.
 *
 * @param[out] x Pointer to the allocated space
 * @param[in]  n The number of G2 elements to be allocated
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
static C_KZG_RET new_g2_array(g2_t **x, size_t n) {
    return c_kzg_malloc((void **)x, n * sizeof **x);
}

/**
 * Allocate memory for an array of field elements.
 *
 * @remark Free the space later using `free()`.
 *
 * @param[out] x Pointer to the allocated space
 * @param[in]  n The number of field elements to be allocated
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
static C_KZG_RET new_fr_array(fr_t **x, size_t n) {
    return c_kzg_malloc((void **)x, n * sizeof **x);
}

/**
 * Fast log base 2 of a byte.
 *
 * Corresponds to the index of the highest bit set in the byte. Adapted from
 * https://graphics.stanford.edu/~seander/bithacks.html#IntegerLog.
 *
 * @param[in] b A non-zero byte
 * @return The index of the highest set bit
 */
static int log_2_byte(byte b) {
    int r, shift;
    r = (b > 0xF) << 2;
    b >>= r;
    shift = (b > 0x3) << 1;
    b >>= (shift + 1);
    r |= shift | b;
    return r;
}

/** The zero field element */
static const fr_t fr_zero = {0L, 0L, 0L, 0L};

/** This is 1 in Blst's `blst_fr` limb representation. Crazy but true. */
static const fr_t fr_one = {0x00000001fffffffeL, 0x5884b7fa00034802L, 0x998c4fefecbc4ff5L, 0x1824b159acc5056fL};

/**
 * Create a field element from an array of four 64-bit unsigned integers.
 *
 * @param out  The field element equivalent of @p vals
 * @param vals The array of 64-bit integers to be converted, little-endian ordering of the 64-bit words
 */
static void fr_from_uint64s(fr_t *out, const uint64_t vals[4]) {
    blst_fr_from_uint64(out, vals);
}

/**
 * Test whether the operand is one in the finite field.
 *
 * @param p The field element to be checked
 * @retval true The element is one
 * @retval false The element is not one
 *
 * @todo See if there is a more efficient way to check for one in the finite field.
 */
static bool fr_is_one(const fr_t *p) {
    uint64_t a[4];
    blst_uint64_from_fr(a, p);
    return a[0] == 1 && a[1] == 0 && a[2] == 0 && a[3] == 0;
}

/**
 * Test whether two field elements are equal.
 *
 * @param[in] aa The first element
 * @param[in] bb The second element
 * @retval true if @p aa and @p bb are equal
 * @retval false otherwise
 */
static bool fr_equal(const fr_t *aa, const fr_t *bb) {
    uint64_t a[4], b[4];
    blst_uint64_from_fr(a, aa);
    blst_uint64_from_fr(b, bb);
    return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3];
}

/**
 * Add two field elements.
 *
 * @param[out] out @p a plus @p b in the field
 * @param[in]  a   Field element
 * @param[in]  b   Field element
 */
static void fr_add(fr_t *out, const fr_t *a, const fr_t *b) {
    blst_fr_add(out, a, b);
}

/**
 * Subtract one field element from another.
 *
 * @param[out] out @p a minus @p b in the field
 * @param[in]  a   Field element
 * @param[in]  b   Field element
 */
static void fr_sub(fr_t *out, const fr_t *a, const fr_t *b) {
    blst_fr_sub(out, a, b);
}

/**
 * Multiply two field elements.
 *
 * @param[out] out @p a multiplied by @p b in the field
 * @param[in]  a   Multiplicand
 * @param[in]  b   Multiplier
 */
static void fr_mul(fr_t *out, const fr_t *a, const fr_t *b) {
    blst_fr_mul(out, a, b);
}

/**
 * Division of two field elements.
 *
 * @param[out] out @p a divided by @p b in the field
 * @param[in]  a   The dividend
 * @param[in]  b   The divisor
 */
static void fr_div(fr_t *out, const fr_t *a, const fr_t *b) {
    blst_fr tmp;
    blst_fr_eucl_inverse(&tmp, b);
    blst_fr_mul(out, a, &tmp);
}

/**
 * Square a field element.
 *
 * @param[out] out @p a squared
 * @param[in]  a   A field element
 */
static void fr_sqr(fr_t *out, const fr_t *a) {
    blst_fr_sqr(out, a);
}

/**
 * Exponentiation of a field element.
 *
 * Uses square and multiply for log(@p n) performance.
 *
 * @remark A 64-bit exponent is sufficient for our needs here.
 *
 * @param[out] out @p a raised to the power of @p n
 * @param[in]  a   The field element to be exponentiated
 * @param[in]  n   The exponent
 */
static void fr_pow(fr_t *out, const fr_t *a, uint64_t n) {
    fr_t tmp = *a;
    *out = fr_one;

    while (true) {
        if (n & 1) {
            fr_mul(out, out, &tmp);
        }
        if ((n >>= 1) == 0) break;
        fr_sqr(&tmp, &tmp);
    }
}

/**
 * Create a field element from a single 64-bit unsigned integer.
 *
 * @remark This can only generate a tiny fraction of possible field elements, and is mostly useful for testing.
 *
 * @param out The field element equivalent of @p n
 * @param n   The 64-bit integer to be converted
 */
static void fr_from_uint64(fr_t *out, uint64_t n) {
    uint64_t vals[] = {n, 0, 0, 0};
    fr_from_uint64s(out, vals);
}

/**
 * Inverse of a field element.
 *
 * @param[out] out The inverse of @p a
 * @param[in]  a   A field element
 */
static void fr_inv(fr_t *out, const fr_t *a) {
    blst_fr_eucl_inverse(out, a);
}

/**
 * Montgomery batch inversion in finite field
 *
 * @param[out] out The inverses of @p a, length @p len
 * @param[in]  a   A vector of field elements, length @p len
 * @param[in]  len Length
 */
static C_KZG_RET fr_batch_inv(fr_t *out, const fr_t *a, size_t len) {
    fr_t *prod;
    fr_t inv;
    size_t i;

    TRY(new_fr_array(&prod, len));

    prod[0] = a[0];

    for(i = 1; i < len; i++) {
        fr_mul(&prod[i], &a[i], &prod[i - 1]);
    }

    blst_fr_eucl_inverse(&inv, &prod[len - 1]);

    for(i = len - 1; i > 0; i--) {
        fr_mul(&out[i], &inv, &prod[i - 1]);
        fr_mul(&inv, &a[i], &inv);
    }
    out[0] = inv;

    free(prod);

    return C_KZG_OK;
}


/** The G1 identity/infinity */
static const g1_t g1_identity = {{0L, 0L, 0L, 0L, 0L, 0L}, {0L, 0L, 0L, 0L, 0L, 0L}, {0L, 0L, 0L, 0L, 0L, 0L}};

/** The G1 generator */
static const g1_t g1_generator = {{0x5cb38790fd530c16L, 0x7817fc679976fff5L, 0x154f95c7143ba1c1L, 0xf0ae6acdf3d0e747L,
                                   0xedce6ecc21dbf440L, 0x120177419e0bfb75L},
                                  {0xbaac93d50ce72271L, 0x8c22631a7918fd8eL, 0xdd595f13570725ceL, 0x51ac582950405194L,
                                   0x0e1c8c3fad0059c0L, 0x0bbc3efc5008a26aL},
                                  {0x760900000002fffdL, 0xebf4000bc40c0002L, 0x5f48985753c758baL, 0x77ce585370525745L,
                                   0x5c071a97a256ec6dL, 0x15f65ec3fa80e493L}};

/** The G2 generator */
static const g2_t g2_generator = {{{{0xf5f28fa202940a10L, 0xb3f5fb2687b4961aL, 0xa1a893b53e2ae580L, 0x9894999d1a3caee9L,
                                     0x6f67b7631863366bL, 0x058191924350bcd7L},
                                    {0xa5a9c0759e23f606L, 0xaaa0c59dbccd60c3L, 0x3bb17e18e2867806L, 0x1b1ab6cc8541b367L,
                                     0xc2b6ed0ef2158547L, 0x11922a097360edf3L}}},
                                  {{{0x4c730af860494c4aL, 0x597cfa1f5e369c5aL, 0xe7e6856caa0a635aL, 0xbbefb5e96e0d495fL,
                                     0x07d3a975f0ef25a2L, 0x0083fd8e7e80dae5L},
                                    {0xadc0fc92df64b05dL, 0x18aa270a2b1461dcL, 0x86adac6a3be4eba0L, 0x79495c4ec93da33aL,
                                     0xe7175850a43ccaedL, 0x0b2bc2a163de1bf2L}}},
                                  {{{0x760900000002fffdL, 0xebf4000bc40c0002L, 0x5f48985753c758baL, 0x77ce585370525745L,
                                     0x5c071a97a256ec6dL, 0x15f65ec3fa80e493L},
                                    {0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L,
                                     0x0000000000000000L, 0x0000000000000000L}}}};


/**
 * Add or double G1 points.
 *
 * This is safe if the two points are the same.
 *
 * @param[out] out @p a plus @p b in the group
 * @param[in]  a   G1 group point
 * @param[in]  b   G1 group point
 */
static void g1_add_or_dbl(g1_t *out, const g1_t *a, const g1_t *b) {
    blst_p1_add_or_double(out, a, b);
}

/**
 * Multiply a G1 group element by a field element.
 *
 * This "undoes" the Blst constant-timedness. FFTs do a lot of multiplication by one, so constant time is rather slow.
 *
 * @param[out] out [@p b]@p a
 * @param[in]  a   The G1 group element
 * @param[in]  b   The multiplier
 */
static void g1_mul(g1_t *out, const g1_t *a, const fr_t *b) {
    blst_scalar s;
    blst_scalar_from_fr(&s, b);

    // Count the number of bytes to be multiplied.
    int i = sizeof(blst_scalar);
    while (i && !s.b[i - 1]) --i;
    if (i == 0) {
        *out = g1_identity;
    } else if (i == 1 && s.b[0] == 1) {
        *out = *a;
    } else {
        // Count the number of bits to be multiplied.
        blst_p1_mult(out, a, s.b, 8 * i - 7 + log_2_byte(s.b[i - 1]));
    }
}

/**
 * Subtraction of G1 group elements.
 *
 * @param[out] out @p a - @p b
 * @param[in]  a   A G1 group element
 * @param[in]  b   The G1 group element to be subtracted
 */
static void g1_sub(g1_t *out, const g1_t *a, const g1_t *b) {
    g1_t bneg = *b;
    blst_p1_cneg(&bneg, true);
    blst_p1_add_or_double(out, a, &bneg);
}

/**
 * Subtraction of G2 group elements.
 *
 * @param[out] out @p a - @p b
 * @param[in]  a   A G2 group element
 * @param[in]  b   The G2 group element to be subtracted
 */
static void g2_sub(g2_t *out, const g2_t *a, const g2_t *b) {
    g2_t bneg = *b;
    blst_p2_cneg(&bneg, true);
    blst_p2_add_or_double(out, a, &bneg);
}

/**
 * Multiply a G2 group element by a field element.
 *
 * @param[out] out [@p b]@p a
 * @param[in]  a   The G2 group element
 * @param[in]  b   The multiplier
 */
static void g2_mul(g2_t *out, const g2_t *a, const fr_t *b) {
    blst_scalar s;
    blst_scalar_from_fr(&s, b);
    blst_p2_mult(out, a, s.b, 8 * sizeof(blst_scalar));
}


/**
 * Utility function to test whether the argument is a power of two.
 *
 * @remark This method returns `true` for `is_power_of_two(0)` which is a bit weird, but not an issue in the contexts in
 * which we use it.
 *
 * @param[in] n The number to test
 * @retval true  if @p n is a power of two or zero
 * @retval false otherwise
 */
static bool is_power_of_two(uint64_t n) {
    return (n & (n - 1)) == 0;
}

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
 * Discrete fourier transforms over arrays of G1 group elements.
 *
 * Also known as [number theoretic
 * transforms](https://en.wikipedia.org/wiki/Discrete_Fourier_transform_(general)#Number-theoretic_transform).
 *
 * @remark Functions here work only for lengths that are a power of two.
 */

/**
 * Fast Fourier Transform.
 *
 * Recursively divide and conquer.
 *
 * @param[out] out    The results (array of length @p n)
 * @param[in]  in     The input data (array of length @p n * @p stride)
 * @param[in]  stride The input data stride
 * @param[in]  roots  Roots of unity (array of length @p n * @p roots_stride)
 * @param[in]  roots_stride The stride interval among the roots of unity
 * @param[in]  n      Length of the FFT, must be a power of two
 */
static void fft_g1_fast(g1_t *out, const g1_t *in, uint64_t stride, const fr_t *roots, uint64_t roots_stride,
                        uint64_t n) {
    uint64_t half = n / 2;
    if (half > 0) { // Tunable parameter
        fft_g1_fast(out, in, stride * 2, roots, roots_stride * 2, half);
        fft_g1_fast(out + half, in + stride, stride * 2, roots, roots_stride * 2, half);
        for (uint64_t i = 0; i < half; i++) {
            g1_t y_times_root;
            g1_mul(&y_times_root, &out[i + half], &roots[i * roots_stride]);
            g1_sub(&out[i + half], &out[i], &y_times_root);
            g1_add_or_dbl(&out[i], &out[i], &y_times_root);
        }
    } else {
        *out = *in;
    }
}

/**
 * The main entry point for forward and reverse FFTs over the finite field.
 *
 * @param[out] out     The results (array of length @p n)
 * @param[in]  in      The input data (array of length @p n)
 * @param[in]  inverse `false` for forward transform, `true` for inverse transform
 * @param[in]  n       Length of the FFT, must be a power of two
 * @param[in]  fs      Pointer to previously initialised FFTSettings structure with `max_width` at least @p n.
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 */
static C_KZG_RET fft_g1(g1_t *out, const g1_t *in, bool inverse, uint64_t n, const FFTSettings *fs) {
    uint64_t stride = fs->max_width / n;
    CHECK(n <= fs->max_width);
    CHECK(is_power_of_two(n));
    if (inverse) {
        fr_t inv_len;
        fr_from_uint64(&inv_len, n);
        fr_inv(&inv_len, &inv_len);
        fft_g1_fast(out, in, 1, fs->reverse_roots_of_unity, stride, n);
        for (uint64_t i = 0; i < n; i++) {
            g1_mul(&out[i], &out[i], &inv_len);
        }
    } else {
        fft_g1_fast(out, in, 1, fs->expanded_roots_of_unity, stride, n);
    }
    return C_KZG_OK;
}

/**
 * Generate powers of a root of unity in the field for use in the FFTs.
 *
 * @remark @p root must be such that @p root ^ @p width is equal to one, but no smaller power of @p root is equal to
 * one.
 *
 * @param[out] out   The generated powers of the root of unity (array size @p width + 1)
 * @param[in]  root  A root of unity
 * @param[in]  width One less than the size of @p out
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 */
static C_KZG_RET expand_root_of_unity(fr_t *out, const fr_t *root, uint64_t width) {
    out[0] = fr_one;
    out[1] = *root;

    for (uint64_t i = 2; !fr_is_one(&out[i - 1]); i++) {
        CHECK(i <= width);
        fr_mul(&out[i], &out[i - 1], root);
    }
    CHECK(fr_is_one(&out[width]));

    return C_KZG_OK;
}


/**
 * Reverse the bits in a byte.
 *
 * From https://graphics.stanford.edu/~seander/bithacks.html#ReverseByteWith64BitsDiv
 *
 * @param a A byte
 * @return A byte that is bit-reversed with respect to @p a
 *
 * @todo Benchmark some of the other bit-reversal options in the list. Maybe.
 */
#define rev_byte(a) ((((a)&0xff) * 0x0202020202ULL & 0x010884422010ULL) % 1023)

/**
 * Reverse the bits in a 32 bit word.
 *
 * @param a A 32 bit unsigned integer
 * @return A 32 bit unsigned integer that is bit-reversed with respect to @p a
 */
#define rev_4byte(a) (rev_byte(a) << 24 | rev_byte((a) >> 8) << 16 | rev_byte((a) >> 16) << 8 | rev_byte((a) >> 24))

/**
 * Calculate log base two of a power of two.
 *
 * In other words, the bit index of the one bit.
 *
 * @remark Works only for n a power of two, and only for n up to 2^31.
 *
 * @param[in] n The power of two
 * @return the log base two of n
 */
static int log2_pow2(uint32_t n) {
    const uint32_t b[] = {0xAAAAAAAA, 0xCCCCCCCC, 0xF0F0F0F0, 0xFF00FF00, 0xFFFF0000};
    register uint32_t r;
    r = (n & b[0]) != 0;
    r |= ((n & b[1]) != 0) << 1;
    r |= ((n & b[2]) != 0) << 2;
    r |= ((n & b[3]) != 0) << 3;
    r |= ((n & b[4]) != 0) << 4;
    return r;
}

/**
 * Reverse the bit order in a 32 bit integer.
 *
 * @remark This simply wraps the macro to enforce the type check.
 *
 * @param[in] a The integer to be reversed
 * @return An integer with the bits of @p a reversed
 */
static uint32_t reverse_bits(uint32_t a) {
    return rev_4byte(a);
}

/**
 * Reorder an array in reverse bit order of its indices.
 *
 * @remark Operates in-place on the array.
 * @remark Can handle arrays of any type: provide the element size in @p size.
 *
 * @param[in,out] values The array, which is re-ordered in-place
 * @param[in]     size   The size in bytes of an element of the array
 * @param[in]     n      The length of the array, must be a power of two less that 2^32
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 */
static C_KZG_RET reverse_bit_order(void *values, size_t size, uint64_t n) {
    CHECK(n >> 32 == 0);
    CHECK(is_power_of_two(n));

    // Pointer arithmetic on `void *` is naughty, so cast to something definite
    byte *v = values;
    byte tmp[size];
    int unused_bit_len = 32 - log2_pow2(n);
    for (uint32_t i = 0; i < n; i++) {
        uint32_t r = reverse_bits(i) >> unused_bit_len;
        if (r > i) {
            // Swap the two elements
            memcpy(tmp, v + (i * size), size);
            memcpy(v + (i * size), v + (r * size), size);
            memcpy(v + (r * size), tmp, size);
        }
    }

    return C_KZG_OK;
}

/**
 * Initialise an FFTSettings structure.
 *
 * Space is allocated for, and arrays are populated with, powers of the roots of unity. The two arrays contain the same
 * values in reverse order for convenience in inverse FFTs.
 *
 * `max_width` is the maximum size of FFT that can be calculated with these settings, and is a power of two by
 * construction. The same settings may be used to calculated FFTs of smaller power sizes.
 *
 * @remark As with all functions prefixed `new_`, this allocates memory that needs to be reclaimed by calling the
 * corresponding `free_` function. In this case, #free_fft_settings.
 * @remark These settings may be used for FFTs on both field elements and G1 group elements.
 *
 * @param[out] fs        The new settings
 * @param[in]  max_scale Log base 2 of the max FFT size to be used with these settings
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_ERROR   An internal error occurred
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
static C_KZG_RET new_fft_settings(FFTSettings *fs, unsigned int max_scale) {
    fr_t root_of_unity;

    fs->max_width = (uint64_t)1 << max_scale;

    CHECK((max_scale < sizeof scale2_root_of_unity / sizeof scale2_root_of_unity[0]));
    fr_from_uint64s(&root_of_unity, scale2_root_of_unity[max_scale]);

    // Allocate space for the roots of unity
    TRY(new_fr_array(&fs->expanded_roots_of_unity, fs->max_width + 1));
    TRY(new_fr_array(&fs->reverse_roots_of_unity, fs->max_width + 1));
    TRY(new_fr_array(&fs->roots_of_unity, fs->max_width));

    // Populate the roots of unity
    TRY(expand_root_of_unity(fs->expanded_roots_of_unity, &root_of_unity, fs->max_width));

    // Populate reverse roots of unity
    for (uint64_t i = 0; i <= fs->max_width; i++) {
        fs->reverse_roots_of_unity[i] = fs->expanded_roots_of_unity[fs->max_width - i];
    }

    // Permute the roots of unity
    memcpy(fs->roots_of_unity, fs->expanded_roots_of_unity, sizeof(fr_t) * fs->max_width);
    TRY(reverse_bit_order(fs->roots_of_unity, sizeof(fr_t), fs->max_width));

    return C_KZG_OK;
}

/**
 * Free the memory that was previously allocated by #new_fft_settings.
 *
 * @param fs The settings to be freed
 */
static void free_fft_settings(FFTSettings *fs) {
    free(fs->expanded_roots_of_unity);
    free(fs->reverse_roots_of_unity);
    free(fs->roots_of_unity);
    free(fs);
}

/**
 * Free the memory that was previously allocated by #new_kzg_settings.
 *
 * @param ks The settings to be freed
 */
static void free_kzg_settings(KZGSettings *ks) {
    free(ks->g1_values);
    free(ks->g2_values);
}


/**
 * Perform pairings and test whether the outcomes are equal in G_T.
 *
 * Tests whether `e(a1, a2) == e(b1, b2)`.
 *
 * @param[in] a1 A G1 group point for the first pairing
 * @param[in] a2 A G2 group point for the first pairing
 * @param[in] b1 A G1 group point for the second pairing
 * @param[in] b2 A G2 group point for the second pairing
 * @retval true  The pairings were equal
 * @retval false The pairings were not equal
 */
static bool pairings_verify(const g1_t *a1, const g2_t *a2, const g1_t *b1, const g2_t *b2) {
    blst_fp12 loop0, loop1, gt_point;
    blst_p1_affine aa1, bb1;
    blst_p2_affine aa2, bb2;

    // As an optimisation, we want to invert one of the pairings,
    // so we negate one of the points.
    g1_t a1neg = *a1;
    blst_p1_cneg(&a1neg, true);

    blst_p1_to_affine(&aa1, &a1neg);
    blst_p1_to_affine(&bb1, b1);
    blst_p2_to_affine(&aa2, a2);
    blst_p2_to_affine(&bb2, b2);

    blst_miller_loop(&loop0, &aa2, &aa1);
    blst_miller_loop(&loop1, &bb2, &bb1);

    blst_fp12_mul(&gt_point, &loop0, &loop1);
    blst_final_exp(&gt_point, &gt_point);

    return blst_fp12_is_one(&gt_point);
}


typedef BLSFieldElement Polynomial[FIELD_ELEMENTS_PER_BLOB];

void bytes_from_g1(uint8_t out[48], const g1_t *in) {
  blst_p1_compress(out, in);
}

C_KZG_RET bytes_to_g1(g1_t* out, const uint8_t bytes[48]) {
  blst_p1_affine tmp;
  if (blst_p1_uncompress(&tmp, bytes) != BLST_SUCCESS)
    return C_KZG_BADARGS;
  blst_p1_from_affine(out, &tmp);
  return C_KZG_OK;
}

static void bytes_from_bls_field(uint8_t out[32], const BLSFieldElement *in) {
  blst_scalar_from_fr((blst_scalar*)out, in);
}

C_KZG_RET load_trusted_setup(KZGSettings *out, const uint8_t g1_bytes[], size_t n1, const uint8_t g2_bytes[], size_t n2) {
  uint64_t i;
  blst_p2_affine g2_affine;
  g1_t *g1_projective;

  TRY(new_g1_array(&out->g1_values, n1));
  TRY(new_g2_array(&out->g2_values, n2));

  TRY(new_g1_array(&g1_projective, n1));

  for (i = 0; i < n1; i++)
    bytes_to_g1(&g1_projective[i], &g1_bytes[48 * i]);

  for (i = 0; i < n2; i++) {
    blst_p2_uncompress(&g2_affine, &g2_bytes[96 * i]);
    blst_p2_from_affine(&out->g2_values[i], &g2_affine);
  }

  unsigned int max_scale = 0;
  while (((uint64_t)1 << max_scale) < n1) max_scale++;

  out->fs = (FFTSettings*)malloc(sizeof(FFTSettings));
  if (out->fs == NULL) { free(g1_projective); return C_KZG_MALLOC; }

  C_KZG_RET ret;
  ret = new_fft_settings((FFTSettings*)out->fs, max_scale);
  if (ret != C_KZG_OK) { free(g1_projective); return ret; }

  ret = fft_g1(out->g1_values, g1_projective, true, n1, out->fs);
  free(g1_projective);
  if (ret != C_KZG_OK) return ret;

  TRY(reverse_bit_order(out->g1_values, sizeof(g1_t), n1));

  return C_KZG_OK;
}

C_KZG_RET load_trusted_setup_file(KZGSettings *out, FILE *in) {
  uint64_t i;

  fscanf(in, "%" SCNu64, &i);
  CHECK(i == FIELD_ELEMENTS_PER_BLOB);
  fscanf(in, "%" SCNu64, &i);
  CHECK(i == 65);

  uint8_t g1_bytes[FIELD_ELEMENTS_PER_BLOB * 48];
  uint8_t g2_bytes[65 * 96];

  for (i = 0; i < FIELD_ELEMENTS_PER_BLOB * 48; i++)
    fscanf(in, "%2hhx", &g1_bytes[i]);

  for (i = 0; i < 65 * 96; i++)
    fscanf(in, "%2hhx", &g2_bytes[i]);

  return load_trusted_setup(out, g1_bytes, FIELD_ELEMENTS_PER_BLOB, g2_bytes, 65);
}

void free_trusted_setup(KZGSettings *s) {
  free_fft_settings((FFTSettings*)s->fs);
  free_kzg_settings(s);
}

static void compute_powers(BLSFieldElement out[], BLSFieldElement *x, uint64_t n) {
  BLSFieldElement current_power = fr_one;
  for (uint64_t i = 0; i < n; i++) {
    out[i] = current_power;
    fr_mul(&current_power, &current_power, x);
  }
}

static void hash_to_bls_field(BLSFieldElement *out, const uint8_t bytes[32]) {
  blst_scalar tmp;
  blst_scalar_from_lendian(&tmp, bytes);
  blst_fr_from_scalar(out, &tmp);
}

C_KZG_RET bytes_to_bls_field(BLSFieldElement *out, const uint8_t bytes[32]) {
  blst_scalar tmp;
  blst_scalar_from_lendian(&tmp, bytes);
  if (!blst_scalar_fr_check(&tmp)) return C_KZG_BADARGS;
  blst_fr_from_scalar(out, &tmp);
  return C_KZG_OK;
}

static void poly_lincomb(Polynomial out, const Polynomial vectors[], const fr_t scalars[], uint64_t n) {
  fr_t tmp;
  uint64_t i, j;
  for (j = 0; j < FIELD_ELEMENTS_PER_BLOB; j++)
    out[j] = fr_zero;
  for (i = 0; i < n; i++) {
    for (j = 0; j < FIELD_ELEMENTS_PER_BLOB; j++) {
      fr_mul(&tmp, &scalars[i], &vectors[i][j]);
      fr_add(&out[j], &out[j], &tmp);
    }
  }
}

/**
 * Calculate a linear combination of G1 group elements.
 *
 * Calculates `[coeffs_0]p_0 + [coeffs_1]p_1 + ... + [coeffs_n]p_n` where `n` is `len - 1`.
 *
 * @param[out] out    The resulting sum-product
 * @param[in]  p      Array of G1 group elements, length @p len
 * @param[in]  coeffs Array of field elements, length @p len
 * @param[in]  len    The number of group/field elements
 *
 * For the benefit of future generations (since Blst has no documentation to speak of),
 * there are two ways to pass the arrays of scalars and points into `blst_p1s_mult_pippenger()`.
 *
 * 1. Pass `points` as an array of pointers to the points, and pass `scalars` as an array of pointers to the scalars,
 * each of length @p len.
 * 2. Pass an array where the first element is a pointer to the contiguous array of points and the second is null, and
 * similarly for scalars.
 *
 * We do the second of these to save memory here.
 */
static C_KZG_RET g1_lincomb(g1_t *out, const g1_t *p, const fr_t *coeffs, const uint64_t len) {
    if (len < 8) { // Tunable parameter: must be at least 2 since Blst fails for 0 or 1
        // Direct approach
        g1_t tmp;
        *out = g1_identity;
        for (uint64_t i = 0; i < len; i++) {
            g1_mul(&tmp, &p[i], &coeffs[i]);
            blst_p1_add_or_double(out, out, &tmp);
        }
    } else {
        // Blst's implementation of the Pippenger method
        void *scratch = malloc(blst_p1s_mult_pippenger_scratch_sizeof(len));
        if (scratch == NULL) return C_KZG_MALLOC;
        blst_p1_affine *p_affine = malloc(len * sizeof(blst_p1_affine));
        if (p_affine == NULL) { free(scratch); return C_KZG_MALLOC; }
        blst_scalar *scalars = malloc(len * sizeof(blst_scalar));
        if (scalars == NULL) { free(scratch); free(p_affine); return C_KZG_MALLOC; }

        // Transform the points to affine representation
        const blst_p1 *p_arg[2] = {p, NULL};
        blst_p1s_to_affine(p_affine, p_arg, len);

        // Transform the field elements to 256-bit scalars
        for (int i = 0; i < len; i++) {
            blst_scalar_from_fr(&scalars[i], &coeffs[i]);
        }

        // Call the Pippenger implementation
        const byte *scalars_arg[2] = {(byte *)scalars, NULL};
        const blst_p1_affine *points_arg[2] = {p_affine, NULL};
        blst_p1s_mult_pippenger(out, points_arg, len, scalars_arg, 256, scratch);

        // Tidy up
        free(scratch);
        free(p_affine);
        free(scalars);
    }
    return C_KZG_OK;
}

static C_KZG_RET poly_to_kzg_commitment(KZGCommitment *out, const Polynomial p, const KZGSettings *s) {
  return g1_lincomb(out, s->g1_values, p, FIELD_ELEMENTS_PER_BLOB);
}

static C_KZG_RET poly_from_blob(Polynomial p, const Blob blob) {
  C_KZG_RET ret;
  for (size_t i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++) {
    ret = bytes_to_bls_field(&p[i], &blob[i * BYTES_PER_FIELD_ELEMENT]);
    if (ret != C_KZG_OK) return ret;
  }
  return C_KZG_OK;
}

C_KZG_RET blob_to_kzg_commitment(KZGCommitment *out, const Blob blob, const KZGSettings *s) {
  Polynomial p;
  C_KZG_RET ret = poly_from_blob(p, blob);
  if (ret != C_KZG_OK) return ret;
  return poly_to_kzg_commitment(out, p, s);
}

/**
 * Check a KZG proof at a point against a commitment.
 *
 * Given a @p commitment to a polynomial, a @p proof for @p x, and the claimed value @p y at @p x, verify the claim.
 *
 * @param[out] out        `true` if the proof is valid, `false` if not
 * @param[in]  commitment The commitment to a polynomial
 * @param[in]  x          The point at which the proof is to be checked (opened)
 * @param[in]  y          The claimed value of the polynomial at @p x
 * @param[in]  proof      A proof of the value of the polynomial at the point @p x
 * @param[in]  ks  The settings containing the secrets, previously initialised with #new_kzg_settings
 * @retval C_CZK_OK      All is well
 */
static C_KZG_RET verify_kzg_proof_impl(bool *out, const g1_t *commitment, const fr_t *x, const fr_t *y,
                           const g1_t *proof, const KZGSettings *ks) {
    g2_t x_g2, s_minus_x;
    g1_t y_g1, commitment_minus_y;
    g2_mul(&x_g2, &g2_generator, x);
    g2_sub(&s_minus_x, &ks->g2_values[1], &x_g2);
    g1_mul(&y_g1, &g1_generator, y);
    g1_sub(&commitment_minus_y, commitment, &y_g1);

    *out = pairings_verify(&commitment_minus_y, &g2_generator, proof, &s_minus_x);

    return C_KZG_OK;
}

C_KZG_RET verify_kzg_proof(bool *out,
    const KZGCommitment *commitment,
    const uint8_t z[BYTES_PER_FIELD_ELEMENT],
    const uint8_t y[BYTES_PER_FIELD_ELEMENT],
    const KZGProof *kzg_proof,
    const KZGSettings *s) {
  BLSFieldElement frz, fry;
  C_KZG_RET ret;
  ret = bytes_to_bls_field(&frz, z); if (ret != C_KZG_OK) return ret;
  ret = bytes_to_bls_field(&fry, y); if (ret != C_KZG_OK) return ret;
  return verify_kzg_proof_impl(out, commitment, &frz, &fry, kzg_proof, s);
}

static C_KZG_RET evaluate_polynomial_in_evaluation_form(BLSFieldElement *out, const Polynomial p, const BLSFieldElement *x, const KZGSettings *s) {
  fr_t tmp, *inverses_in, *inverses;
  uint64_t i;
  const fr_t *roots_of_unity = s->fs->roots_of_unity;

  TRY(new_fr_array(&inverses_in, FIELD_ELEMENTS_PER_BLOB));
  TRY(new_fr_array(&inverses, FIELD_ELEMENTS_PER_BLOB));
  for (i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++) {
    if (fr_equal(x, &roots_of_unity[i])) {
      *out = p[i];
      free(inverses_in);
      free(inverses);
      return C_KZG_OK;
    }
    fr_sub(&inverses_in[i], x, &roots_of_unity[i]);
  }
  TRY(fr_batch_inv(inverses, inverses_in, FIELD_ELEMENTS_PER_BLOB));

  *out = fr_zero;
  for (i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++) {
    fr_mul(&tmp, &inverses[i], &roots_of_unity[i]);
    fr_mul(&tmp, &tmp, &p[i]);
    fr_add(out, out, &tmp);
  }
  fr_from_uint64(&tmp, FIELD_ELEMENTS_PER_BLOB);
  fr_div(out, out, &tmp);
  fr_pow(&tmp, x, FIELD_ELEMENTS_PER_BLOB);
  fr_sub(&tmp, &tmp, &fr_one);
  fr_mul(out, out, &tmp);

  free(inverses_in);
  free(inverses);

  return C_KZG_OK;
}

/**
 * Compute KZG proof for polynomial in Lagrange form at position x
 *
 * @param[out] out The combined proof as a single G1 element
 * @param[in]  p   The polynomial in Lagrange form
 * @param[in]  x   The generator x-value for the evaluation points
 * @param[in]  s   The settings containing the secrets, previously initialised with #new_kzg_settings
 * @retval C_KZG_OK      All is well
 * @retval C_KZG_ERROR   An internal error occurred
 * @retval C_KZG_MALLOC  Memory allocation failed
 */
static C_KZG_RET compute_kzg_proof(KZGProof *out, const Polynomial p, const BLSFieldElement *x, const KZGSettings *s) {
  BLSFieldElement y;
  TRY(evaluate_polynomial_in_evaluation_form(&y, p, x, s));

  fr_t tmp;
  Polynomial q;
  const fr_t *roots_of_unity = s->fs->roots_of_unity;
  uint64_t i, m = 0;

  fr_t *inverses_in, *inverses;

  TRY(new_fr_array(&inverses_in, FIELD_ELEMENTS_PER_BLOB));
  C_KZG_RET ret;
  ret = new_fr_array(&inverses, FIELD_ELEMENTS_PER_BLOB);
  if (ret != C_KZG_OK) { free(inverses_in); return ret; }

  for (i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++) {
    if (fr_equal(x, &roots_of_unity[i])) {
      m = i + 1;
      continue;
    }
    // (p_i - y) / (ω_i - x)
    fr_sub(&q[i], &p[i], &y);
    fr_sub(&inverses_in[i], &roots_of_unity[i], x);
  }

  ret = fr_batch_inv(inverses, inverses_in, FIELD_ELEMENTS_PER_BLOB);
  if (ret != C_KZG_OK) { free(inverses_in); free(inverses); return ret; }

  for (i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++) {
    fr_mul(&q[i], &q[i], &inverses[i]);
  }

  if (m) { // ω_m == x
    q[--m] = fr_zero;
    for (i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++) {
      if (i == m) continue;
      // (p_i - y) * ω_i / (x * (x - ω_i))
      fr_sub(&tmp, x, &roots_of_unity[i]);
      fr_mul(&inverses_in[i], &tmp, x);
    }
    ret = fr_batch_inv(inverses, inverses_in, FIELD_ELEMENTS_PER_BLOB);
    if (ret != C_KZG_OK) { free(inverses_in); free(inverses); return ret; }
    for (i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++) {
      fr_sub(&tmp, &p[i], &y);
      fr_mul(&tmp, &tmp, &roots_of_unity[i]);
      fr_mul(&tmp, &tmp, &inverses[i]);
      fr_add(&q[m], &q[m], &tmp);
    }
  }

  free(inverses_in);
  free(inverses);

  g1_lincomb(out, s->g1_values, q, FIELD_ELEMENTS_PER_BLOB);

  return C_KZG_OK;
}

typedef struct {
    unsigned int h[8];
    unsigned long long N;
    unsigned char buf[64];
    size_t off;
} SHA256_CTX;

void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const void *_inp, size_t len);
void sha256_final(unsigned char md[32], SHA256_CTX *ctx);

static void hash(uint8_t md[32], const uint8_t input[], size_t n) {
  SHA256_CTX ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, input, n);
  sha256_final(md, &ctx);
}

static void bytes_of_uint64(uint8_t out[8], uint64_t n) {
  for (int i = 0; i < 8; i++) {
    out[i] = n & 0xFF;
    n >>= 8;
  }
}

static C_KZG_RET compute_challenges(BLSFieldElement *out, BLSFieldElement r_powers[],
    const Polynomial polys[], const KZGCommitment comms[], uint64_t n) {
  size_t i; uint64_t j;
  const size_t ni = 32; // len(FIAT_SHAMIR_PROTOCOL_DOMAIN) + 8 + 8
  const size_t np = ni + n * BYTES_PER_BLOB;
  const size_t nb = np + n * 48;

  uint8_t* bytes = calloc(nb, sizeof(uint8_t));
  if (bytes == NULL) return C_KZG_MALLOC;

  /* Copy domain seperator */
  memcpy(bytes, FIAT_SHAMIR_PROTOCOL_DOMAIN, 16);
  bytes_of_uint64(&bytes[16], FIELD_ELEMENTS_PER_BLOB);
  bytes_of_uint64(&bytes[16 + 8], n);

  /* Copy polynomials */
  for (i = 0; i < n; i++)
    for (j = 0; j < FIELD_ELEMENTS_PER_BLOB; j++)
      bytes_from_bls_field(&bytes[ni + BYTES_PER_FIELD_ELEMENT * (i * FIELD_ELEMENTS_PER_BLOB + j)], &polys[i][j]);

  /* Copy commitments */
  for (i = 0; i < n; i++)
    bytes_from_g1(&bytes[np + i * 48], &comms[i]);

  /* Now let's create challenges! */
  uint8_t hashed_data[32] = {0};
  hash(hashed_data, bytes, nb);

  /* We will use hash_input in the computation of both challenges */
  uint8_t hash_input[33];

  /* Compute r */
  uint8_t r_bytes[32] = {0};
  memcpy(hash_input, hashed_data, 32);
  hash_input[32] = 0x0;
  hash(r_bytes, hash_input, 33);

  /* Compute r_powers */
  BLSFieldElement r;
  hash_to_bls_field(&r, r_bytes);
  compute_powers(r_powers, &r, n);

  /* Compute eval_challenge */
  uint8_t eval_challenge[32] = {0};
  hash_input[32] = 0x1;
  hash(eval_challenge, hash_input, 33);
  hash_to_bls_field(out, eval_challenge);

  free(bytes);
  return C_KZG_OK;
}

static C_KZG_RET compute_aggregated_poly_and_commitment(Polynomial poly_out, KZGCommitment *comm_out, BLSFieldElement *chal_out,
    const Polynomial polys[],
    const KZGCommitment kzg_commitments[],
    size_t n) {
  BLSFieldElement* r_powers = calloc(n, sizeof(BLSFieldElement));
  if (0 < n && r_powers == NULL) return C_KZG_MALLOC;

  C_KZG_RET ret;
  ret = compute_challenges(chal_out, r_powers, polys, kzg_commitments, n);
  if (ret != C_KZG_OK) { if (r_powers != NULL) free(r_powers); return ret; }

  poly_lincomb(poly_out, polys, r_powers, n);

  g1_lincomb(comm_out, kzg_commitments, r_powers, n);

  if (r_powers != NULL) free(r_powers);
  return C_KZG_OK;
}

C_KZG_RET compute_aggregate_kzg_proof(KZGProof *out,
    const Blob blobs[],
    size_t n,
    const KZGSettings *s) {
  KZGCommitment* commitments = calloc(n, sizeof(KZGCommitment));
  if (0 < n && commitments == NULL) return C_KZG_MALLOC;

  Polynomial* polys = calloc(n, sizeof(Polynomial));
  if (0 < n && polys == NULL) { free(commitments); return C_KZG_MALLOC; }

  C_KZG_RET ret;
  for (size_t i = 0; i < n; i++) {
    ret = poly_from_blob(polys[i], blobs[i]);
    if (ret != C_KZG_OK) {
      if (commitments != NULL) free(commitments);
      if (polys != NULL) free(polys);
      return ret;
    }
    poly_to_kzg_commitment(&commitments[i], polys[i], s);
  }

  Polynomial aggregated_poly;
  KZGCommitment aggregated_poly_commitment;
  BLSFieldElement evaluation_challenge;
  ret = compute_aggregated_poly_and_commitment(aggregated_poly, &aggregated_poly_commitment, &evaluation_challenge, polys, commitments, n);
  if (commitments != NULL) free(commitments);
  if (polys != NULL) free(polys);
  if (ret != C_KZG_OK) return ret;

  return compute_kzg_proof(out, aggregated_poly, &evaluation_challenge, s);
}

C_KZG_RET verify_aggregate_kzg_proof(bool *out,
    const Blob blobs[],
    const KZGCommitment expected_kzg_commitments[],
    size_t n,
    const KZGProof *kzg_aggregated_proof,
    const KZGSettings *s) {
  Polynomial* polys = calloc(n, sizeof(Polynomial));
  if (polys == NULL) return C_KZG_MALLOC;
  C_KZG_RET ret;
  for (size_t i = 0; i < n; i++) {
    ret = poly_from_blob(polys[i], blobs[i]);
    if (ret != C_KZG_OK) { free(polys); return ret; }
  }

  Polynomial aggregated_poly;
  KZGCommitment aggregated_poly_commitment;
  BLSFieldElement evaluation_challenge;
  ret = compute_aggregated_poly_and_commitment(aggregated_poly, &aggregated_poly_commitment, &evaluation_challenge, polys, expected_kzg_commitments, n);
  free(polys);
  if (ret != C_KZG_OK) return ret;

  BLSFieldElement y;
  TRY(evaluate_polynomial_in_evaluation_form(&y, aggregated_poly, &evaluation_challenge, s));

  return verify_kzg_proof_impl(out, &aggregated_poly_commitment, &evaluation_challenge, &y, kzg_aggregated_proof, s);
}
