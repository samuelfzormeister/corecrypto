/*
 * Copyright (C) 2025 The PureDarwin Project, All rights reserved.
 *
 * @LICENSE_HEADER_BEGIN@
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
 * @LICENSE_HEADER_END@
 */

/*
 * Code adapted from LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccdigest_priv.h>
#include <corecrypto/ccmd4.h>

#define S11 3
#define S12 7
#define S13 11
#define S14 19
#define S21 3
#define S22 5
#define S23 9
#define S24 13
#define S31 3
#define S32 9
#define S33 11
#define S34 15

/* F, G and H are basic LTC_MD4 functions. */
#define F(x, y, z) (z ^ (x & (y ^ z)))
#define G(x, y, z) ((x & y) | (z & (x | y)))
#define H(x, y, z) ((x) ^ (y) ^ (z))

/* ROTATE_LEFT rotates x left n bits. */
#define ROTATE_LEFT(x, n) CC_ROLc(x, n)

/* FF, GG and HH are transformations for rounds 1, 2 and 3 */
/* Rotation is separate from addition to prevent recomputation */

#define FF(a, b, c, d, x, s)           \
    {                                  \
        (a) += F((b), (c), (d)) + (x); \
        (a) = ROTATE_LEFT((a), (s));   \
    }
#define GG(a, b, c, d, x, s)                          \
    {                                                 \
        (a) += G((b), (c), (d)) + (x) + 0x5a827999UL; \
        (a) = ROTATE_LEFT((a), (s));                  \
    }
#define HH(a, b, c, d, x, s)                          \
    {                                                 \
        (a) += H((b), (c), (d)) + (x) + 0x6ed9eba1UL; \
        (a) = ROTATE_LEFT((a), (s));                  \
    }

const uint32_t ccmd4_initial_state[4] = {
    0x67452301UL,
    0xefcdab89UL,
    0x98badcfeUL,
    0x10325476UL
};

static void md4_compress(unsigned *state, unsigned char *buffer)
{
    uint32_t x[16], a, b, c, d;
    int i;

    /* copy state */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];

    /* copy the state into 512-bits into W[0..15] */
    for (i = 0; i < 16; i++) {
        CC_LOAD32_LE(x[i], buffer + (4 * i));
    }

    /* Round 1 */
    FF(a, b, c, d, x[0], S11);  /* 1 */
    FF(d, a, b, c, x[1], S12);  /* 2 */
    FF(c, d, a, b, x[2], S13);  /* 3 */
    FF(b, c, d, a, x[3], S14);  /* 4 */
    FF(a, b, c, d, x[4], S11);  /* 5 */
    FF(d, a, b, c, x[5], S12);  /* 6 */
    FF(c, d, a, b, x[6], S13);  /* 7 */
    FF(b, c, d, a, x[7], S14);  /* 8 */
    FF(a, b, c, d, x[8], S11);  /* 9 */
    FF(d, a, b, c, x[9], S12);  /* 10 */
    FF(c, d, a, b, x[10], S13); /* 11 */
    FF(b, c, d, a, x[11], S14); /* 12 */
    FF(a, b, c, d, x[12], S11); /* 13 */
    FF(d, a, b, c, x[13], S12); /* 14 */
    FF(c, d, a, b, x[14], S13); /* 15 */
    FF(b, c, d, a, x[15], S14); /* 16 */

    /* Round 2 */
    GG(a, b, c, d, x[0], S21);  /* 17 */
    GG(d, a, b, c, x[4], S22);  /* 18 */
    GG(c, d, a, b, x[8], S23);  /* 19 */
    GG(b, c, d, a, x[12], S24); /* 20 */
    GG(a, b, c, d, x[1], S21);  /* 21 */
    GG(d, a, b, c, x[5], S22);  /* 22 */
    GG(c, d, a, b, x[9], S23);  /* 23 */
    GG(b, c, d, a, x[13], S24); /* 24 */
    GG(a, b, c, d, x[2], S21);  /* 25 */
    GG(d, a, b, c, x[6], S22);  /* 26 */
    GG(c, d, a, b, x[10], S23); /* 27 */
    GG(b, c, d, a, x[14], S24); /* 28 */
    GG(a, b, c, d, x[3], S21);  /* 29 */
    GG(d, a, b, c, x[7], S22);  /* 30 */
    GG(c, d, a, b, x[11], S23); /* 31 */
    GG(b, c, d, a, x[15], S24); /* 32 */

    /* Round 3 */
    HH(a, b, c, d, x[0], S31);  /* 33 */
    HH(d, a, b, c, x[8], S32);  /* 34 */
    HH(c, d, a, b, x[4], S33);  /* 35 */
    HH(b, c, d, a, x[12], S34); /* 36 */
    HH(a, b, c, d, x[2], S31);  /* 37 */
    HH(d, a, b, c, x[10], S32); /* 38 */
    HH(c, d, a, b, x[6], S33);  /* 39 */
    HH(b, c, d, a, x[14], S34); /* 40 */
    HH(a, b, c, d, x[1], S31);  /* 41 */
    HH(d, a, b, c, x[9], S32);  /* 42 */
    HH(c, d, a, b, x[5], S33);  /* 43 */
    HH(b, c, d, a, x[13], S34); /* 44 */
    HH(a, b, c, d, x[3], S31);  /* 45 */
    HH(d, a, b, c, x[11], S32); /* 46 */
    HH(c, d, a, b, x[7], S33);  /* 47 */
    HH(b, c, d, a, x[15], S34); /* 48 */

    /* Update our state */
    state[0] = state[0] + a;
    state[1] = state[1] + b;
    state[2] = state[2] + c;
    state[3] = state[3] + d;
}

static void md4_process(ccdigest_state_t state, size_t nblocks, const void *data)
{
    uint32_t *curstate = ccdigest_u32(state);
    unsigned char *buf = (unsigned char *)data;
    for (int i = 0; i < nblocks; i++) {
        md4_compress(curstate, buf);
        buf += CCMD4_BLOCK_SIZE;
    }
}

const struct ccdigest_info ccmd4_ltc_di = {
    .initial_state = ccmd4_initial_state,
    .output_size = CCMD4_OUTPUT_SIZE,
    .block_size = CCMD4_BLOCK_SIZE,
    .state_size = CCMD4_STATE_SIZE,
    .oid = ccoid_md4,
    .oid_size = ccoid_md4_len,
    .compress = md4_process,
    .final = ccdigest_final_64le,
};
