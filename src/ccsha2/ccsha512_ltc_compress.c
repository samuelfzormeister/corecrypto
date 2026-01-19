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

#include "ccsha2_ltc_internal.h"
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccdigest.h>

#define K ccsha512_K

#define Ch(x, y, z)  (z ^ (x & (y ^ z)))
#define Maj(x, y, z) (((x | y) & z) | (x & y))
#define S(x, n)      CC_ROR64c(x, n)
#define R(x, n)      (((x) & 0xFFFFFFFFFFFFFFFFULL) >> ((uint64_t)n))
#define Sigma0(x)    (S(x, 28) ^ S(x, 34) ^ S(x, 39))
#define Sigma1(x)    (S(x, 14) ^ S(x, 18) ^ S(x, 41))
#define Gamma0(x)    (S(x, 1) ^ S(x, 8) ^ R(x, 7))
#define Gamma1(x)    (S(x, 19) ^ S(x, 61) ^ R(x, 6))

void ccsha512_ltc_compress(ccdigest_state_t state, size_t nblocks, const void *data)
{
    uint64_t S[8], W[80], t0, t1;
    int i;

    /* copy state into S */
    for (i = 0; i < 8; i++) {
        S[i] = ccdigest_u64(state)[i];
    }

    /* copy the state into 1024-bits into W[0..15] */
    for (i = 0; i < 16; i++) {
        CC_LOAD64_BE(W[i], data + (8 * i));
    }

    /* fill W[16..79] */
    for (i = 16; i < 80; i++) {
        W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];
    }

    /* Compress */
#if CC_SMALL_CODE
    for (i = 0; i < 80; i++) {
        t0 = S[7] + Sigma1(S[4]) + Ch(S[4], S[5], S[6]) + K[i] + W[i];
        t1 = Sigma0(S[0]) + Maj(S[0], S[1], S[2]);
        S[7] = S[6];
        S[6] = S[5];
        S[5] = S[4];
        S[4] = S[3] + t0;
        S[3] = S[2];
        S[2] = S[1];
        S[1] = S[0];
        S[0] = t0 + t1;
    }
#else
#define RND(a, b, c, d, e, f, g, h, i)              \
    t0 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i]; \
    t1 = Sigma0(a) + Maj(a, b, c);                  \
    d += t0;                                        \
    h = t0 + t1;

    for (i = 0; i < 80; i += 8) {
        RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], i + 0);
        RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], i + 1);
        RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], i + 2);
        RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], i + 3);
        RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], i + 4);
        RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], i + 5);
        RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], i + 6);
        RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], i + 7);
    }
#endif

    /* feedback */
    for (i = 0; i < 8; i++) {
        ccdigest_u64(state)[i] += S[i];
    }

    data += CCSHA512_BLOCK_SIZE;
}
