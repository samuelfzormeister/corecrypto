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

#include "aes_tab.c"
#include "ccaes_ltc_internal.h"
#include "corecrypto/ccmode_impl.h"

static uint32_t setup_mix(uint32_t temp)
{
    return (Te4_3[cc_byte(temp, 2)]) ^ (Te4_2[cc_byte(temp, 1)]) ^ (Te4_1[cc_byte(temp, 0)]) ^ (Te4_0[cc_byte(temp, 3)]);
}

#if CC_SMALL_CODE
static uint32_t setup_mix2(uint32_t temp)
{
    return Td0(255 & Te4[cc_byte(temp, 3)]) ^ Td1(255 & Te4[cc_byte(temp, 2)]) ^ Td2(255 & Te4[cc_byte(temp, 1)]) ^ Td3(255 & Te4[cc_byte(temp, 0)]);
}
#endif

int ccaes_ltc_init(const unsigned char *key, int keylen, int num_rounds, ccecb_ctx *skey)
{
    int i, j;
    uint32_t temp, *rk;
    uint32_t *rrk;
    struct ltc_rijndael_key *rijndael = (struct ltc_rijndael_key *)skey;

    if (keylen != 16 && keylen != 24 && keylen != 32) {
        return -1;
    }

    if (num_rounds != 0 && num_rounds != (10 + ((keylen / 8) - 2) * 2)) {
        return -1;
    }

    rijndael->Nr = 10 + ((keylen / 8) - 2) * 2;

    /* setup the forward key */
    i = 0;
    rk = rijndael->eK;
    CC_LOAD32_BE(rk[0], key);
    CC_LOAD32_BE(rk[1], key + 4);
    CC_LOAD32_BE(rk[2], key + 8);
    CC_LOAD32_BE(rk[3], key + 12);
    if (keylen == 16) {
        j = 44;
        for (;;) {
            temp = rk[3];
            rk[4] = rk[0] ^ setup_mix(temp) ^ rcon[i];
            rk[5] = rk[1] ^ rk[4];
            rk[6] = rk[2] ^ rk[5];
            rk[7] = rk[3] ^ rk[6];
            if (++i == 10) {
                break;
            }
            rk += 4;
        }
    } else if (keylen == 24) {
        j = 52;
        CC_LOAD32_BE(rk[4], key + 16);
        CC_LOAD32_BE(rk[5], key + 20);
        for (;;) {
#ifdef _MSC_VER
            temp = rijndael->eK[rk - rijndael->eK + 5];
#else
            temp = rk[5];
#endif
            rk[6] = rk[0] ^ setup_mix(temp) ^ rcon[i];
            rk[7] = rk[1] ^ rk[6];
            rk[8] = rk[2] ^ rk[7];
            rk[9] = rk[3] ^ rk[8];
            if (++i == 8) {
                break;
            }
            rk[10] = rk[4] ^ rk[9];
            rk[11] = rk[5] ^ rk[10];
            rk += 6;
        }
    } else if (keylen == 32) {
        j = 60;
        CC_LOAD32_BE(rk[4], key + 16);
        CC_LOAD32_BE(rk[5], key + 20);
        CC_LOAD32_BE(rk[6], key + 24);
        CC_LOAD32_BE(rk[7], key + 28);
        for (;;) {
#ifdef _MSC_VER
            temp = rijndael->eK[rk - rijndael->eK + 7];
#else
            temp = rk[7];
#endif
            rk[8] = rk[0] ^ setup_mix(temp) ^ rcon[i];
            rk[9] = rk[1] ^ rk[8];
            rk[10] = rk[2] ^ rk[9];
            rk[11] = rk[3] ^ rk[10];
            if (++i == 7) {
                break;
            }
            temp = rk[11];
            rk[12] = rk[4] ^ setup_mix(CC_RORc(temp, 8));
            rk[13] = rk[5] ^ rk[12];
            rk[14] = rk[6] ^ rk[13];
            rk[15] = rk[7] ^ rk[14];
            rk += 8;
        }
    } else {
        /* this can't happen */
        return -1;
    }

    /* setup the inverse key now */
    rk = rijndael->dK;
    rrk = rijndael->eK + j - 4;

    /* apply the inverse MixColumn transform to all round keys but the first and the last: */
    /* copy first */
    *rk++ = *rrk++;
    *rk++ = *rrk++;
    *rk++ = *rrk++;
    *rk = *rrk;
    rk -= 3;
    rrk -= 3;

    for (i = 1; i < rijndael->Nr; i++) {
        rrk -= 4;
        rk += 4;
#if CC_SMALL_CODE
        temp = rrk[0];
        rk[0] = setup_mix2(temp);
        temp = rrk[1];
        rk[1] = setup_mix2(temp);
        temp = rrk[2];
        rk[2] = setup_mix2(temp);
        temp = rrk[3];
        rk[3] = setup_mix2(temp);
#else
        temp = rrk[0];
        rk[0] = Tks0[cc_byte(temp, 3)] ^ Tks1[cc_byte(temp, 2)] ^ Tks2[cc_byte(temp, 1)] ^ Tks3[cc_byte(temp, 0)];
        temp = rrk[1];
        rk[1] = Tks0[cc_byte(temp, 3)] ^ Tks1[cc_byte(temp, 2)] ^ Tks2[cc_byte(temp, 1)] ^ Tks3[cc_byte(temp, 0)];
        temp = rrk[2];
        rk[2] = Tks0[cc_byte(temp, 3)] ^ Tks1[cc_byte(temp, 2)] ^ Tks2[cc_byte(temp, 1)] ^ Tks3[cc_byte(temp, 0)];
        temp = rrk[3];
        rk[3] = Tks0[cc_byte(temp, 3)] ^ Tks1[cc_byte(temp, 2)] ^ Tks2[cc_byte(temp, 1)] ^ Tks3[cc_byte(temp, 0)];
#endif
    }

    /* copy last */
    rrk -= 4;
    rk += 4;
    *rk++ = *rrk++;
    *rk++ = *rrk++;
    *rk++ = *rrk++;
    *rk = *rrk;

    return 0;
}

int ccaes_ltc_ecb_encrypt(const unsigned char *pt, unsigned char *ct, ccecb_ctx *skey)
{
    uint32_t s0, s1, s2, s3, t0, t1, t2, t3, *rk;
    int Nr, r;
    struct ltc_rijndael_key *rijndael = (struct ltc_rijndael_key *)skey;

    Nr = rijndael->Nr;
    rk = rijndael->eK;

    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
    CC_LOAD32_BE(s0, pt);
    s0 ^= rk[0];
    CC_LOAD32_BE(s1, pt + 4);
    s1 ^= rk[1];
    CC_LOAD32_BE(s2, pt + 8);
    s2 ^= rk[2];
    CC_LOAD32_BE(s3, pt + 12);
    s3 ^= rk[3];

#if CC_SMALL_CODE

    for (r = 0;; r++) {
        rk += 4;
        t0 = Te0(cc_byte(s0, 3)) ^ Te1(cc_byte(s1, 2)) ^ Te2(cc_byte(s2, 1)) ^ Te3(cc_byte(s3, 0)) ^ rk[0];
        t1 = Te0(cc_byte(s1, 3)) ^ Te1(cc_byte(s2, 2)) ^ Te2(cc_byte(s3, 1)) ^ Te3(cc_byte(s0, 0)) ^ rk[1];
        t2 = Te0(cc_byte(s2, 3)) ^ Te1(cc_byte(s3, 2)) ^ Te2(cc_byte(s0, 1)) ^ Te3(cc_byte(s1, 0)) ^ rk[2];
        t3 = Te0(cc_byte(s3, 3)) ^ Te1(cc_byte(s0, 2)) ^ Te2(cc_byte(s1, 1)) ^ Te3(cc_byte(s2, 0)) ^ rk[3];
        if (r == Nr - 2) {
            break;
        }
        s0 = t0;
        s1 = t1;
        s2 = t2;
        s3 = t3;
    }
    rk += 4;

#else

    /*
     * Nr - 1 full rounds:
     */
    r = Nr >> 1;
    for (;;) {
        t0 = Te0(cc_byte(s0, 3)) ^ Te1(cc_byte(s1, 2)) ^ Te2(cc_byte(s2, 1)) ^ Te3(cc_byte(s3, 0)) ^ rk[4];
        t1 = Te0(cc_byte(s1, 3)) ^ Te1(cc_byte(s2, 2)) ^ Te2(cc_byte(s3, 1)) ^ Te3(cc_byte(s0, 0)) ^ rk[5];
        t2 = Te0(cc_byte(s2, 3)) ^ Te1(cc_byte(s3, 2)) ^ Te2(cc_byte(s0, 1)) ^ Te3(cc_byte(s1, 0)) ^ rk[6];
        t3 = Te0(cc_byte(s3, 3)) ^ Te1(cc_byte(s0, 2)) ^ Te2(cc_byte(s1, 1)) ^ Te3(cc_byte(s2, 0)) ^ rk[7];

        rk += 8;
        if (--r == 0) {
            break;
        }

        s0 = Te0(cc_byte(t0, 3)) ^ Te1(cc_byte(t1, 2)) ^ Te2(cc_byte(t2, 1)) ^ Te3(cc_byte(t3, 0)) ^ rk[0];
        s1 = Te0(cc_byte(t1, 3)) ^ Te1(cc_byte(t2, 2)) ^ Te2(cc_byte(t3, 1)) ^ Te3(cc_byte(t0, 0)) ^ rk[1];
        s2 = Te0(cc_byte(t2, 3)) ^ Te1(cc_byte(t3, 2)) ^ Te2(cc_byte(t0, 1)) ^ Te3(cc_byte(t1, 0)) ^ rk[2];
        s3 = Te0(cc_byte(t3, 3)) ^ Te1(cc_byte(t0, 2)) ^ Te2(cc_byte(t1, 1)) ^ Te3(cc_byte(t2, 0)) ^ rk[3];
    }

#endif

    /*
     * apply last round and
     * map cipher state to byte array block:
     */
    s0 = (Te4_3[cc_byte(t0, 3)]) ^ (Te4_2[cc_byte(t1, 2)]) ^ (Te4_1[cc_byte(t2, 1)]) ^ (Te4_0[cc_byte(t3, 0)]) ^ rk[0];
    CC_STORE32_BE(s0, ct);
    s1 = (Te4_3[cc_byte(t1, 3)]) ^ (Te4_2[cc_byte(t2, 2)]) ^ (Te4_1[cc_byte(t3, 1)]) ^ (Te4_0[cc_byte(t0, 0)]) ^ rk[1];
    CC_STORE32_BE(s1, ct + 4);
    s2 = (Te4_3[cc_byte(t2, 3)]) ^ (Te4_2[cc_byte(t3, 2)]) ^ (Te4_1[cc_byte(t0, 1)]) ^ (Te4_0[cc_byte(t1, 0)]) ^ rk[2];
    CC_STORE32_BE(s2, ct + 8);
    s3 = (Te4_3[cc_byte(t3, 3)]) ^ (Te4_2[cc_byte(t0, 2)]) ^ (Te4_1[cc_byte(t1, 1)]) ^ (Te4_0[cc_byte(t2, 0)]) ^ rk[3];
    CC_STORE32_BE(s3, ct + 12);

    return 0;
}

int ccaes_ltc_ecb_decrypt(const unsigned char *ct, unsigned char *pt, ccecb_ctx *skey)
{
    uint32_t s0, s1, s2, s3, t0, t1, t2, t3, *rk;
    int Nr, r;
    struct ltc_rijndael_key *rijndael = (struct ltc_rijndael_key *)skey;

    Nr = rijndael->Nr;
    rk = rijndael->dK;

    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
    CC_LOAD32_BE(s0, ct);
    s0 ^= rk[0];
    CC_LOAD32_BE(s1, ct + 4);
    s1 ^= rk[1];
    CC_LOAD32_BE(s2, ct + 8);
    s2 ^= rk[2];
    CC_LOAD32_BE(s3, ct + 12);
    s3 ^= rk[3];

#if CC_SMALL_CODE
    for (r = 0;; r++) {
        rk += 4;
        t0 = Td0(cc_byte(s0, 3)) ^ Td1(cc_byte(s3, 2)) ^ Td2(cc_byte(s2, 1)) ^ Td3(cc_byte(s1, 0)) ^ rk[0];
        t1 = Td0(cc_byte(s1, 3)) ^ Td1(cc_byte(s0, 2)) ^ Td2(cc_byte(s3, 1)) ^ Td3(cc_byte(s2, 0)) ^ rk[1];
        t2 = Td0(cc_byte(s2, 3)) ^ Td1(cc_byte(s1, 2)) ^ Td2(cc_byte(s0, 1)) ^ Td3(cc_byte(s3, 0)) ^ rk[2];
        t3 = Td0(cc_byte(s3, 3)) ^ Td1(cc_byte(s2, 2)) ^ Td2(cc_byte(s1, 1)) ^ Td3(cc_byte(s0, 0)) ^ rk[3];
        if (r == Nr - 2) {
            break;
        }
        s0 = t0;
        s1 = t1;
        s2 = t2;
        s3 = t3;
    }
    rk += 4;

#else

    /*
     * Nr - 1 full rounds:
     */
    r = Nr >> 1;
    for (;;) {

        t0 = Td0(cc_byte(s0, 3)) ^ Td1(cc_byte(s3, 2)) ^ Td2(cc_byte(s2, 1)) ^ Td3(cc_byte(s1, 0)) ^ rk[4];
        t1 = Td0(cc_byte(s1, 3)) ^ Td1(cc_byte(s0, 2)) ^ Td2(cc_byte(s3, 1)) ^ Td3(cc_byte(s2, 0)) ^ rk[5];
        t2 = Td0(cc_byte(s2, 3)) ^ Td1(cc_byte(s1, 2)) ^ Td2(cc_byte(s0, 1)) ^ Td3(cc_byte(s3, 0)) ^ rk[6];
        t3 = Td0(cc_byte(s3, 3)) ^ Td1(cc_byte(s2, 2)) ^ Td2(cc_byte(s1, 1)) ^ Td3(cc_byte(s0, 0)) ^ rk[7];

        rk += 8;
        if (--r == 0) {
            break;
        }

        s0 = Td0(cc_byte(t0, 3)) ^ Td1(cc_byte(t3, 2)) ^ Td2(cc_byte(t2, 1)) ^ Td3(cc_byte(t1, 0)) ^ rk[0];
        s1 = Td0(cc_byte(t1, 3)) ^ Td1(cc_byte(t0, 2)) ^ Td2(cc_byte(t3, 1)) ^ Td3(cc_byte(t2, 0)) ^ rk[1];
        s2 = Td0(cc_byte(t2, 3)) ^ Td1(cc_byte(t1, 2)) ^ Td2(cc_byte(t0, 1)) ^ Td3(cc_byte(t3, 0)) ^ rk[2];
        s3 = Td0(cc_byte(t3, 3)) ^ Td1(cc_byte(t2, 2)) ^ Td2(cc_byte(t1, 1)) ^ Td3(cc_byte(t0, 0)) ^ rk[3];
    }
#endif

    /*
     * apply last round and
     * map cipher state to byte array block:
     */
    s0 = (Td4[cc_byte(t0, 3)] & 0xff000000) ^ (Td4[cc_byte(t3, 2)] & 0x00ff0000) ^ (Td4[cc_byte(t2, 1)] & 0x0000ff00) ^ (Td4[cc_byte(t1, 0)] & 0x000000ff) ^ rk[0];
    CC_STORE32_BE(s0, pt);
    s1 = (Td4[cc_byte(t1, 3)] & 0xff000000) ^ (Td4[cc_byte(t0, 2)] & 0x00ff0000) ^ (Td4[cc_byte(t3, 1)] & 0x0000ff00) ^ (Td4[cc_byte(t2, 0)] & 0x000000ff) ^ rk[1];
    CC_STORE32_BE(s1, pt + 4);
    s2 = (Td4[cc_byte(t2, 3)] & 0xff000000) ^ (Td4[cc_byte(t1, 2)] & 0x00ff0000) ^ (Td4[cc_byte(t0, 1)] & 0x0000ff00) ^ (Td4[cc_byte(t3, 0)] & 0x000000ff) ^ rk[2];
    CC_STORE32_BE(s2, pt + 8);
    s3 = (Td4[cc_byte(t3, 3)] & 0xff000000) ^ (Td4[cc_byte(t2, 2)] & 0x00ff0000) ^ (Td4[cc_byte(t1, 1)] & 0x0000ff00) ^ (Td4[cc_byte(t0, 0)] & 0x000000ff) ^ rk[3];
    CC_STORE32_BE(s3, pt + 12);

    return 0;
}
