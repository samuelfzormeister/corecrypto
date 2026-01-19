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
#include <corecrypto/ccmd2.h>

const unsigned char PI_SUBST[256] = {
    41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
    19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
    76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
    138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
    245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
    148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
    39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
    181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
    150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
    112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
    96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
    85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
    234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
    129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
    8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
    203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
    166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
    31, 26, 219, 153, 141, 51, 159, 17, 131, 20
};

// MD2 starts as null bytes.
const uint32_t ccmd2_initial_state[] = {
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
};

/*
 CommonCrypto for reference

 static inline void md2in(const struct ccdigest_info *di, ccdigest_ctx_t ctx, CC_MD2_CTX *c)
 {
     memcpy(ccdigest_state_u8(di, ctx)+48, c->cksm, CC_MD2_BLOCK_LONG);
     memcpy(ccdigest_state_u8(di, ctx), c->state, CC_MD2_BLOCK_LONG);
     memcpy(ccdigest_data(di, ctx), c->data, CC_MD2_DIGEST_LENGTH);
     ccdigest_num(di, ctx) = c->num;
 }


 static inline void md2out(const struct ccdigest_info *di, CC_MD2_CTX *c, ccdigest_ctx_t ctx)
 {
     memcpy(c->cksm, ccdigest_state_u8(di, ctx)+48, CC_MD2_BLOCK_LONG);
     memcpy(c->state, ccdigest_state_u8(di, ctx), CC_MD2_BLOCK_LONG);
     memcpy(c->data, ccdigest_data(di, ctx), CC_MD2_DIGEST_LENGTH);
     c->num = (int) ccdigest_num(di, ctx);
 }
 */

static void md2_update_chksum(unsigned char *checksum, unsigned char *buffer)
{
    unsigned char L = checksum[15];

    for (int j = 0; j < 16; j++) {
        /*
         * caution, the RFC says its "C[j] = S[M[i*16+j] xor L]" but the reference source code [and test vectors] say
         * otherwise.
         */
        L = (checksum[j] ^= PI_SUBST[(int)(buffer[j] ^ L)] & 255);
    }
}

static void md2_compress(unsigned char *X, unsigned char *buffer)
{
    int j, k;
    unsigned char t;

    /* copy block */
    for (j = 0; j < 16; j++) {
        X[16 + j] = buffer[j];
        X[32 + j] = X[j] ^ X[16 + j];
    }

    t = (unsigned char)0;

    /* do 18 rounds */
    for (j = 0; j < 18; j++) {
        for (k = 0; k < 48; k++) {
            t = (X[k] ^= PI_SUBST[(int)(t & 255)]);
        }
        t = (t + (unsigned char)j) & 255;
    }
}

static void md2_process(ccdigest_state_t state, size_t nblocks, const void *data)
{
    unsigned char *X = ccdigest_u8(state);
    unsigned char *checksum = ccdigest_u8(state) + 48;
    unsigned char *buf = (unsigned char *)data;
    for (int i = 0; i < nblocks; i++) {
        md2_compress(X, buf);
        md2_update_chksum(checksum, buf);
        buf += CCMD2_BLOCK_SIZE;
    }
}

static void md2_final(const struct ccdigest_info *di, ccdigest_ctx_t ctx, void *digest)
{
    unsigned long i, k;

    unsigned char *X = ccdigest_state_u8(di, ctx);
    unsigned char *checksum = ccdigest_state_u8(di, ctx) + 48;

    /* pad the message */
    k = 16 - ccdigest_num(di, ctx);
    for (i = ccdigest_num(di, ctx); i < 16; i++) {
        ccdigest_data(di, ctx)[i] = (unsigned char)k;
    }

    /* hash and update */
    md2_compress(X, ccdigest_data(di, ctx));
    md2_update_chksum(checksum, ccdigest_data(di, ctx));

    /* hash checksum */
    CC_MEMCPY(ccdigest_data(di, ctx), checksum, 16);

    md2_compress(X, ccdigest_data(di, ctx));

    /* output is lower 16 bytes of X */
    CC_MEMCPY(digest, ccdigest_data(di, ctx), 16);
}

const struct ccdigest_info ccmd2_ltc_di = {
    .block_size = CCMD2_BLOCK_SIZE,
    .state_size = CCMD2_STATE_SIZE,
    .output_size = CCMD2_OUTPUT_SIZE,
    .initial_state = ccmd2_initial_state,
    .oid = ccoid_md2,
    .oid_size = ccoid_md2_len,
    .final = md2_final,
    .compress = md2_process,
};
