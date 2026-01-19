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

#include "cast_lcl.h"
#include <corecrypto/cc_priv.h>
#include <corecrypto/cccast.h>
#include <corecrypto/ccmode_impl.h>
#include <corecrypto/ccn.h>

int cccast_setup(const struct ccmode_ecb *ecb, ccecb_ctx *ctx, size_t key_len, const void *key)
{
    CAST_set_key((CAST_KEY *)ctx, key_len, key);
    return CCERR_OK;
}

int cccast_ecb_encrypt(const ccecb_ctx *ctx, size_t nblocks, const void *in, void *out)
{
    uint32_t d[2];
    const CAST_KEY *key = (const CAST_KEY *)ctx;

    const void *cur_in = in;
    void *cur_out = out;

    while (nblocks--) {
        CC_LOAD32_BE(d[0], cur_in);
        CC_LOAD32_BE(d[1], cur_in + 4);
        CAST_encrypt(d, __DECONST(CAST_KEY *, key)); /* TODO: should i fix the violation of the const marker? */
        CC_STORE32_BE(d[0], cur_out);
        CC_STORE32_BE(d[1], cur_out + 4);

        cur_in += CCCAST_BLOCK_SIZE;
        cur_out += CCCAST_BLOCK_SIZE;
    }

    return CCERR_OK;
}

int cccast_ecb_decrypt(const ccecb_ctx *ctx, size_t nblocks, const void *in, void *out)
{
    uint32_t d[2];
    const CAST_KEY *key = (const CAST_KEY *)ctx;

    const void *cur_in = in;
    void *cur_out = out;

    while (nblocks--) {
        CC_LOAD32_LE(d[0], cur_in);
        CC_LOAD32_LE(d[1], cur_in + 4);
        CAST_decrypt(d, __DECONST(CAST_KEY *, key)); /* TODO: should i fix the violation of the const marker? */
        CC_STORE32_LE(d[0], cur_out);
        CC_STORE32_LE(d[1], cur_out + 4);

        cur_in += CCCAST_BLOCK_SIZE;
        cur_out += CCCAST_BLOCK_SIZE;
    }

    return CCERR_OK;
}

const struct ccmode_ecb cccast_eay_ecb_encrypt_mode = {
    .size = ccn_sizeof_size(sizeof(CAST_KEY)),
    .block_size = CCCAST_BLOCK_SIZE,
    .init = cccast_setup,
    .ecb = cccast_ecb_encrypt,
};

const struct ccmode_ecb cccast_eay_ecb_decrypt_mode = {
    .size = ccn_sizeof_size(sizeof(CAST_KEY)),
    .block_size = CCCAST_BLOCK_SIZE,
    .init = cccast_setup,
    .ecb = cccast_ecb_decrypt,
};
