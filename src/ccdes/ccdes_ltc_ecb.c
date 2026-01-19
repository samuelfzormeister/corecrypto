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

#include "ccdes_ltc_internal.h"
#include <corecrypto/cc_error.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccdes.h>
#include <corecrypto/ccmode_impl.h>

int ccdes_ltc_setup(const struct ccmode_ecb *ecb, ccecb_ctx *ctx, size_t key_len, const void *key)
{
    struct ccdes_ltc_ecb_ctx *lctx = (struct ccdes_ltc_ecb_ctx *)ctx;

    if (key_len != CCDES_KEY_SIZE) {
        return CCERR_INTERNAL;
    } else {
        deskey(key, EN0, lctx->ek);
        deskey(key, DE1, lctx->dk);
    }

    return CCERR_OK;
}

int ltc_des_ecb_encrypt(const ccecb_ctx *ctx, size_t nblocks, const void *in, void *out)
{
    struct ccdes_ltc_ecb_ctx *lctx = (struct ccdes_ltc_ecb_ctx *)ctx;
    uint32_t work[2];

    const void *cur_in = in;
    void *cur_out = out;

    while (nblocks--) {
        CC_LOAD32_BE(work[0], cur_in);
        CC_LOAD32_BE(work[1], cur_in + 4);
        desfunc(work, lctx->ek);
        CC_STORE32_BE(work[0], cur_out);
        CC_STORE32_BE(work[1], cur_out + 4);
        cur_in += CCDES_BLOCK_SIZE;
        cur_out += CCDES_BLOCK_SIZE;
    }

    return CCERR_OK;
}

int ltc_des_ecb_decrypt(const ccecb_ctx *ctx, size_t nblocks, const void *in, void *out)
{
    struct ccdes_ltc_ecb_ctx *lctx = (struct ccdes_ltc_ecb_ctx *)ctx;
    uint32_t work[2];

    const void *cur_in = in;
    void *cur_out = out;

    while (nblocks--) {
        CC_LOAD32_BE(work[0], cur_in);
        CC_LOAD32_BE(work[1], cur_in + 4);
        desfunc(work, lctx->dk);
        CC_STORE32_BE(work[0], cur_out);
        CC_STORE32_BE(work[1], cur_out + 4);
        cur_in += CCDES_BLOCK_SIZE;
        cur_out += CCDES_BLOCK_SIZE;
    }

    return CCERR_OK;
}

const struct ccmode_ecb ccdes_ltc_ecb_encrypt_mode = {
    .size = ccn_sizeof_size(sizeof(struct ccdes_ltc_ecb_ctx)),
    .block_size = CCDES_BLOCK_SIZE,
    .init = ccdes_ltc_setup,
    .ecb = ltc_des_ecb_encrypt,
};

const struct ccmode_ecb ccdes_ltc_ecb_decrypt_mode = {
    .size = ccn_sizeof_size(sizeof(struct ccdes_ltc_ecb_ctx)),
    .block_size = CCDES_BLOCK_SIZE,
    .init = ccdes_ltc_setup,
    .ecb = ltc_des_ecb_decrypt,
};
