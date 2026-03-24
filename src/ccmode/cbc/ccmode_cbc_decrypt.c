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

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccmode_internal.h>

int ccmode_cbc_decrypt(const cccbc_ctx *ctx, cccbc_iv *iv, size_t nblocks, const void *in, void *out)
{
    const struct _ccmode_cbc_key *fctx = (const struct _ccmode_cbc_key *)ctx;
    const struct ccmode_ecb *ecb = fctx->ecb;
    ccecb_ctx *ecb_ctx = CCMODE_CBC_KEY_ECB_CTX(fctx);
    size_t block_size = ecb->block_size;
    uint8_t *cur_iv = (uint8_t *)iv;
    uint8_t *pt = out;
    const uint8_t *ct = in;
    uint8_t buf[block_size];

    /* iterate. */
    while (nblocks) {
        /* run decryption */
        ccecb_update(ecb, ecb_ctx, 1, ct, buf);

        /* XOR the IV */
        for (cc_size i = 0; i < block_size; i++) {
            uint8_t tmp = cur_iv[i] ^ buf[i];
            cur_iv[i] = ct[i];
            pt[i] = tmp;
        }

        ct += block_size;
        pt += block_size;

        --nblocks;
    }

    return CCERR_OK;
}
