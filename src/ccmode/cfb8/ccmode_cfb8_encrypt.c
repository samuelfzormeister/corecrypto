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

int ccmode_cfb8_encrypt(cccfb8_ctx *ctx, size_t nbytes, const void *in, void *out)
{
    struct _ccmode_cfb8_key *ckey = (struct _ccmode_cfb8_key *)ctx;
    const struct ccmode_ecb *ecb = ckey->ecb;
    ccecb_ctx *ecb_ctx = CCMODE_CFB_KEY_ECB_CTX(ckey);
    size_t block_size = ecb->block_size;
    uint8_t *ct = out;
    const uint8_t *pt = in;
    uint8_t *iv = (uint8_t *)CCMODE_CFB8_KEY_FEEDBACK(ckey);
    uint8_t *pad = (uint8_t *)CCMODE_CFB8_KEY_PADDING(ckey);

    while (nbytes-- > 0) {
        cc_memmove(iv, iv + 1, block_size - 1);
        iv[block_size - 1] = *ct = pad[0] ^ *pt;
        ccecb_update(ecb, ecb_ctx, 1, iv, pad);
        ++pt;
        ++ct;
    }

    return CCERR_OK;
}
