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

int ccmode_ofb_crypt(ccofb_ctx *ctx, size_t nbytes, const void *in, void *out)
{
    struct _ccmode_ofb_key *okey = (struct _ccmode_ofb_key *)ctx;
    const uint8_t *in_ptr = in;
    uint8_t *out_ptr = out;

    /* way more efficient than just cycling it by block. maybe i should do this for other impls. */
    while (nbytes--) {
        if (okey->pad_len == okey->ecb->block_size) {
            okey->ecb->ecb(CCMODE_OFB_KEY_ECB_CTX(okey), 1, CCMODE_OFB_KEY_IV(okey), CCMODE_OFB_KEY_IV(okey));
            okey->pad_len = 0;
        }

        *out_ptr++ = *in_ptr++ ^ CCMODE_OFB_KEY_IV(okey)[okey->pad_len];
        okey->pad_len++;
    }

    return CCERR_OK;
}
