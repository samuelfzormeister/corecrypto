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

int ccmode_cfb8_decrypt(cccfb8_ctx *ctx, size_t nbytes, const void *in, void *out)
{
    struct _ccmode_cfb8_key *ckey = (struct _ccmode_cfb8_key *)ctx;
    uint8_t *out_ptr = out;
    const uint8_t *in_ptr = in;
    uint8_t *iv = (uint8_t *)CCMODE_CFB8_KEY_FEEDBACK(ckey);
    uint8_t *pad = (uint8_t *)CCMODE_CFB8_KEY_PADDING(ckey);

    while (nbytes--) {
        /* ZORMEISTER: this code is ugly but gets the job done */
        cc_memmove(iv, iv + 1, (ckey->ecb->block_size - 1));
        iv[(ckey->ecb->block_size - 1)] = *in_ptr;
        *out_ptr = pad[0] ^ *in_ptr;
        ckey->ecb->ecb(CCMODE_CFB8_KEY_ECB_CTX(ckey), 1, iv, pad);
        out_ptr++;
        in_ptr++;
    }

    return CCERR_OK;
}
