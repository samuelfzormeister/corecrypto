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

int ccmode_cfb_encrypt(cccfb_ctx *ctx, size_t nbytes, const void *in, void *out)
{
    struct _ccmode_cfb_key *ckey = (struct _ccmode_cfb_key *)ctx;
    size_t block_size = ckey->ecb->block_size;
    const uint8_t *cur_in = in;
    uint8_t *cur_out = out;

    /* way more efficient than just cycling it by block. maybe i should do this for other impls. */
    while (nbytes--) {
        if (ckey->pad_len == block_size) {
            ckey->ecb->ecb(CCMODE_CFB_KEY_ECB_CTX(ckey), 1, CCMODE_CFB_KEY_PADDING(ckey), CCMODE_CFB_KEY_FEEDBACK(ckey));
            ckey->pad_len = 0;
        }

        CCMODE_CFB_KEY_PADDING(ckey)
        [ckey->pad_len] = *cur_out = (*cur_in ^ CCMODE_CFB_KEY_FEEDBACK(ckey)[ckey->pad_len]);
        ckey->pad_len++;
        cur_in++;
        cur_out++;
    }

    return CCERR_OK;
}
