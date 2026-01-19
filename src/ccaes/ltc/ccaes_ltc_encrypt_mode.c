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

#include "ccaes_ltc_internal.h"
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccaes.h>

/* weird that the symbol is named this, but you know. whatecer works i guess. */
static int ccaes_ecb_encrypt_init(const struct ccmode_ecb *ecb, ccecb_ctx *ctx, size_t key_nbytes, const void *key)
{
    ccaes_ltc_init(key, key_nbytes, 0, ctx);

    return CCERR_OK;
}

static int ccaes_ecb_encrypt(const ccecb_ctx *ctx, size_t nblocks, const void *in, void *out)
{
    while (nblocks--) {
        ccaes_ltc_ecb_encrypt(in, out, __DECONST(ccecb_ctx *, ctx));
        in += CCAES_BLOCK_SIZE;
        out += CCAES_BLOCK_SIZE;
    }

    return CCERR_OK;
}

const struct ccmode_ecb ccaes_ltc_ecb_encrypt_mode = {
    .size = sizeof(struct ltc_rijndael_key),
    .block_size = CCAES_BLOCK_SIZE,
    .init = ccaes_ecb_encrypt_init,
    .ecb = ccaes_ecb_encrypt,
};
