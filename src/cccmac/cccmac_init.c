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
#include <corecrypto/cccmac_priv.h>

int cccmac_init(const struct ccmode_cbc *cbc, cccmac_ctx_t ctx, size_t key_nbytes, const void *key)
{
    cccmac_cbc(ctx) = cbc;

    /* Block size CANNOT be larger than CMAC_BLOCKSIZE. */
    if (cbc->block_size > CMAC_BLOCKSIZE) {
        return CCERR_PARAMETER;
    }

    cccmac_generate_subkeys(cbc, key_nbytes, key, cccmac_k1(ctx), cccmac_k2(ctx));
    cbc->init(cccmac_cbc(ctx), cccmac_mode_sym_ctx(cccmac_cbc(ctx), ctx), key_nbytes, key);

    /* Anything else? */
    return CCERR_OK;
}
