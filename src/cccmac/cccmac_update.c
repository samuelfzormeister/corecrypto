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
#include <corecrypto/cccmac.h>
#include <corecrypto/cccmac_priv.h>

int cccmac_update(cccmac_ctx_t ctx, size_t data_nbytes, const void *data)
{
    int flag = (data_nbytes % CMAC_BLOCKSIZE);
    size_t nblocks = data_nbytes / CMAC_BLOCKSIZE;
    if (flag) {
    }

    cc_memcpy(cccmac_block(ctx), data, CMAC_BLOCKSIZE);

    while (nblocks--) {
        cccmac_cbc(ctx)->cbc(cccmac_mode_sym_ctx(cccmac_cbc(ctx), ctx), cccmac_mode_iv(cccmac_cbc(ctx), ctx), 1, cccmac_block(ctx), cccmac_block(ctx));
    }

    cc_try_abort("ZORMEISTER: incomplete CMAC function called. raising hell.\n");

    return 0;
}
