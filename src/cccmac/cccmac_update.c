/*
 * Copyright (C) 2025-2026 The PureDarwin Project, All rights reserved.
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
#include <corecrypto/ccmode.h>

#define CCCMAC_DEBUG 1

#if CCCMAC_DEBUG
#include <corecrypto/cc_debug.h>

#define cccmac_debug(...) cc_printf("cccmac: " __VA_ARGS__) 
#else
#define cccmac_debug(...)
#endif

int cccmac_update(cccmac_ctx_t ctx, size_t data_nbytes, const void *data)
{
    const struct ccmode_cbc *cbc = cccmac_cbc(ctx);
    uint8_t buf[CMAC_BLOCKSIZE];
    cc_size nblocks;
    cc_size resume;
    cc_size leftover;

    cccmac_debug("updating context.\n");

    // if data_nbytes is less than the carry over byte count, use data_nbytes.
    resume = CC_MIN(data_nbytes, (CMAC_BLOCKSIZE - cccmac_block_nbytes(ctx)));
    cccmac_debug("resuming with %zd bytes to process", resume);

    /* always check for any remaining bytes from the last update call. */
    if (cccmac_block_nbytes(ctx) > 0) {
        cc_memcpy(cccmac_block(ctx) + cccmac_block_nbytes(ctx), data, resume);
        /* quickly check that we have enough bytes to update the block */
        if (resume + cccmac_block_nbytes(ctx) < CMAC_BLOCKSIZE) {
            cccmac_block_nbytes(ctx) += resume;
            return 0;
        }
        cccbc_update(cbc, cccmac_mode_sym_ctx(cbc, ctx), cccmac_mode_iv(cbc, ctx), 1, cccmac_block(ctx), buf);
        cccmac_cumulated_nbytes(ctx) += CMAC_BLOCKSIZE;
        cccmac_block_nbytes(ctx) += resume;
        data += resume;
    }

    /* get the number of blocks we have */
    nblocks = cc_ceiling(data_nbytes, CMAC_BLOCKSIZE);
    leftover = data_nbytes - (nblocks * CMAC_BLOCKSIZE);

    while (nblocks) {
        cccbc_update(cbc, cccmac_mode_sym_ctx(cbc, ctx), cccmac_mode_iv(cbc, ctx), 1, data, buf);
        data += CMAC_BLOCKSIZE;
        cccmac_cumulated_nbytes(ctx) += CMAC_BLOCKSIZE;
        nblocks--;
    }

    cc_memcpy(cccmac_block(ctx), data, leftover);
    cccmac_block_nbytes(ctx) = leftover;

    return 0;
}
