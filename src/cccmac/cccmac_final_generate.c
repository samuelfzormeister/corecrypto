/*
 * Copyright (C) 2026 The PureDarwin Project, All rights reserved.
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

#include <corecrypto/cc.h>
#include <corecrypto/cccmac_priv.h>
#include <corecrypto/ccmode.h>

int cccmac_final_generate(cccmac_ctx_t ctx, size_t mac_nbytes, void *mac)
{
    const struct ccmode_cbc *cbc = cccmac_cbc(ctx);
    uint8_t *subkey = cccmac_k2(ctx);
    uint8_t *last_block = cccmac_block(ctx);
    cc_size leftover = cccmac_block_nbytes(ctx);
    uint8_t mac_buf[CMAC_BLOCKSIZE];

    /* account for one last block (the MAC) */
    cccmac_cumulated_nbytes(ctx) += CMAC_BLOCKSIZE;

    /* if we don't have any padding, use K1 per the spec */
    if (leftover == CMAC_BLOCKSIZE) {
        subkey = cccmac_k1(ctx);
    } else {
        /* pad and use K2 */
        cc_clear(CMAC_BLOCKSIZE - leftover,last_block + leftover);
        last_block[leftover] = 0x80;
    }

    cc_xor(CMAC_BLOCKSIZE, last_block, last_block, subkey);
    cccbc_update(cbc, cccmac_mode_sym_ctx(cbc, ctx), cccmac_mode_iv(cbc, ctx), 1, last_block, mac_buf);
    cc_copy(mac_nbytes, mac, mac_buf);

    cccmac_mode_clear(cbc, cccmac_mode_sym_ctx(cbc, ctx));
    return 0;
}
