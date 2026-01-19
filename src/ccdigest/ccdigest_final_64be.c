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

#include <corecrypto/ccdigest.h>
#include <corecrypto/ccdigest_priv.h>

/* Ripped from XNU, as per ccdigest_final_64le.c's license header */
void ccdigest_final_64be(const struct ccdigest_info *di, ccdigest_ctx_t ctx,
                         void *digest)
{
    unsigned char *dgst = digest;
    ccdigest_nbits(di, ctx) += ccdigest_num(di, ctx) * 8;
    ccdigest_data(di, ctx)[ccdigest_num(di, ctx)++] = 0x80;

    /* If we don't have at least 8 bytes (for the length) left we need to add
     a second block. */
    if (ccdigest_num(di, ctx) > 64 - 8) {
        while (ccdigest_num(di, ctx) < 64) {
            ccdigest_data(di, ctx)[ccdigest_num(di, ctx)++] = 0;
        }
        di->compress(ccdigest_state(di, ctx), 1, ccdigest_data(di, ctx));
        ccdigest_num(di, ctx) = 0;
    }

    /* pad upto block_size minus 8 with 0s */
    while (ccdigest_num(di, ctx) < 64 - 8) {
        ccdigest_data(di, ctx)[ccdigest_num(di, ctx)++] = 0;
    }

    CC_STORE64_BE(ccdigest_nbits(di, ctx), ccdigest_data(di, ctx) + 64 - 8);
    di->compress(ccdigest_state(di, ctx), 1, ccdigest_data(di, ctx));

    /* copy output */
    for (unsigned int i = 0; i < di->output_size / 4; i++) {
        CC_STORE32_BE(ccdigest_state_u32(di, ctx)[i], dgst + (4 * i));
    }
}
