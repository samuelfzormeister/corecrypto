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

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccpad.h>

extern void ccmode_xts_mult_alpha(uint8_t *I);

size_t ccpad_xts_decrypt(const struct ccmode_xts *xts,
                       ccxts_ctx *ctx, ccxts_tweak *tweak,
                       size_t nbytes, const void *in, void *out)
{
    uint8_t cbuf[16], pbuf[16] = {0};
    cc_size leftover = nbytes & 15;
    cc_size bytes = nbytes - leftover;
    const uint8_t *ct = in;
    uint8_t *pt = out;

    if (leftover == 0) {
        ccxts_update(xts, ctx, tweak, (bytes >> 4), ct, pt);
    } else {
        void *twk;
        cc_size i;
        twk = ccxts_update(xts, ctx, tweak, (bytes >> 4) - 1, ct, pt);
        cc_copy(16, cbuf, twk);
        ccmode_xts_mult_alpha(twk);

        ct += bytes - 16;
        pt += bytes - 16;

        ccxts_update(xts, ctx, tweak, 1, ct, pbuf);

        cc_copy(16, twk, cbuf);
        for (i = 0; i < leftover; i++) {
            cbuf[i] = ct[i + 16];
            pt[i + 16] = pbuf[i];
        }

        for (; i < 16; i++) {
            cbuf[i] = pbuf[i];
        }

        ccxts_update(xts, ctx, tweak, 1, cbuf, pt);
    }

    return nbytes;
}
