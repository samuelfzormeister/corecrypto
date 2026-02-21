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

#include <corecrypto/ccpad.h>

extern void ccmode_xts_mult_alpha(uint8_t *I);

void ccpad_xts_encrypt(const struct ccmode_xts *xts,
                       ccxts_ctx *ctx, ccxts_tweak *tweak,
                       size_t nbytes, const void *in, void *out)
{
    uint8_t cbuf[16], pbuf[16] = {0};
    cc_size leftover = nbytes & 15;
    cc_size bytes = nbytes - leftover;
    const uint8_t *pt = in;
    uint8_t *ct = out;

    if (leftover == 0) {
        ccxts_update(xts, ctx, tweak, (bytes >> 4), pt, ct);
        return;
    } else {
        cc_size i;
        ccxts_update(xts, ctx, tweak, (bytes >> 4) - 1, pt, ct);
        pt += bytes - 16;
        ct += bytes - 16;
        ccxts_update(xts, ctx, tweak, 1, pt, cbuf);

        for (i = 0; i < leftover; i++) {
            pbuf[i] = pt[i];
            ct[i] = cbuf[i];
        }

        for (; i < 16; i++) {
            pbuf[i] = cbuf[i];
        }

        ccxts_update(xts, ctx, tweak, 1, pbuf, ct - 16);
    }
}
