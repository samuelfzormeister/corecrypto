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

/*
 * Code adapted from LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */

#include "ccdes_ltc_internal.h"
#include <corecrypto/cc_config.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccdes.h>
#include <corecrypto/ccn.h>

static void cookey(const uint32_t *raw1, uint32_t *keyout);

void deskey(const unsigned char *key, short edf, uint32_t *keyout)
{
    uint32_t i, j, l, m, n, kn[32];
    unsigned char pc1m[56], pcr[56];

    for (j = 0; j < 56; j++) {
        l = (uint32_t)pc1[j];
        m = l & 7;
        pc1m[j] = (unsigned char)((key[l >> 3U] & bytebit[m]) == bytebit[m] ? 1 : 0);
    }

    for (i = 0; i < 16; i++) {
        if (edf == DE1) {
            m = (15 - i) << 1;
        } else {
            m = i << 1;
        }
        n = m + 1;
        kn[m] = kn[n] = 0L;
        for (j = 0; j < 28; j++) {
            l = j + (uint32_t)totrot[i];
            if (l < 28) {
                pcr[j] = pc1m[l];
            } else {
                pcr[j] = pc1m[l - 28];
            }
        }
        for (/*j = 28*/; j < 56; j++) {
            l = j + (uint32_t)totrot[i];
            if (l < 56) {
                pcr[j] = pc1m[l];
            } else {
                pcr[j] = pc1m[l - 28];
            }
        }
        for (j = 0; j < 24; j++) {
            if ((int)pcr[(int)pc2[j]] != 0) {
                kn[m] |= bigbyte[j];
            }
            if ((int)pcr[(int)pc2[j + 24]] != 0) {
                kn[n] |= bigbyte[j];
            }
        }
    }

    cookey(kn, keyout);
}

static void cookey(const uint32_t *raw1, uint32_t *keyout)
{
    uint32_t *cook;
    const uint32_t *raw0;
    uint32_t dough[32];
    int i;

    cook = dough;
    for (i = 0; i < 16; i++, raw1++) {
        raw0 = raw1++;
        *cook = (*raw0 & 0x00fc0000L) << 6;
        *cook |= (*raw0 & 0x00000fc0L) << 10;
        *cook |= (*raw1 & 0x00fc0000L) >> 10;
        *cook++ |= (*raw1 & 0x00000fc0L) >> 6;
        *cook = (*raw0 & 0x0003f000L) << 12;
        *cook |= (*raw0 & 0x0000003fL) << 16;
        *cook |= (*raw1 & 0x0003f000L) >> 4;
        *cook++ |= (*raw1 & 0x0000003fL);
    }

    cc_memcpy(keyout, dough, sizeof(dough));
}
