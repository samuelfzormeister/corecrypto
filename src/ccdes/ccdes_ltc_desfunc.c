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

void desfunc(uint32_t *block, const uint32_t *keys)
{
    uint32_t work, right, leftt;
    int cur_round;

    leftt = block[0];
    right = block[1];

    work = ((leftt >> 4) ^ right) & 0x0f0f0f0fL;
    right ^= work;
    leftt ^= (work << 4);

    work = ((leftt >> 16) ^ right) & 0x0000ffffL;
    right ^= work;
    leftt ^= (work << 16);

    work = ((right >> 2) ^ leftt) & 0x33333333L;
    leftt ^= work;
    right ^= (work << 2);

    work = ((right >> 8) ^ leftt) & 0x00ff00ffL;
    leftt ^= work;
    right ^= (work << 8);

    right = CC_ROLc(right, 1);
    work = (leftt ^ right) & 0xaaaaaaaaL;

    leftt ^= work;
    right ^= work;
    leftt = CC_ROLc(leftt, 1);

    for (cur_round = 0; cur_round < 8; cur_round++) {
        work = CC_RORc(right, 4) ^ *keys++;
        leftt ^= SP7[work & 0x3fL]
            ^ SP5[(work >> 8) & 0x3fL]
            ^ SP3[(work >> 16) & 0x3fL]
            ^ SP1[(work >> 24) & 0x3fL];
        work = right ^ *keys++;
        leftt ^= SP8[work & 0x3fL]
            ^ SP6[(work >> 8) & 0x3fL]
            ^ SP4[(work >> 16) & 0x3fL]
            ^ SP2[(work >> 24) & 0x3fL];

        work = CC_RORc(leftt, 4) ^ *keys++;
        right ^= SP7[work & 0x3fL]
            ^ SP5[(work >> 8) & 0x3fL]
            ^ SP3[(work >> 16) & 0x3fL]
            ^ SP1[(work >> 24) & 0x3fL];
        work = leftt ^ *keys++;
        right ^= SP8[work & 0x3fL]
            ^ SP6[(work >> 8) & 0x3fL]
            ^ SP4[(work >> 16) & 0x3fL]
            ^ SP2[(work >> 24) & 0x3fL];
    }

    right = CC_RORc(right, 1);
    work = (leftt ^ right) & 0xaaaaaaaaL;
    leftt ^= work;
    right ^= work;
    leftt = CC_RORc(leftt, 1);
    work = ((leftt >> 8) ^ right) & 0x00ff00ffL;
    right ^= work;
    leftt ^= (work << 8);
    /* -- */
    work = ((leftt >> 2) ^ right) & 0x33333333L;
    right ^= work;
    leftt ^= (work << 2);
    work = ((right >> 16) ^ leftt) & 0x0000ffffL;
    leftt ^= work;
    right ^= (work << 16);
    work = ((right >> 4) ^ leftt) & 0x0f0f0f0fL;
    leftt ^= work;
    right ^= (work << 4);

    block[0] = right;
    block[1] = leftt;
}
