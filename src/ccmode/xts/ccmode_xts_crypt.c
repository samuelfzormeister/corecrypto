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
#include <corecrypto/ccmode_internal.h>

/* not mentioned outside of the symbol table, assuming this runs xts_mult_x using the first parameter as the tweak */
void ccmode_xts_mult_alpha(uint8_t *I)
{
    int idx;
    uint8_t t, tt;

    for (idx = t = 0; idx < 16; idx++) {
        tt = I[idx] >> 7;
        I[idx] = ((I[idx] << 1) | t) & 0xFF;
        t = tt;
    }

    if (tt) {
        I[0] ^= 0x87;
    }
}

/* the function that everyone's been waiting for. */

/* ccmode_xts's declaration says we return the pointer to the tweak buffer */
void *ccmode_xts_crypt(const ccxts_ctx *ctx, ccxts_tweak *tweak,
                       size_t nblocks, const void *in, void *out)
{
    /* grab our actual key and tweak pointers */
    struct _ccmode_xts_key *key = (struct _ccmode_xts_key *)ctx;
    struct _ccmode_xts_tweak *twk = (struct _ccmode_xts_tweak *)tweak;

    /*
     * set_tweak has already been called at this point, therefore we don't need
     * to worry about anything to do with tweak enc
     */

    /* so, does XTS have a set block size? */
    while (nblocks--) {
        /* en/de crypt the block using the tweak */

        /* check that the tweak counter hasn't overflowed. */
        if (twk->blocks_processed >= CCMODE_XTS_TWEAK_MAX_BLOCKS_PROCESSED) {
            /* We shouldn't en/de crypt any futher as per FIPS */
            return NULL;
        }

        /* first, XOR the plaintext with the tweak */
        cc_xor(ccecb_block_size(key->ecb), out, in, &twk->u);

        /* then, en/de crypt the block using ecb */
        ccecb_update(key->ecb, CCMODE_XTS_KEY_ECB_CTX(key), 1, out, out);

        /* then, XOR the block using the tweak */
        cc_xor(ccecb_block_size(key->ecb), out, out, &twk->u);

        /* then, multiply the tweak */
        ccmode_xts_mult_alpha((uint8_t *)&twk->u);

        /* finally, increment the tweak counter and progress the pointers. */
        twk->blocks_processed++;

        in += ccecb_block_size(key->ecb);
        out += ccecb_block_size(key->ecb);
    }

    return &twk->u; /* Is this how it should work? */
}
