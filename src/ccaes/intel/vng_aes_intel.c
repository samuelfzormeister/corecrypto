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

#include <corecrypto/cc_config.h>

#if CCAES_INTEL_ASM

#include "vng_aes_intel.h"

int vng_aes_xts_encrypt_aesni(const uint8_t *pt, unsigned long ptlen, uint8_t *ct, const uint8_t *T, void *ctx)
{
    vng_aes_intel_encrypt_ctx *encrypt_ctx = (vng_aes_intel_encrypt_ctx *)ctx;

    uint8_t PP[16], CC[16];
    uint64_t i, m, mo, lim;
    uint64_t err;

    /* get number of blocks */
    m = ptlen >> 4;
    mo = ptlen & 15;

    /* must have at least one full block */
    if (m == 0) {
        return CRYPT_INVALID_ARG;
    }

    /* for i = 0 to m-2 do */
    if (mo == 0) {
        lim = m;
    } else {
        lim = m - 1;
    }

    if (lim > 0) {
        err = aesxts_tweak_crypt_group_aesni(pt, ct, T, encrypt_ctx, lim);
        ct += (lim << 4);
        pt += (lim << 4);
    }

    /* if ptlen not divide 16 then */
    if (mo > 0) {
        /* CC = tweak encrypt block m-1 */
        if ((err = aesxts_tweak_crypt_aesni(pt, CC, T, encrypt_ctx)) != 0) {
            return err;
        }

        /* Cm = first ptlen % 16 bytes of CC */
        for (i = 0; i < mo; i++) {
            PP[i] = pt[16 + i];
            ct[16 + i] = CC[i];
        }

        for (; i < 16; i++) {
            PP[i] = CC[i];
        }

        /* Cm-1 = Tweak encrypt PP */
        if ((err = aesxts_tweak_crypt_aesni(PP, ct, T, encrypt_ctx)) != 0) {
            return err;
        }
    }

    return err;
}

int vng_aes_xts_encrypt_opt(const uint8_t *pt, unsigned long ptlen, uint8_t *ct, const uint8_t *T, void *ctx)
{
    vng_aes_intel_encrypt_ctx *encrypt_ctx = (vng_aes_intel_encrypt_ctx *)ctx;

    uint8_t PP[16], CC[16];
    uint64_t i, m, mo, lim;
    uint64_t err;

    /* get number of blocks */
    m = ptlen >> 4;
    mo = ptlen & 15;

    /* must have at least one full block */
    if (m == 0) {
        return CRYPT_INVALID_ARG;
    }

    /* for i = 0 to m-2 do */
    if (mo == 0) {
        lim = m;
    } else {
        lim = m - 1;
    }

    if (lim > 0) {
        err = aesxts_tweak_crypt_group_opt(pt, ct, T, encrypt_ctx, lim);
        ct += (lim << 4);
        pt += (lim << 4);
    }

    /* if ptlen not divide 16 then */
    if (mo > 0) {
        /* CC = tweak encrypt block m-1 */
        if ((err = aesxts_tweak_crypt_opt(pt, CC, T, encrypt_ctx)) != 0) {
            return err;
        }

        /* Cm = first ptlen % 16 bytes of CC */
        for (i = 0; i < mo; i++) {
            PP[i] = pt[16 + i];
            ct[16 + i] = CC[i];
        }

        for (; i < 16; i++) {
            PP[i] = CC[i];
        }

        /* Cm-1 = Tweak encrypt PP */
        if ((err = aesxts_tweak_crypt_opt(PP, ct, T, encrypt_ctx)) != 0) {
            return err;
        }
    }

    return err;
}

int vng_aes_xts_decrypt_aesni(const uint8_t *ct, unsigned long ptlen, uint8_t *pt, const uint8_t *tweak, void *ctx)
{
    vng_aes_intel_decrypt_ctx *decrypt_ctx = (vng_aes_intel_decrypt_ctx *)ctx;
    uint8_t PP[16], CC[16], T[16];
    uint64_t i, m, mo, lim;
    uint64_t err;

    /* check inputs */
    if ((pt == NULL) || (ct == NULL) || (tweak == NULL) || (ctx == NULL)) {
        return 1;
    }

    /* get number of blocks */
    m = ptlen >> 4;
    mo = ptlen & 15;

    /* must have at least one full block */
    if (m == 0) {
        return CRYPT_INVALID_ARG;
    }

    /* for i = 0 to m-2 do */
    if (mo == 0) {
        lim = m;
    } else {
        lim = m - 1;
    }

    if (lim > 0) {
        err = aesxts_tweak_uncrypt_group_aesni(ct, pt, T, decrypt_ctx, lim);
        ct += (lim << 4);
        pt += (lim << 4);
    }

    /* if ptlen not divide 16 then */
    if (mo > 0) {
        memcpy(CC, T, 16);
        aesxts_mult_x(CC);

        /* PP = tweak decrypt block m-1 */
        if ((err = aesxts_tweak_uncrypt_aesni(ct, PP, CC, decrypt_ctx)) != CRYPT_OK) {
            return err;
        }

        /* Pm = first ptlen % 16 bytes of PP */
        for (i = 0; i < mo; i++) {
            CC[i] = ct[16 + i];
            pt[16 + i] = PP[i];
        }
        for (; i < 16; i++) {
            CC[i] = PP[i];
        }

        /* Pm-1 = Tweak uncrypt CC */
        if ((err = aesxts_tweak_uncrypt_aesni(CC, pt, T, decrypt_ctx)) != CRYPT_OK) {
            return err;
        }
    }

    return CRYPT_OK;
}

int vng_aes_xts_decrypt_opt(const uint8_t *ct, unsigned long ptlen, uint8_t *pt, const uint8_t *tweak, void *ctx)
{
    vng_aes_intel_decrypt_ctx *decrypt_ctx = (vng_aes_intel_decrypt_ctx *)ctx;
    uint8_t PP[16], CC[16], T[16];
    uint64_t i, m, mo, lim;
    uint64_t err;

    /* check inputs */
    if ((pt == NULL) || (ct == NULL) || (tweak == NULL) || (ctx == NULL)) {
        return 1;
    }

    /* get number of blocks */
    m = ptlen >> 4;
    mo = ptlen & 15;

    /* must have at least one full block */
    if (m == 0) {
        return CRYPT_INVALID_ARG;
    }

    /* for i = 0 to m-2 do */
    if (mo == 0) {
        lim = m;
    } else {
        lim = m - 1;
    }

    if (lim > 0) {
        err = aesxts_tweak_uncrypt_group_opt(ct, pt, T, decrypt_ctx, lim);
        ct += (lim << 4);
        pt += (lim << 4);
    }

    /* if ptlen not divide 16 then */
    if (mo > 0) {
        memcpy(CC, T, 16);
        aesxts_mult_x(CC);

        /* PP = tweak decrypt block m-1 */
        if ((err = aesxts_tweak_uncrypt_opt(ct, PP, CC, decrypt_ctx)) != CRYPT_OK) {
            return err;
        }

        /* Pm = first ptlen % 16 bytes of PP */
        for (i = 0; i < mo; i++) {
            CC[i] = ct[16 + i];
            pt[16 + i] = PP[i];
        }
        for (; i < 16; i++) {
            CC[i] = PP[i];
        }

        /* Pm-1 = Tweak uncrypt CC */
        if ((err = aesxts_tweak_uncrypt_opt(CC, pt, T, decrypt_ctx)) != CRYPT_OK) {
            return err;
        }
    }

    return CRYPT_OK;
}

#endif
