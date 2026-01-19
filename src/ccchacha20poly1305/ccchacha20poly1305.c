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

#include "corecrypto/cc.h"
#include "corecrypto/cc_priv.h"
#include <corecrypto/cc_macros.h>
#include <corecrypto/ccchacha20poly1305.h>
#include <corecrypto/ccchacha20poly1305_priv.h>

// decl from chacha20.c
extern int _ccchacha20_block(ccchacha20_ctx *ctx);

static const uint8_t constant_zero_64[64] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

const struct ccchacha20poly1305_info ccchacha20poly1305_info_default;

const struct ccchacha20poly1305_info *ccchacha20poly1305_info(void) { return &ccchacha20poly1305_info_default; }

int ccchacha20poly1305_init(const struct ccchacha20poly1305_info *info, ccchacha20poly1305_ctx *ctx, const uint8_t *key)
{
    ccchacha20_init(&ctx->chacha20_ctx, key);

    return 0;
}

int ccchacha20poly1305_reset(const struct ccchacha20poly1305_info *info, ccchacha20poly1305_ctx *ctx)
{
    ctx->aad_nbytes = 0;
    ctx->text_nbytes = 0;
    ctx->state = CCCHACHA20POLY1305_STATE_SETNONCE;

    ccchacha20_reset(&ctx->chacha20_ctx);

    return CCERR_OK;
}

int ccchacha20poly1305_setnonce(const struct ccchacha20poly1305_info *info, ccchacha20poly1305_ctx *ctx, const uint8_t *nonce)
{
    /* Use the AssertMacros-like utilities. */
    cc_require(ctx->state == CCCHACHA20POLY1305_STATE_SETNONCE, bail);

    ccchacha20_setnonce(&ctx->chacha20_ctx, nonce);

    /* create the block */
    _ccchacha20_block(&ctx->chacha20_ctx);

    /* that is our poly1305 key */
    ccpoly1305_init(&ctx->poly1305_ctx, ctx->chacha20_ctx.buffer);

    ctx->state = CCCHACHA20POLY1305_STATE_AAD;

    return 0;

bail:
    return 1;
}

int ccchacha20poly1305_aad(const struct ccchacha20poly1305_info *info, ccchacha20poly1305_ctx *ctx, size_t nbytes, const void *aad)
{
    cc_require(ctx->state == CCCHACHA20POLY1305_STATE_AAD, bail);

    ccpoly1305_update(&ctx->poly1305_ctx, nbytes, aad);
    ctx->aad_nbytes += nbytes;

bail:
    return 1;
}

int ccchacha20poly1305_encrypt(const struct ccchacha20poly1305_info *info, ccchacha20poly1305_ctx *ctx, size_t nbytes, const void *ptext, void *ctext)
{
    /*
     * padding1 -- the padding is up to 15 zero bytes, and it brings
     *    the total length so far to an integral multiple of 16.  If the
     *    length of the AAD was already an integral multiple of 16 bytes,
     *    this field is zero-length.
     */
    if (ctx->state == CCCHACHA20POLY1305_STATE_AAD) {
        /* pad out the aad */
        size_t padding = (16 - (ctx->aad_nbytes & 0xf)) & 0xf;
        ccpoly1305_update(&ctx->poly1305_ctx, padding, constant_zero_64);
        /* and set the state for good measure. */
        ctx->state = CCCHACHA20POLY1305_STATE_ENCRYPT;
    }

    cc_require(ctx->state == CCCHACHA20POLY1305_STATE_ENCRYPT, bail);

    /* Enforce this constraint. */
    cc_require(ctx->text_nbytes + nbytes <= CCCHACHA20POLY1305_TEXT_MAX_NBYTES, bail);

    ccchacha20_update(&ctx->chacha20_ctx, nbytes, ptext, ctext);
    ccpoly1305_update(&ctx->poly1305_ctx, nbytes, ctext);

    ctx->text_nbytes += nbytes;

    return 0;

bail:
    return 1;
}

int ccchacha20poly1305_decrypt(const struct ccchacha20poly1305_info *info, ccchacha20poly1305_ctx *ctx, size_t nbytes, const void *ctext, void *ptext)
{
    /*
     * padding1 -- the padding is up to 15 zero bytes, and it brings
     *    the total length so far to an integral multiple of 16.  If the
     *    length of the AAD was already an integral multiple of 16 bytes,
     *    this field is zero-length.
     */
    if (ctx->state == CCCHACHA20POLY1305_STATE_AAD) {
        /* pad out the aad */
        size_t padding = (16 - (ctx->aad_nbytes & 0xf)) & 0xf;
        ccpoly1305_update(&ctx->poly1305_ctx, padding, constant_zero_64);
        /* and set the state for good measure. */
        ctx->state = CCCHACHA20POLY1305_STATE_DECRYPT;
    }

    cc_require(ctx->state == CCCHACHA20POLY1305_STATE_DECRYPT, bail);

    /* Enforce this constraint. */
    cc_require(ctx->text_nbytes + nbytes <= CCCHACHA20POLY1305_TEXT_MAX_NBYTES, bail);

    ccpoly1305_update(&ctx->poly1305_ctx, nbytes, ctext);
    ccchacha20_update(&ctx->chacha20_ctx, nbytes, ctext, ptext);

    ctx->text_nbytes += nbytes;

    return 0;

bail:
    return 1;
}

int ccchacha20poly1305_finalize(const struct ccchacha20poly1305_info *info, ccchacha20poly1305_ctx *ctx, uint8_t *tag)
{
    /*
     * padding1 -- the padding is up to 15 zero bytes, and it brings
     *    the total length so far to an integral multiple of 16.  If the
     *    length of the AAD was already an integral multiple of 16 bytes,
     *    this field is zero-length.
     */
    if (ctx->state == CCCHACHA20POLY1305_STATE_AAD) {
        /* pad out the aad */
        size_t padding = (16 - (ctx->aad_nbytes & 0xf)) & 0xf;
        ccpoly1305_update(&ctx->poly1305_ctx, padding, constant_zero_64);
        /* and set the state for good measure. */
        ctx->state = CCCHACHA20POLY1305_STATE_ENCRYPT;
    }

    cc_require(ctx->state == CCCHACHA20POLY1305_STATE_ENCRYPT, bail);

    /* padding2 as per RFC 7539 */
    size_t padding = (16 - (ctx->text_nbytes & 0xf)) & 0xf;
    ccpoly1305_update(&ctx->poly1305_ctx, padding, constant_zero_64);

    uint8_t buffer[8];

    /* AAD data length */
    CC_WRITE_LE64(buffer, ctx->aad_nbytes);
    ccpoly1305_update(&ctx->poly1305_ctx, 8, buffer);

    /* text byte length */
    CC_WRITE_LE64(buffer, ctx->text_nbytes);
    ccpoly1305_update(&ctx->poly1305_ctx, 8, buffer);

    /* generate the tag */
    ccpoly1305_final(&ctx->poly1305_ctx, tag);

    ctx->state = CCCHACHA20POLY1305_STATE_FINAL;

    return 0;

bail:
    return 1;
}

int ccchacha20poly1305_verify(const struct ccchacha20poly1305_info *info, ccchacha20poly1305_ctx *ctx, const uint8_t *tag)
{
    uint8_t buffer[16];
    /* Run finalize, we want the tag. */

    ccchacha20poly1305_finalize(info, ctx, buffer);

    return cc_cmp_safe(16, buffer, tag) == 0 ? 0 : -1;
}

int ccchacha20poly1305_encrypt_oneshot(const struct ccchacha20poly1305_info *info, const uint8_t *key, const uint8_t *nonce, size_t aad_nbytes, const void *aad, size_t ptext_nbytes, const void *ptext, void *ctext, uint8_t *tag)
{
    ccchacha20poly1305_ctx ctx;

    ccchacha20poly1305_init(info, &ctx, key);
    ccchacha20poly1305_setnonce(info, &ctx, nonce);
    ccchacha20poly1305_aad(info, &ctx, aad_nbytes, aad);
    ccchacha20poly1305_encrypt(info, &ctx, ptext_nbytes, ptext, ctext);
    ccchacha20poly1305_finalize(info, &ctx, tag);

    return 0;
}

int ccchacha20poly1305_decrypt_oneshot(const struct ccchacha20poly1305_info *info, const uint8_t *key, const uint8_t *nonce, size_t aad_nbytes, const void *aad, size_t ctext_nbytes, const void *ctext, void *ptext, const uint8_t *tag)
{
    ccchacha20poly1305_ctx ctx;

    ccchacha20poly1305_init(info, &ctx, key);
    ccchacha20poly1305_setnonce(info, &ctx, nonce);
    ccchacha20poly1305_aad(info, &ctx, aad_nbytes, aad);
    ccchacha20poly1305_decrypt(info, &ctx, ctext_nbytes, ctext, ptext);

    return ccchacha20poly1305_verify(info, &ctx, tag);
    ;
}

int ccchacha20poly1305_incnonce(const struct ccchacha20poly1305_info *info, ccchacha20poly1305_ctx *ctx, uint8_t *nonce)
{
    return 1;
}
