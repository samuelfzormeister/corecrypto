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
#include <corecrypto/ccchacha20poly1305_priv.h>

/*
 * REFERENCE SOURCES:
 *  - https://datatracker.ietf.org/doc/html/rfc7539
 */

#define CHACHA_QUARTERROUND(state, a, b, c, d)  \
    state[a] += state[b];                       \
    state[d] = CC_ROL(state[d] ^ state[a], 16); \
    state[c] += state[d];                       \
    state[b] = CC_ROL(state[b] ^ state[c], 12); \
    state[a] += state[b];                       \
    state[d] = CC_ROL(state[d] ^ state[a], 8);  \
    state[c] += state[d];                       \
    state[b] = CC_ROL(state[b] ^ state[c], 7);

/*
 *  c = constant, k - key, b = counter, n = nonce
 *  cccccccc  cccccccc  cccccccc  cccccccc
 *  kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
 *  kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
 *  bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn
 */

int ccchacha20_init(ccchacha20_ctx *ctx, const uint8_t *key)
{
    if (ctx == NULL || key == NULL) {
        return CCERR_PARAMETER;
    }

    if (ctx->state[0] != 0) {
        return CCERR_CALL_SEQUENCE;
    }

    // Setup the constants
    ctx->state[0] = CC_H2LE32(0x61707865);
    ctx->state[1] = CC_H2LE32(0x3320646e);
    ctx->state[2] = CC_H2LE32(0x79622d32);
    ctx->state[3] = CC_H2LE32(0x6b206574);

    // Copy the 8 bytes of key we need to state[4]
    // Should I worry about endianness? We're always going to be running on a LE system but IDK if I should future-proof this
    CC_WRITE_LE32(&ctx->state[4], *(uint32_t *)(key));
    CC_WRITE_LE32(&ctx->state[5], *(uint32_t *)(key + 4));
    CC_WRITE_LE32(&ctx->state[6], *(uint32_t *)(key + 8));
    CC_WRITE_LE32(&ctx->state[7], *(uint32_t *)(key + 12));
    CC_WRITE_LE32(&ctx->state[8], *(uint32_t *)(key + 16));
    CC_WRITE_LE32(&ctx->state[9], *(uint32_t *)(key + 20));
    CC_WRITE_LE32(&ctx->state[10], *(uint32_t *)(key + 24));
    CC_WRITE_LE32(&ctx->state[11], *(uint32_t *)(key + 28));

    return CCERR_OK;
}

int ccchacha20_setcounter(ccchacha20_ctx *ctx, uint32_t counter)
{
    if (ctx == NULL) {
        return CCERR_PARAMETER;
    }

    ctx->state[11] = CC_H2LE32(counter);

    return CCERR_OK;
}

int ccchacha20_setnonce(ccchacha20_ctx *ctx, const uint8_t *nonce)
{
    if (ctx == NULL || nonce == NULL) {
        return CCERR_PARAMETER;
    }

    if (ctx->state[13] == 0) {
        // big endian considerations?
        CC_WRITE_LE32(&ctx->state[13], *(uint32_t *)(nonce));
        CC_WRITE_LE32(&ctx->state[14], *(uint32_t *)(nonce + 4));
        CC_WRITE_LE32(&ctx->state[15], *(uint32_t *)(nonce + 8));
    } else {
        return CCERR_CALL_SEQUENCE;
    }

    return CCERR_OK;
}

int _ccchacha20_block(ccchacha20_ctx *ctx)
{
    uint32_t *buf = (uint32_t *)ctx->buffer;

    /* copy our initial state to the buffer */
    CC_MEMCPY(buf, ctx->state, CCCHACHA20_BLOCK_NBYTES);

    /* Setup our state */
    for (int r = 20; r > 0; r -= 2) {
        CHACHA_QUARTERROUND(buf, 0, 4, 8, 12);
        CHACHA_QUARTERROUND(buf, 1, 5, 9, 13);
        CHACHA_QUARTERROUND(buf, 2, 6, 10, 14);
        CHACHA_QUARTERROUND(buf, 3, 7, 11, 15);
        CHACHA_QUARTERROUND(buf, 0, 5, 10, 15);
        CHACHA_QUARTERROUND(buf, 1, 6, 11, 12);
        CHACHA_QUARTERROUND(buf, 2, 7, 8, 13);
        CHACHA_QUARTERROUND(buf, 3, 4, 9, 14);
    }

    /* once we're done, we have to add the initial state to the current state, or vice versa. */
    for (int s = 0; s < 16; s++) {
        buf[s] += ctx->state[s];
    }

    return CCERR_OK;
}

int ccchacha20_update(ccchacha20_ctx *ctx, size_t nbytes, const void *in, void *out)
{
    const uint32_t *data_chunk_ptr = in;
    uint32_t *out_chunk_buf = out;
    uint32_t *buf = (uint32_t *)ctx->buffer;

    if (ctx == NULL || in == NULL || out == NULL) {
        return CCERR_PARAMETER;
    }

    for (;;) {
        if (nbytes == 0) { break; }

        _ccchacha20_block(ctx);

        if (nbytes >= 64) {
            for (int x = 0; x < 16; x++) {
                buf[x] ^= CC_H2LE32(data_chunk_ptr[x]);
            }
            CC_MEMCPY(out_chunk_buf, ctx->buffer, 64);
        } else {
            uint8_t tmp[CCCHACHA20_BLOCK_NBYTES];
            CC_MEMCPY(tmp, data_chunk_ptr, nbytes);
            for (int x = 0; x < 16; x++) {
                buf[x] ^= CC_H2LE32(tmp[x]);
            }
            CC_MEMCPY(out_chunk_buf, ctx->buffer, nbytes);
            break; /* i ASSUME this means we're done here. */
        }

        ctx->state[12]++; /* if the counter spills over 0xFFFFFFFF then I think whoever is using this is stupid. */
        nbytes -= 64;
        data_chunk_ptr += 16;
        out_chunk_buf += 16;
    }

    return CCERR_OK;
}

// Is this really all it does?
// It doesn't even wipe the nonce.
int ccchacha20_reset(ccchacha20_ctx *ctx)
{

    ccchacha20_setcounter(ctx, 0); // reset counter

    return CCERR_OK;
}

int ccchacha20_final(ccchacha20_ctx *ctx)
{
    cc_clear(sizeof(*ctx), ctx);
    return CCERR_OK;
};

int ccchacha20(const void *key, const void *nonce, uint32_t counter, size_t nbytes, const void *in, void *out)
{
    // check that we have our required args
    if (key == NULL || nonce == NULL || in == NULL || out == NULL) {
        return CCERR_PARAMETER;
    }
    ccchacha20_ctx ctx;

    ccchacha20_init(&ctx, key);
    ccchacha20_setnonce(&ctx, nonce);
    ccchacha20_setcounter(&ctx, counter);
    ccchacha20_update(&ctx, nbytes, in, out);
    ccchacha20_final(&ctx);

    return CCERR_OK;
}
