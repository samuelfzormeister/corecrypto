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

#include <corecrypto/cc_debug.h>
#include <corecrypto/cctest_internal.h>
#include <corecrypto/ccchacha20poly1305_priv.h>

struct _ccchacha20_test_ctx {
    const struct cctest_info *me;
    ccchacha20_ctx ctx;
};

#define CCCHACHA20_TEST_CTX(cx) (struct _ccchacha20_test_ctx *)cx

static void ccchacha20_dump_state(ccchacha20_ctx *ctx)
{
    cc_printf("[CCTEST][CHACHA20]: CURRENT STATE:\n");

    uint32_t *state = ctx->state;
    
    for (cc_size i = 0; i < 16; i++) {
        if ((i % 8) == 0) {
            if (i > 0) {
                cc_printf("\n");
            }
        }
        cc_printf("%04x ", *state);
        state++;
    }

    cc_printf("\n");

    cc_printf("[CCTEST][CHACHA20]: CURRENT BUFFER:\n");

    uint8_t *buffer = ctx->buffer;

    for (cc_size i = 0; i < 64; i++) {
        if ((i % 8) == 0) {
            if (i > 0) {
                cc_printf("\n");
            }
        }
        cc_printf("%02x ", *buffer);
        buffer++;
    }
}

//
// RFC 7539 - Section 2.3.2
//
#pragma mark - Block Function Test

static const uint8_t ccchacha20_block_test_key[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

static const uint8_t ccchacha20_block_test_nonce[] = {
    0x00, 0x00, 0x00, 0x09,
    0x00, 0x00, 0x00, 0x4a,
    0x00, 0x00, 0x00, 0x00
};

/*
  000  10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4  .....;Y.P.... q.
  016  c7 d1 f4 c7 33 c0 68 03 04 22 aa 9a c3 d4 6c 4e  ....3.h.."....lN
  032  d2 82 64 46 07 9f aa 09 14 c2 d7 05 d9 8b 02 a2  ..dF............
  048  b5 12 9c d1 de 16 4e b9 cb d0 83 e8 a2 50 3c 4e  ......N......P<N
 */
static const uint8_t ccchacha20_block_test_expected_state[] = {
    0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
    0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
    0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
    0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
    0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
    0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
    0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
    0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e
};

//
// we're testing the block function only.
//
extern int _ccchacha20_block(ccchacha20_ctx *ctx);

int ccchacha20_block_test(cctest_ctx *cx) {
    struct _ccchacha20_test_ctx *ctx = CCCHACHA20_TEST_CTX(cx);
    ccchacha20_init(&ctx->ctx, &ccchacha20_block_test_key);
    ccchacha20_setnonce(&ctx->ctx, &ccchacha20_block_test_nonce);
    _ccchacha20_block(&ctx->ctx);

    if (cc_cmp_safe(sizeof(ctx->ctx.buffer), ctx->ctx.buffer, 
               ccchacha20_block_test_expected_state) == 0) {
        cctest_trace_pass_named(CCTEST_SUBSYSTEM_CHACHA20, ctx->me->name, "BLOCK FUNCTION TEST");
        ccchacha20_final(&ctx->ctx);
        return 0;
    } else {
        cctest_trace_fail_named(CCTEST_SUBSYSTEM_CHACHA20, ctx->me->name, "BLOCK FUNCTION TEST");
        ccchacha20_dump_state(&ctx->ctx);
        ccchacha20_final(&ctx->ctx);
        return -1;
    }
}


