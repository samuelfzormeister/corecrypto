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

#include <corecrypto/cc.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/cc_debug.h>
#include <corecrypto/cc_memory.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccdigest_test_internal.h>
#include <corecrypto/cctest_internal.h>

void ccdigest_test_dump_state(cctest_ctx *tx)
{
    struct _ccdigest_test_ctx *ctx = CCDIGEST_TEST_CTX(tx);
    ccdigest_state_t state = ccdigest_state(ctx->di, (struct ccdigest_ctx *)&CCDIGEST_TEST_CTX(ctx)->u);
    uint8_t *byte = ccdigest_u8(state);

    cc_printf("[CCTEST][DIGEST][%s]: CURRENT STATE:\n", ctx->ti->name);

    for (cc_size i = 0; i < ctx->di->state_size; i++) {
        if ((i % 8) == 0) {
            if (i > 0) {
                cc_printf("\n");
            }
        }
        cc_printf("%02x", *byte);
        byte++;
    }
    
    cc_printf("\n");
    
    cc_printf("[CCTEST][DIGEST][%s]: SCRATCH MEMORY:\n", ctx->ti->name);
    
    byte = (uint8_t *)CCDIGEST_TEST_CTX_SCRATCH_SPACE(ctx);
    
    for (cc_size i = 0; i < ctx->di->output_size; i++) {
        if ((i % 8) == 0) {
            if (i > 0) {
                cc_printf("\n");
            }
        }
        cc_printf("%02x ", *byte);
        byte++;
    }
    
    cc_printf("\n");
}

int ccdigest_test_init(const struct cctest_info *info, cctest_ctx *ctx)
{
    struct _ccdigest_test_ctx *dt = CCDIGEST_TEST_CTX(ctx);

    cctest_trace_general(CCTEST_SUBSYSTEM_DIGEST, info->name, "init >>");

    dt->di = (const struct ccdigest_info *)info->custom;
    dt->vi = CCDIGEST_TEST_VI(info->custom1);
    dt->ctx_size = ccdigest_di_size(dt->di);
    dt->ti = info;

    cctest_trace_general(CCTEST_SUBSYSTEM_DIGEST, info->name, "init <<");

    return 0;
}

int ccdigest_test_run(cctest_ctx *ctx)
{
    int res = 0;
    const struct ccdigest_info *di = CCDIGEST_TEST_CTX(ctx)->di;
    const struct ccdigest_test_vector_info *vi = CCDIGEST_TEST_CTX(ctx)->vi;
    void *scratch = CCDIGEST_TEST_CTX_SCRATCH_SPACE(CCDIGEST_TEST_CTX(ctx));
    ccdigest_ctx_t dctx = CCDIGEST_TEST_CTX_DIGEST_CTX(CCDIGEST_TEST_CTX(ctx));

    cctest_trace_general(CCTEST_SUBSYSTEM_DIGEST, CCDIGEST_TEST_CTX(ctx)->ti->name, "run >>");

    for (size_t i = 0; i < vi->nvectors; i++) {
        struct ccdigest_test_vector vec = vi->vectors[i];
        ccdigest_init(di, dctx);
        ccdigest_update(di, dctx, vec.msg_len, vec.message);
        ccdigest_final(di, dctx, scratch);
        if (cc_cmp_safe(di->output_size, vec.expected_digest, scratch) != 0) {
            cctest_trace_fail(CCTEST_SUBSYSTEM_DIGEST, CCDIGEST_TEST_CTX(ctx)->ti->name, i+1);
            ccdigest_test_dump_state(ctx);
        } else {
            cctest_trace_pass(CCTEST_SUBSYSTEM_DIGEST, CCDIGEST_TEST_CTX(ctx)->ti->name, i+1);
        }

        ccdigest_ctx_clear(di->state_size, di->block_size, dctx);
        cc_clear(di->output_size, scratch);
    }

    cctest_trace_general(CCTEST_SUBSYSTEM_DIGEST, CCDIGEST_TEST_CTX(ctx)->ti->name, "run <<");

    return res;
}

void ccdigest_test_factory(struct cctest_info *ti, const struct ccdigest_info *di, const char *name, struct ccdigest_test_vector_info *vi)
{
    ti->custom = (const void *)di;
    ti->custom1 = (const void *)vi;
    ti->size = ccdigest_di_size(di) + sizeof(struct _ccdigest_test_ctx) + di->output_size;
    ti->init = &ccdigest_test_init;
    ti->run = &ccdigest_test_run;
    ti->dump_state = &ccdigest_test_dump_state;
    ti->name = name;
}

