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

int ccdigest_test_init(const struct cctest_info *info, cctest_ctx *ctx)
{
    struct _ccdigest_test_ctx *dt = CCDIGEST_TEST_CTX(ctx);

    cctest_trace_general(CCTEST_SUBSYSTEM_DIGEST, info->name, "init >>");

    dt->di = (const struct ccdigest_info *)info->custom;
    dt->vi = CCDIGEST_TEST_VI(info->custom1);
    cc_printf("%zx\n", dt->vi->nvectors);
    dt->ctx_size = ccdigest_ctx_size(dt->di->state_size, dt->di->block_size);
    dt->ti = info;

    cctest_trace_general(CCTEST_SUBSYSTEM_DIGEST, info->name, "init <<");

    return 0;
}

int ccdigest_test_run(cctest_ctx *ctx)
{
    int res = 0;
    const struct ccdigest_info *di = CCDIGEST_TEST_CTX(ctx)->di;
    const struct ccdigest_test_vector_info *vi = CCDIGEST_TEST_CTX(ctx)->vi;
    struct ccdigest_ctx *dc = (struct ccdigest_ctx *)&CCDIGEST_TEST_CTX(ctx)->u;
    void *scratch = CCDIGEST_TEST_CTX_SCRATCH_SPACE(CCDIGEST_TEST_CTX(ctx));

    cctest_trace_general(CCTEST_SUBSYSTEM_DIGEST, CCDIGEST_TEST_CTX(ctx)->ti->name, "run >>");
    cc_printf("%p\n", ctx);
    cc_printf("%p\n", vi);
    cc_printf("%p\n", scratch);
    cc_printf("%zx\n", vi->nvectors);

    for (size_t i = 0; i < vi->nvectors; i++) {
        struct ccdigest_test_vector vec = vi->vectors[i];
        cctest_trace_general(CCTEST_SUBSYSTEM_DIGEST, CCDIGEST_TEST_CTX(ctx)->ti->name, "doing test iter:");
        cc_printf("%zx\n", i);

        cctest_trace_general(CCTEST_SUBSYSTEM_DIGEST, CCDIGEST_TEST_CTX(ctx)->ti->name, "cond");
        cc_printf("%p\n", scratch);
        ccdigest(di, vec.msg_len, vec.message, scratch);

        res |= (cc_memcmp(vec.expected_digest, scratch, di->output_size) == 0) &&
                    !(vec.attrs & CCTEST_ATTR_EXPECTEDFAIL);
        
        if (res != 0) {
            cctest_trace_fail(CCTEST_SUBSYSTEM_DIGEST, CCDIGEST_TEST_CTX(ctx)->ti->name, i+1);
        }

        ccdigest_ctx_clear(di->state_size, di->block_size, dc);
        cc_clear(di->output_size, scratch);
    }

    cctest_trace_general(CCTEST_SUBSYSTEM_DIGEST, CCDIGEST_TEST_CTX(ctx)->ti->name, "run <<");

    return res;
}

void ccdigest_test_dump_state(cctest_ctx *tx)
{
    struct _ccdigest_test_ctx *ctx = CCDIGEST_TEST_CTX(tx);
    ccdigest_state_t state = ccdigest_state(ctx->di, (struct ccdigest_ctx *)&CCDIGEST_TEST_CTX(ctx)->u);
    uint8_t *byte = ccdigest_u8(state);

    cctest_trace_general(CCTEST_SUBSYSTEM_DIGEST, CCDIGEST_TEST_CTX(ctx)->ti->name, "dump state >>");

    cc_printf("[CCTEST][DIGEST][%s]: CURRENT STATE:", ctx->ti->name);

    for (cc_size i = 0; i < ctx->di->state_size; i++) {
        cc_printf("%02x", *byte);
        byte++;
    }

    cctest_trace_general(CCTEST_SUBSYSTEM_DIGEST, CCDIGEST_TEST_CTX(ctx)->ti->name, "dump state <<");

    cc_printf("\n");
}

void ccdigest_test_factory(struct cctest_info *ti, const struct ccdigest_info *di, const char *name, struct ccdigest_test_vector_info *vi)
{
    ti->custom = (const void *)di;
    ti->custom1 = (const void *)vi;
    cc_printf("%p\n", di);
    cc_printf("%p\n", vi);
    cc_printf("%p\n", name);
    cc_printf("%zx\n", vi->nvectors);
    ti->size = ccdigest_ctx_size(di->state_size, di->block_size) + sizeof(struct _ccdigest_test_ctx) + di->output_size;
    ti->init = &ccdigest_test_init;
    ti->run = &ccdigest_test_run;
    ti->name = name;
}

