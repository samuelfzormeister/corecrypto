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
#include <corecrypto/cctest_priv.h>

#if CORECRYPTO_TEST

void ccdigest_test_factory(struct cctest_info *ti, const struct ccdigest_info *di, const char *name, struct ccdigest_test_vector_info *vi)
{
    ti->custom = (const void *)di;
    ti->custom1 = (const void *)vi;
    ti->size = ccdigest_ctx_size(di->state_size, di->block_size) + sizeof(struct _ccdigest_test_ctx) + di->output_size;
    ti->init = &ccdigest_test_init;
    ti->run = &ccdigest_test_run;
}

int ccdigest_test_init(const struct cctest_info *info, cctest_ctx *ctx)
{
    struct _ccdigest_test_ctx *dt = CCDIGEST_TEST_CTX(ctx);

    dt->vi = CCDIGEST_TEST_VI(info->custom1);
    dt->di = (const struct ccdigest_info *)info->custom;
    dt->ctx_size = ccdigest_ctx_size(dt->di->state_size, dt->di->block_size);

    return 0;
}

int ccdigest_test_run(cctest_ctx *ctx)
{
    int res = 0;
    const struct ccdigest_info *di = CCDIGEST_TEST_CTX(ctx)->di;
    const struct ccdigest_test_vector_info *vi = CCDIGEST_TEST_CTX(ctx)->vi;
    struct ccdigest_ctx *dc = (struct ccdigest_ctx *)&CCDIGEST_TEST_CTX(ctx)->u;
    void *scratch = CCDIGEST_TEST_CTX_SCRATCH_SPACE(CCDIGEST_TEST_CTX(ctx));

    for (size_t i = 0; i < vi->nvectors; i++) {
        struct ccdigest_test_vector vec = vi->vectors[i];

        ccdigest(di, vec.msg_len, vec.message, scratch);

        res |= (cc_memcmp(vec.expected_digest, scratch, di->output_size) == 0) &&
                    !(vec.attrs & CCTEST_ATTR_EXPECTEDFAIL);

        ccdigest_ctx_clear(di->state_size, di->block_size, dc);
        cc_clear(di->output_size, scratch);
    }

    return res;
}

#endif
