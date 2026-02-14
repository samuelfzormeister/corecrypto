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

#include "corecrypto/cctest_internal.h"
#include <corecrypto/cc.h>
#include <corecrypto/cc_error.h>
#include <corecrypto/cc_memory.h>
#include <corecrypto/ccmode_test_internal.h>

int ccmode_ecb_test_init(const struct cctest_info *info, cctest_ctx *ctx)
{
    struct _ccmode_test_ctx *tctx = (struct _ccmode_test_ctx *)ctx;
    const struct ccmode_ecb *mode = (const struct ccmode_ecb *)info->custom;

    tctx->mode = info->custom;
    tctx->vi = (const struct ccmode_test_vector_info *)info->custom1;
    tctx->ctx_size = mode->size;
    tctx->ti = info;

    //
    // DO NOT INITIALISE TEST ECB CTX HERE!!!
    //

    return 0;
}

int ccmode_ecb_encrypt_test_run(cctest_ctx *ctx)
{
    struct _ccmode_test_ctx *tctx = (struct _ccmode_test_ctx *)ctx;
    const struct ccmode_ecb *mode = (const struct ccmode_ecb *)tctx->mode;
    const struct ccmode_test_vector_info *vi = tctx->vi;
    void *scratch = CCMODE_TEST_CTX_SCRATCH_SPACE(tctx);

    ccecb_ctx_decl(mode->size, ecb);

    for (int i = 0; i < vi->nvectors; i++) {
        struct ccmode_test_vector vec = vi->vectors[i];
        uint32_t blocks = vec.text_length / ccecb_block_size(mode);
        ccecb_one_shot(mode, vec.key_length, vec.key, blocks, vec.plaintext, scratch);
        if (cc_cmp_safe(vec.text_length, vec.ciphertext, scratch) == 0) {
            cctest_trace_pass(CCTEST_SUBSYSTEM_MODE, tctx->ti->name, i+1);
            continue;
        } else {
            cctest_trace_fail(CCTEST_SUBSYSTEM_MODE, tctx->ti->name, i+1);
            return CCPOST_KAT_FAILURE;
        }
    }

    return 0;
}

int ccmode_ecb_decrypt_test_run(cctest_ctx *ctx)
{
    struct _ccmode_test_ctx *tctx = (struct _ccmode_test_ctx *)ctx;
    const struct ccmode_ecb *mode = (const struct ccmode_ecb *)tctx->mode;
    const struct ccmode_test_vector_info *vi = tctx->vi;
    void *scratch = CCMODE_TEST_CTX_SCRATCH_SPACE(tctx);

    ccecb_ctx_decl(mode->size, ecb);

    for (int i = 0; i < vi->nvectors; i++) {
        struct ccmode_test_vector vec = vi->vectors[i];
        uint32_t blocks = vec.text_length / ccecb_block_size(mode);
        ccecb_one_shot(mode, vec.key_length, vec.key, blocks, vec.ciphertext, scratch);
        if (cc_cmp_safe(vec.text_length, vec.plaintext, scratch) == 0) {
            cc_clear(CCMODE_TEST_CTX_SCRATCH_SIZE(mode), scratch);
            cctest_trace_pass(CCTEST_SUBSYSTEM_MODE, tctx->ti->name, i+1);
            continue;
        } else {
            cctest_trace_fail(CCTEST_SUBSYSTEM_MODE, tctx->ti->name, i+1);
            return CCPOST_KAT_FAILURE;
        }
    }

    return 0;
}

void ccmode_ecb_encrypt_test_factory(struct cctest_info *ti, const struct ccmode_ecb *mode, const char *name, struct ccmode_test_vector_info *vi)
{
    ti->name = name;
    ti->custom = mode;
    ti->custom1 = vi;
    ti->size = mode->size + CCMODE_TEST_CTX_SCRATCH_SIZE(mode);
    ti->init = ccmode_ecb_test_init;
    ti->run = ccmode_ecb_encrypt_test_run;
}

void ccmode_ecb_decrypt_test_factory(struct cctest_info *ti, const struct ccmode_ecb *mode, const char *name, struct ccmode_test_vector_info *vi)
{
    ti->name = name;
    ti->custom = mode;
    ti->custom1 = vi;
    ti->size = mode->size + CCMODE_TEST_CTX_SCRATCH_SIZE(mode);
    ti->init = ccmode_ecb_test_init;
    ti->run = ccmode_ecb_decrypt_test_run;
}