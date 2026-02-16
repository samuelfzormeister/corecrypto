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

#include "corecrypto/ccmode.h"
#include <corecrypto/cc.h>
#include <corecrypto/cc_debug.h>
#include <corecrypto/cc_error.h>
#include <corecrypto/cc_macros.h>
#include <corecrypto/cc_memory.h>
#include <corecrypto/ccmode_test_internal.h>
#include <corecrypto/cctest_internal.h>

void ccmode_cbc_test_dump_state(cctest_ctx *tx)
{
    struct _ccmode_test_ctx *ctx = CCMODE_TEST_CTX(tx);
    uint8_t *state = (uint8_t *)CCMODE_TEST_CTX_KEY(cccbc_ctx, ctx);

    cc_printf("[CCTEST][CIPHER][%s]: CURRENT STATE:\n", ctx->ti->name);

    for (cc_size i = 0; i < ctx->ctx_size; i++) {
        if ((i % 8) == 0) {
            if (i > 0) {
                cc_printf("\n");
            }
        }
        cc_printf("%02x ", *state);
        state++;
    }
    
    cc_printf("\n");
    
    cc_printf("[CCTEST][CIPHER][%s]: SCRATCH MEMORY:\n", ctx->ti->name);
    
    state = (uint8_t *)CCMODE_TEST_CTX_SCRATCH_SPACE(ctx);
    
    for (cc_size i = 0; i < CCMODE_TEST_CTX_SCRATCH_SIZE(((struct ccmode_cbc *)ctx->mode)); i++) {
        if ((i % 8) == 0) {
            if (i > 0) {
                cc_printf("\n");
            }
        }
        cc_printf("%02x ", *state);
        state++;
    }
    
    cc_printf("\n");
}

int ccmode_cbc_test_init(const struct cctest_info *info, cctest_ctx *ctx)
{
    struct _ccmode_test_ctx *tctx = (struct _ccmode_test_ctx *)ctx;
    const struct ccmode_cbc *mode = (const struct ccmode_cbc *)info->custom;

    tctx->mode = info->custom;
    tctx->vi = (const struct ccmode_test_vector_info *)info->custom1;
    tctx->ctx_size = mode->size;
    tctx->ti = info;

    //
    // DO NOT INITIALISE TEST cbc CTX HERE!!!
    //

    return 0;
}

int ccmode_cbc_encrypt_test_run(cctest_ctx *ctx)
{
    struct _ccmode_test_ctx *tctx = (struct _ccmode_test_ctx *)ctx;
    const struct ccmode_cbc *mode = (const struct ccmode_cbc *)tctx->mode;
    const struct ccmode_test_vector_info *vi = tctx->vi;
    void *scratch = CCMODE_TEST_CTX_SCRATCH_SPACE(tctx);
    cccbc_ctx *cx = CCMODE_TEST_CTX_KEY(cccbc_ctx, tctx);

    for (int i = 0; i < vi->nvectors; i++) {
        struct ccmode_test_vector vec = vi->vectors[i];
        cc_size blocks = vec.text_length / cccbc_block_size(mode);
        const char *reason = "";
        cccbc_iv *iv = CCMODE_TEST_CTX_IV_SPACE(cccbc_iv, tctx);
        
        int ret = cccbc_init(mode, cx, vec.key_length, vec.key);
        cc_require_action(ret == 0, testfail, reason = "INIT FAIL");
        ret = cccbc_update(mode, cx, iv, blocks, vec.plaintext, scratch);
        cc_require_action(ret == 0, testfail, reason = "UPDATE FAIL");
        if (cc_cmp_safe(vec.text_length, vec.ciphertext, scratch) == 0) {
            cctest_trace_pass(CCTEST_SUBSYSTEM_MODE, tctx->ti->name, i+1);
            cccbc_ctx_clear(mode->size, cx);
            continue;
        } else {
            cctest_trace_fail(CCTEST_SUBSYSTEM_MODE, tctx->ti->name, i+1);
            return CCPOST_KAT_FAILURE;
        }
        
    testfail:
        cctest_trace_general(CCTEST_SUBSYSTEM_MODE, tctx->ti->name, reason);
        return CCPOST_LIBRARY_ERROR;
    }

    return 0;
}

int ccmode_cbc_decrypt_test_run(cctest_ctx *ctx)
{
    struct _ccmode_test_ctx *tctx = (struct _ccmode_test_ctx *)ctx;
    const struct ccmode_cbc *mode = (const struct ccmode_cbc *)tctx->mode;
    const struct ccmode_test_vector_info *vi = tctx->vi;
    void *scratch = CCMODE_TEST_CTX_SCRATCH_SPACE(tctx);
    cccbc_ctx *cx = CCMODE_TEST_CTX_KEY(cccbc_ctx, tctx);

    for (int i = 0; i < vi->nvectors; i++) {
        struct ccmode_test_vector vec = vi->vectors[i];
        cc_size blocks = vec.text_length / cccbc_block_size(mode);
        const char *reason = "";
        cccbc_iv *iv = CCMODE_TEST_CTX_IV_SPACE(cccbc_iv, tctx);
        
        int ret = cccbc_init(mode, cx, vec.key_length, vec.key);
        cccbc_set_iv(mode, iv, vec.iv);
        cc_require_action(ret == 0, testfail, reason = "INIT FAIL");
        ret = cccbc_update(mode, cx, iv, blocks, vec.ciphertext, scratch);
        cc_require_action(ret == 0, testfail, reason = "UPDATE FAIL");
        if (cc_cmp_safe(vec.text_length, vec.plaintext, scratch) == 0) {
            cctest_trace_pass(CCTEST_SUBSYSTEM_MODE, tctx->ti->name, i+1);
            cccbc_set_iv(mode, iv, NULL);
            cccbc_ctx_clear(mode->size, cx);
            continue;
        } else {
            cctest_trace_fail(CCTEST_SUBSYSTEM_MODE, tctx->ti->name, i+1);
            cc_printf("[CCTEST][CIPHER][%s]: EXPECTED:\n", tctx->ti->name);
            
            uint8_t *state = (uint8_t *)vec.plaintext;
            
            for (cc_size i = 0; i < CCMODE_TEST_CTX_SCRATCH_SIZE(((struct ccmode_cbc *)tctx->mode)); i++) {
                if ((i % 8) == 0) {
                    if (i > 0) {
                        cc_printf("\n");
                    }
                }
                cc_printf("%02x ", *state);
                state++;
            }
            cc_printf("\n");
            
            cc_printf("[CCTEST][CIPHER][%s]: CIPHERTEXT:\n", tctx->ti->name);
            
            state = (uint8_t *)vec.ciphertext;
            
            for (cc_size i = 0; i < CCMODE_TEST_CTX_SCRATCH_SIZE(((struct ccmode_cbc *)tctx->mode)); i++) {
                if ((i % 8) == 0) {
                    if (i > 0) {
                        cc_printf("\n");
                    }
                }
                cc_printf("%02x ", *state);
                state++;
            }
            cc_printf("\n");
            ccmode_cbc_test_dump_state(ctx);
            return CCPOST_KAT_FAILURE;
        }
        
    testfail:
        cctest_trace_general(CCTEST_SUBSYSTEM_MODE, tctx->ti->name, reason);
        return CCPOST_LIBRARY_ERROR;
    }


    return 0;
}

void ccmode_cbc_encrypt_test_factory(struct cctest_info *ti, const struct ccmode_cbc *mode, const char *name, struct ccmode_test_vector_info *vi)
{
    ti->name = name;
    ti->custom = mode;
    ti->custom1 = vi;
    ti->size = mode->size + CCMODE_TEST_CTX_SCRATCH_SIZE(mode);
    ti->init = ccmode_cbc_test_init;
    ti->run = ccmode_cbc_encrypt_test_run;
}

void ccmode_cbc_decrypt_test_factory(struct cctest_info *ti, const struct ccmode_cbc *mode, const char *name, struct ccmode_test_vector_info *vi)
{
    ti->name = name;
    ti->custom = mode;
    ti->custom1 = vi;
    ti->size = mode->size + CCMODE_TEST_CTX_SCRATCH_SIZE(mode);
    ti->init = ccmode_cbc_test_init;
    ti->run = ccmode_cbc_decrypt_test_run;
}
