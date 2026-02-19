/*
 * Copyright (C) 2025-2026 The PureDarwin Project, All rights reserved.
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
#include <corecrypto/cc_macros.h>
#include <corecrypto/cctest_internal.h>
#include <corecrypto/cctest_priv.h>
#include <corecrypto/ccdigest_test_internal.h>
#include <corecrypto/cc_memory.h>

#define CCTEST_TRACE(x...) cc_printf("[CCTEST]: " x)

static struct _cctest_test_link *root;

extern struct _cctest_test_link *cctest_link_aes_ecb(struct _cctest_test_link *lnk);
extern struct _cctest_test_link *cctest_link_aes_cbc(struct _cctest_test_link *lnk);
extern struct _cctest_test_link *cctest_link_aes_ofb(struct _cctest_test_link *lnk);
extern struct _cctest_test_link *cctest_link_aes_cfb(struct _cctest_test_link *lnk);
extern struct _cctest_test_link *cctest_link_aes_cfb8(struct _cctest_test_link *lnk);

/*
 * MEMORY CORRUPTION!!! MEMORY CORRUPTION!!! COME GET YOUR MEMORY CORRUPTION!!!
 *
 * TODO: DIAGNOSE THIS HEADACHE.
 */
int cctest_conduct_tests(uint32_t flags)
{
    int ret = 0;
    struct _cctest_test_link *chain = root = malloc(sizeof(struct _cctest_test_link));

    CCTEST_TRACE("==== BEGIN TESTING SEQUENCE (flags: %08x) ===\n", flags);

    if (flags & CCTEST_ENABLE_MD2) {
        CCTEST_ADD_TEST(chain, ccmd2_ti());
    }

    if (flags & CCTEST_ENABLE_MD4) {
        CCTEST_ADD_TEST(chain, ccmd4_ti());
    }
    
    if (flags & CCTEST_ENABLE_MD5) {
        CCTEST_ADD_TEST(chain, ccmd5_ltc_ti());
    }
    
    if (flags & CCTEST_ENABLE_RIPEMD) {
        CCTEST_ADD_TEST(chain, ccrmd160_ti());
    }

    if (flags & CCTEST_ENABLE_SHA1) {
        CCTEST_ADD_TEST(chain, ccsha1_ltc_longmsg_ti());
        CCTEST_ADD_TEST(chain, ccsha1_ltc_shortmsg_ti());
    }

    if (flags & CCTEST_ENABLE_SHA2) {
        CCTEST_ADD_TEST(chain, ccsha224_ltc_longmsg_ti());
        CCTEST_ADD_TEST(chain, ccsha224_ltc_shortmsg_ti());
        CCTEST_ADD_TEST(chain, ccsha256_ltc_longmsg_ti());
        CCTEST_ADD_TEST(chain, ccsha256_ltc_shortmsg_ti());
        CCTEST_ADD_TEST(chain, ccsha384_ltc_longmsg_ti());
        CCTEST_ADD_TEST(chain, ccsha384_ltc_shortmsg_ti());
        CCTEST_ADD_TEST(chain, ccsha512_ltc_longmsg_ti());
        CCTEST_ADD_TEST(chain, ccsha512_ltc_shortmsg_ti());
        CCTEST_ADD_TEST(chain, ccsha512_224_ltc_longmsg_ti());
        CCTEST_ADD_TEST(chain, ccsha512_224_ltc_shortmsg_ti());
        CCTEST_ADD_TEST(chain, ccsha512_256_ltc_longmsg_ti());
        CCTEST_ADD_TEST(chain, ccsha512_256_ltc_shortmsg_ti());
    }

    if (flags & CCTEST_ENABLE_AES) {
        chain = cctest_link_aes_ecb(chain);
        chain = cctest_link_aes_cbc(chain);
        chain = cctest_link_aes_ofb(chain);
        chain = cctest_link_aes_cfb(chain);
        chain = cctest_link_aes_cfb8(chain);
    }

    struct _cctest_test_link *lnk = root;

    while (lnk->next != NULL) {
        const struct cctest_info *ti = lnk->ti;
        cctest_ctx *ctx = cctest_malloc(ti->size);
        const char *reason = "INIT FAIL";

        //CCTEST_TRACE("Begin test %s\n", ti->name);
        ret = cctest_init(ti, ctx);
        cc_require(ret == 0, fail);
        reason = "TEST FAIL";
        ret = cctest_run(ti, ctx);
        cc_require(ret == 0, fail);
        CCTEST_TRACE("%s - PASS\n", ti->name);
        //CCTEST_TRACE("Exit test %s\n", ti->name);
        cctest_free(ctx, ti->size);
        lnk = lnk->next;
        continue;

        fail:
        CCTEST_TRACE("!!! %s !!!\n", reason);
        CCTEST_TRACE("Exit test %s\n", ti->name);
        break;
    }

    lnk = root;
    while (lnk->next != NULL) {
        struct _cctest_test_link *last = lnk;
        lnk = last->next;
        cctest_free(last, sizeof(struct _cctest_test_link));
    }
    
    CCTEST_TRACE("=== END TESTING SEQUENCE ===\n");

    return ret;
}
