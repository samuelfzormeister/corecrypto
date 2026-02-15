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

#if CC_KERNEL
#define CCTEST_LINK_NEXT_ALLOC(link) link->next = (struct _cctest_test_link *)IOMalloc(sizeof(struct _cctest_test_link))
#define CCTEST_LINK_FREE(link) IOFree(link, sizeof(struct _cctest_test_link))
#else
#define CCTEST_LINK_NEXT_ALLOC(link) link->next = (struct _cctest_test_link *)malloc(sizeof(struct _cctest_test_link))
#define CCTEST_LINK_FREE(link) free(link)
#endif

#define CCTEST_TRACE(x...) cc_printf("[CCTEST]: " x)

#if !defined(_MSC_VER)
static struct _cctest_test_link root;
#else
static struct _cctest_test_link *root;
#endif

extern struct _cctest_test_link *cctest_link_aes_ecb(struct _cctest_test_link *lnk);

/*
 * MEMORY CORRUPTION!!! MEMORY CORRUPTION!!! COME GET YOUR MEMORY CORRUPTION!!!
 *
 * TODO: DIAGNOSE THIS HEADACHE.
 */
int cctest_conduct_tests(uint32_t flags)
{
    int ret = 0;
#if !defined(_MSC_VER)
    struct _cctest_test_link *chain = &root;
#else
    struct _cctest_test_link *chain = root = malloc(sizeof(struct _cctest_test_link));
#endif
    CCTEST_TRACE("==== BEGIN TESTING SEQUENCE (flags: %08x) ===\n", flags);

    if (flags & CCTEST_ENABLE_MD2) {
        chain->ti = ccmd2_ti();
        CCTEST_TRACE("Enabling test %s\n", chain->ti->name);
        CCTEST_LINK_NEXT_ALLOC(chain);
        chain = chain->next;
    }

    if (flags & CCTEST_ENABLE_MD4) {
        chain->ti = ccmd4_ti();
        CCTEST_TRACE("Enabling test %s\n", chain->ti->name);
        CCTEST_LINK_NEXT_ALLOC(chain);
        chain = chain->next;
    }

    if (flags & CCTEST_ENABLE_AES) {
        chain = cctest_link_aes_ecb(chain);
    }

#if !defined(_MSC_VER)
    struct _cctest_test_link *lnk = &root;
#else
    struct _cctest_test_link *lnk = root;
#endif

    //
    // for some reason the nvectors field keeps getting replaced by 8cf0c094ee4514cc
    //
    // why the hell is memory being corrupted
    //
    while (lnk->next != NULL) {
        const struct cctest_info *ti = lnk->ti;
#if _MSC_VER
        cctest_ctx *ctx = malloc(ti->size);
#else
        cctest_ctx_decl(ti->size, ctx);
#endif
        const char *reason = "INIT FAIL";

        //CCTEST_TRACE("Begin test %s\n", ti->name);
        ret = cctest_init(ti, ctx);
        cc_require(ret == 0, fail);
        reason = "TEST FAIL";
        ret = cctest_run(ti, ctx);
        cc_require(ret == 0, fail);
        CCTEST_TRACE("%s - PASS\n", ti->name);
        //CCTEST_TRACE("Exit test %s\n", ti->name);
#if _MSC_VER
        free(ctx);
#else
        cctest_ctx_clear(ti->size, ctx);
#endif
        lnk = lnk->next;
        continue;

        fail:
        CCTEST_TRACE("!!! %s !!!\n", reason);
        CCTEST_TRACE("Exit test %s\n", ti->name);
        break;
    }
    
    CCTEST_TRACE("=== END TESTING SEQUENCE ===\n");

    return ret;
}
