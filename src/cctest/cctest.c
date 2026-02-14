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

#if CC_KERNEL
#define CCTEST_LINK_NEXT_ALLOC(link) link->next = (struct _cctest_test_link *)IOMalloc(sizeof(struct _cctest_test_link))
#define CCTEST_LINK_FREE(link) IOFree(link, sizeof(struct _cctest_test_link))
#else
#define CCTEST_LINK_NEXT_ALLOC(link) link->next = (struct _cctest_test_link *)malloc(sizeof(struct _cctest_test_link))
#define CCTEST_LINK_FREE(link) free(link)
#endif

#define CCTEST_TRACE(x...) cc_printf("[CCTEST]: " x)

//
// We build a "linked list" (I say that loosely, given there's no pointer to the last field)
// consisting of test info structures to sequentially run tests.
//
// There's probably not the best time between checking if a certain test's bit
// is enabled or not, but I don't think the impact would be too severe for quick
// testing on the fly.
//
struct _cctest_test_link {
    struct _cctest_test_link *next;
    const struct cctest_info *ti;
};

struct _cctest_test_link root;

static struct _cctest_test_link *cctest_add_aes_to_chain(struct _cctest_test_link *lnk)
{
    lnk->ti = ccaes_ltc_ecb_encrypt_ecbgfsbox_ti();
    //CCTEST_TRACE("Enabling test %s\n", lnk->ti->name);
    CCTEST_LINK_NEXT_ALLOC(lnk);
    lnk = lnk->next;

    lnk->ti = ccaes_ltc_ecb_encrypt_ecbkeysbox_ti();
    //CCTEST_TRACE("Enabling test %s\n", lnk->ti->name);
    CCTEST_LINK_NEXT_ALLOC(lnk);
    lnk = lnk->next;

    lnk->ti = ccaes_ltc_ecb_encrypt_ecbvarkey_ti();
    //CCTEST_TRACE("Enabling test %s\n", lnk->ti->name);
    CCTEST_LINK_NEXT_ALLOC(lnk);
    lnk = lnk->next;

    lnk->ti = ccaes_ltc_ecb_encrypt_ecbvartxt_ti();
    //CCTEST_TRACE("Enabling test %s\n", lnk->ti->name);
    CCTEST_LINK_NEXT_ALLOC(lnk);
    lnk = lnk->next;

    return lnk;
}

/*
 * MEMORY CORRUPTION!!! MEMORY CORRUPTION!!! COME GET YOUR MEMORY CORRUPTION!!!
 *
 * TODO: DIAGNOSE THIS HEADACHE.
 */
int cctest_conduct_tests(uint32_t flags)
{
    int ret = 0;
    struct _cctest_test_link *chain = &root;
    cc_printf("We have been asked to perform tests!\n");

    if (flags & CCTEST_ENABLE_MD2) {
        chain->ti = ccmd2_ti();
        CCTEST_TRACE("Enabling test %s\n", chain->ti->name);
        cc_printf("%zx\n", CCDIGEST_TEST_VI(chain->ti->custom1)->nvectors);
        CCTEST_LINK_NEXT_ALLOC(chain);
        chain = chain->next;
    }

    if (flags & CCTEST_ENABLE_MD4) {
        chain->ti = ccmd4_ti();
        CCTEST_TRACE("Enabling test %s\n", chain->ti->name);
        cc_printf("%zx\n", CCDIGEST_TEST_VI(chain->ti->custom1)->nvectors);
        CCTEST_LINK_NEXT_ALLOC(chain);
        chain = chain->next;
        cc_printf("%zx\n", CCDIGEST_TEST_VI(chain->ti->custom1)->nvectors);
    }

    if (flags & CCTEST_ENABLE_AES) {
        //chain = cctest_add_aes_to_chain(chain);
    }

    struct _cctest_test_link *lnk = &root;
    cc_printf("%p\n", lnk);
    cc_printf("%zx\n", CCDIGEST_TEST_VI(lnk->ti->custom1)->nvectors);

    //
    // for some reason the nvectors field keeps getting replaced by 8cf0c094ee4514cc
    //
    // why the hell is memory being corrupted
    //
    while (lnk->next != NULL) {
        const struct cctest_info *ti = lnk->ti;
        cc_printf("%zx\n", CCDIGEST_TEST_VI(lnk->ti->custom1)->nvectors);
        cc_printf("%zx\n", CCDIGEST_TEST_VI(lnk->ti->custom1)->nvectors);
        cc_printf("%zx\n", CCDIGEST_TEST_VI(lnk->ti->custom1)->nvectors);
        cctest_ctx_decl(ti->size, ctx);
        //cc_printf("%zx\n", CCDIGEST_TEST_VI(chain->ti->custom1)->nvectors);
        const char *reason = "INIT FAIL";
        //cc_printf("%zx\n", CCDIGEST_TEST_VI(chain->ti->custom1)->nvectors);
        //cctest_ctx_clear(ti->size, ctx);
        //cc_printf("%zx\n", CCDIGEST_TEST_VI(chain->ti->custom1)->nvectors);

        CCTEST_TRACE("Begin test %s (size: %zd)\n", ti->name, ti->size);
        ret = cctest_init(ti, ctx);
        cc_require(ret == 0, fail);
        reason = "TEST FAIL";
        ret = cctest_run(ti, ctx);
        cc_require(ret == 0, fail);
        cc_printf("[CCTEST]: --- %s : PASS ---\n", ti->name);
        CCTEST_TRACE("Exit test %s\n", ti->name);

        lnk = lnk->next;
        continue;

        fail:
        CCTEST_TRACE("!!! %s !!!\n", reason);
        CCTEST_TRACE("Exit test %s\n", ti->name);
        break;
    }

    return ret;
}
