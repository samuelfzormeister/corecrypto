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
#include <corecrypto/cc_runtime_config.h>
#include <corecrypto/ccdigest_test_internal.h>

#define CCTEST_TRACE(x...) cc_printf("[CCTEST]: " x)

static struct _cctest_test_link *cctest_link_aes_intel_ecb(struct _cctest_test_link *lnk)
{
#if CCAES_INTEL_ASM
    lnk->ti = ccaes_intel_ecb_encrypt_opt_ecbgfsbox_ti();
    CCTEST_TRACE("Enabling test %s\n", lnk->ti->name);
    CCTEST_LINK_NEXT_ALLOC(lnk);
    lnk = lnk->next;

    lnk->ti = ccaes_intel_ecb_encrypt_opt_ecbkeysbox_ti();
    CCTEST_TRACE("Enabling test %s\n", lnk->ti->name);
    CCTEST_LINK_NEXT_ALLOC(lnk);
    lnk = lnk->next;

    lnk->ti = ccaes_intel_ecb_encrypt_opt_ecbvarkey_ti();
    CCTEST_TRACE("Enabling test %s\n", lnk->ti->name);
    CCTEST_LINK_NEXT_ALLOC(lnk);
    lnk = lnk->next;

    lnk->ti = ccaes_intel_ecb_encrypt_opt_ecbvartxt_ti();
    CCTEST_TRACE("Enabling test %s\n", lnk->ti->name);
    CCTEST_LINK_NEXT_ALLOC(lnk);
    lnk = lnk->next;
    
    lnk->ti = ccaes_intel_ecb_decrypt_opt_ecbgfsbox_ti();
    CCTEST_TRACE("Enabling test %s\n", lnk->ti->name);
    CCTEST_LINK_NEXT_ALLOC(lnk);
    lnk = lnk->next;

    lnk->ti = ccaes_intel_ecb_decrypt_opt_ecbkeysbox_ti();
    CCTEST_TRACE("Enabling test %s\n", lnk->ti->name);
    CCTEST_LINK_NEXT_ALLOC(lnk);
    lnk = lnk->next;

    lnk->ti = ccaes_intel_ecb_decrypt_opt_ecbvarkey_ti();
    CCTEST_TRACE("Enabling test %s\n", lnk->ti->name);
    CCTEST_LINK_NEXT_ALLOC(lnk);
    lnk = lnk->next;

    lnk->ti = ccaes_intel_ecb_decrypt_opt_ecbvartxt_ti();
    CCTEST_TRACE("Enabling test %s\n", lnk->ti->name);
    CCTEST_LINK_NEXT_ALLOC(lnk);
    lnk = lnk->next;

    if (CC_HAS_AESNI()) {
        lnk->ti = ccaes_intel_ecb_encrypt_aesni_ecbgfsbox_ti();
        CCTEST_TRACE("Enabling test %s\n", lnk->ti->name);
        CCTEST_LINK_NEXT_ALLOC(lnk);
        lnk = lnk->next;

        lnk->ti = ccaes_intel_ecb_encrypt_aesni_ecbkeysbox_ti();
        CCTEST_TRACE("Enabling test %s\n", lnk->ti->name);
        CCTEST_LINK_NEXT_ALLOC(lnk);
        lnk = lnk->next;

        lnk->ti = ccaes_intel_ecb_encrypt_aesni_ecbvarkey_ti();
        CCTEST_TRACE("Enabling test %s\n", lnk->ti->name);
        CCTEST_LINK_NEXT_ALLOC(lnk);
        lnk = lnk->next;

        lnk->ti = ccaes_intel_ecb_encrypt_aesni_ecbvartxt_ti();
        CCTEST_TRACE("Enabling test %s\n", lnk->ti->name);
        CCTEST_LINK_NEXT_ALLOC(lnk);
        lnk = lnk->next;
        
        lnk->ti = ccaes_intel_ecb_decrypt_aesni_ecbgfsbox_ti();
        CCTEST_TRACE("Enabling test %s\n", lnk->ti->name);
        CCTEST_LINK_NEXT_ALLOC(lnk);
        lnk = lnk->next;

        lnk->ti = ccaes_intel_ecb_decrypt_aesni_ecbkeysbox_ti();
        CCTEST_TRACE("Enabling test %s\n", lnk->ti->name);
        CCTEST_LINK_NEXT_ALLOC(lnk);
        lnk = lnk->next;

        lnk->ti = ccaes_intel_ecb_decrypt_aesni_ecbvarkey_ti();
        CCTEST_TRACE("Enabling test %s\n", lnk->ti->name);
        CCTEST_LINK_NEXT_ALLOC(lnk);
        lnk = lnk->next;

        lnk->ti = ccaes_intel_ecb_decrypt_aesni_ecbvartxt_ti();
        CCTEST_TRACE("Enabling test %s\n", lnk->ti->name);
        CCTEST_LINK_NEXT_ALLOC(lnk);
        lnk = lnk->next;
    }
#endif

    return lnk;
}

static struct _cctest_test_link *cctest_link_aes_ltc_ecb(struct _cctest_test_link *lnk)
{
    lnk->ti = ccaes_ltc_ecb_encrypt_ecbgfsbox_ti();
    CCTEST_TRACE("Enabling test %s\n", lnk->ti->name);
    CCTEST_LINK_NEXT_ALLOC(lnk);
    lnk = lnk->next;

    lnk->ti = ccaes_ltc_ecb_encrypt_ecbkeysbox_ti();
    CCTEST_TRACE("Enabling test %s\n", lnk->ti->name);
    CCTEST_LINK_NEXT_ALLOC(lnk);
    lnk = lnk->next;

    lnk->ti = ccaes_ltc_ecb_encrypt_ecbvarkey_ti();
    CCTEST_TRACE("Enabling test %s\n", lnk->ti->name);
    CCTEST_LINK_NEXT_ALLOC(lnk);
    lnk = lnk->next;

    lnk->ti = ccaes_ltc_ecb_encrypt_ecbvartxt_ti();
    CCTEST_TRACE("Enabling test %s\n", lnk->ti->name);
    CCTEST_LINK_NEXT_ALLOC(lnk);
    lnk = lnk->next;
    
    lnk->ti = ccaes_ltc_ecb_decrypt_ecbgfsbox_ti();
    CCTEST_TRACE("Enabling test %s\n", lnk->ti->name);
    CCTEST_LINK_NEXT_ALLOC(lnk);
    lnk = lnk->next;

    lnk->ti = ccaes_ltc_ecb_decrypt_ecbkeysbox_ti();
    CCTEST_TRACE("Enabling test %s\n", lnk->ti->name);
    CCTEST_LINK_NEXT_ALLOC(lnk);
    lnk = lnk->next;

    lnk->ti = ccaes_ltc_ecb_decrypt_ecbvarkey_ti();
    CCTEST_TRACE("Enabling test %s\n", lnk->ti->name);
    CCTEST_LINK_NEXT_ALLOC(lnk);
    lnk = lnk->next;

    lnk->ti = ccaes_ltc_ecb_decrypt_ecbvartxt_ti();
    CCTEST_TRACE("Enabling test %s\n", lnk->ti->name);
    CCTEST_LINK_NEXT_ALLOC(lnk);
    lnk = lnk->next;

    return lnk;
}

struct _cctest_test_link *cctest_link_aes_ecb(struct _cctest_test_link *lnk)
{
    lnk = cctest_link_aes_ltc_ecb(lnk);
    lnk = cctest_link_aes_intel_ecb(lnk);

    return lnk;
}
