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

static struct _cctest_test_link *cctest_link_aes_intel_cfb8(struct _cctest_test_link *lnk)
{
#if CCAES_INTEL_ASM
    CCTEST_ADD_TEST(lnk, ccaes_intel_cfb8_encrypt_opt_gfsbox_ti());
    CCTEST_ADD_TEST(lnk, ccaes_intel_cfb8_encrypt_opt_keysbox_ti());
    CCTEST_ADD_TEST(lnk, ccaes_intel_cfb8_encrypt_opt_varkey_ti());
    CCTEST_ADD_TEST(lnk, ccaes_intel_cfb8_encrypt_opt_vartxt_ti());
    CCTEST_ADD_TEST(lnk, ccaes_intel_cfb8_encrypt_opt_mmt_ti());
    CCTEST_ADD_TEST(lnk, ccaes_intel_cfb8_decrypt_opt_gfsbox_ti());
    CCTEST_ADD_TEST(lnk, ccaes_intel_cfb8_decrypt_opt_keysbox_ti());
    CCTEST_ADD_TEST(lnk, ccaes_intel_cfb8_decrypt_opt_keysbox_ti());
    CCTEST_ADD_TEST(lnk, ccaes_intel_cfb8_decrypt_opt_keysbox_ti());
    CCTEST_ADD_TEST(lnk, ccaes_intel_cfb8_decrypt_opt_mmt_ti());

    if (CC_HAS_AESNI()) {
        CCTEST_ADD_TEST(lnk, ccaes_intel_cfb8_encrypt_aesni_gfsbox_ti());
        CCTEST_ADD_TEST(lnk, ccaes_intel_cfb8_encrypt_aesni_keysbox_ti());
        CCTEST_ADD_TEST(lnk, ccaes_intel_cfb8_encrypt_aesni_varkey_ti());
        CCTEST_ADD_TEST(lnk, ccaes_intel_cfb8_encrypt_aesni_vartxt_ti());
        CCTEST_ADD_TEST(lnk, ccaes_intel_cfb8_encrypt_aesni_mmt_ti());
        CCTEST_ADD_TEST(lnk, ccaes_intel_cfb8_decrypt_aesni_gfsbox_ti());
        CCTEST_ADD_TEST(lnk, ccaes_intel_cfb8_decrypt_aesni_keysbox_ti());
        CCTEST_ADD_TEST(lnk, ccaes_intel_cfb8_decrypt_aesni_keysbox_ti());
        CCTEST_ADD_TEST(lnk, ccaes_intel_cfb8_decrypt_aesni_keysbox_ti());
        CCTEST_ADD_TEST(lnk, ccaes_intel_cfb8_decrypt_aesni_mmt_ti());
    }
#endif

    return lnk;
}

static struct _cctest_test_link *cctest_link_aes_ltc_cfb8(struct _cctest_test_link *lnk)
{
    CCTEST_ADD_TEST(lnk, ccaes_ltc_cfb8_encrypt_gfsbox_ti());
    CCTEST_ADD_TEST(lnk, ccaes_ltc_cfb8_encrypt_keysbox_ti());
    CCTEST_ADD_TEST(lnk, ccaes_ltc_cfb8_encrypt_varkey_ti());
    CCTEST_ADD_TEST(lnk, ccaes_ltc_cfb8_encrypt_vartxt_ti());
    CCTEST_ADD_TEST(lnk, ccaes_ltc_cfb8_encrypt_mmt_ti());
    CCTEST_ADD_TEST(lnk, ccaes_ltc_cfb8_decrypt_gfsbox_ti());
    CCTEST_ADD_TEST(lnk, ccaes_ltc_cfb8_decrypt_keysbox_ti());
    CCTEST_ADD_TEST(lnk, ccaes_ltc_cfb8_decrypt_varkey_ti());
    CCTEST_ADD_TEST(lnk, ccaes_ltc_cfb8_decrypt_vartxt_ti());
    CCTEST_ADD_TEST(lnk, ccaes_ltc_cfb8_decrypt_mmt_ti());
    return lnk;
}

struct _cctest_test_link *cctest_link_aes_cfb8(struct _cctest_test_link *lnk)
{
    lnk = cctest_link_aes_ltc_cfb8(lnk);
    lnk = cctest_link_aes_intel_cfb8(lnk);

    return lnk;
}
