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

#include <corecrypto/cc_debug.h>
#include <corecrypto/cc_runtime_config.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccmode_factory.h>
#include <corecrypto/ccmode_impl.h>

#pragma mark - ECB mode

const struct ccmode_ecb *ccaes_ecb_encrypt_mode(void)
{

#if CCAES_INTEL_ASM
    if (CC_HAS_AESNI()) {
#if CORECRYPTO_DEBUG
        cc_printf("corecrypto(aes): using AES-NI for ECB encrypt\n");
#endif
        return &ccaes_intel_ecb_encrypt_aesni_mode;
    } else {
        return &ccaes_intel_ecb_encrypt_opt_mode;
    }
#endif

    return &ccaes_ltc_ecb_encrypt_mode;
};

const struct ccmode_ecb *ccaes_ecb_decrypt_mode(void)
{

#if CCAES_INTEL_ASM
    if (CC_HAS_AESNI()) {
#if CORECRYPTO_DEBUG
        cc_printf("corecrypto(aes): using AES-NI for ECB decrypt\n");
#endif
        return &ccaes_intel_ecb_decrypt_aesni_mode;
    } else {
        return &ccaes_intel_ecb_decrypt_opt_mode;
    }
#endif

    return &ccaes_ltc_ecb_decrypt_mode;
};

#pragma mark - CBC mode

const struct ccmode_cbc *ccaes_cbc_encrypt_mode(void)
{

#if CCAES_INTEL_ASM
    if (CC_HAS_AESNI()) {
#if CORECRYPTO_DEBUG
        cc_printf("corecrypto(aes): using AES-NI for CBC encrypt\n");
#endif
        return &ccaes_intel_cbc_encrypt_aesni_mode;
    } else {
        return &ccaes_intel_cbc_encrypt_opt_mode;
    }
#endif

    return &ccaes_gladman_cbc_encrypt_mode;
};

const struct ccmode_cbc *ccaes_cbc_decrypt_mode(void)
{

#if CCAES_INTEL_ASM
    if (CC_HAS_AESNI()) {
#if CORECRYPTO_DEBUG
        cc_printf("corecrypto(aes): using AES-NI for CBC decrypt\n");
#endif
        return &ccaes_intel_cbc_decrypt_aesni_mode;
    } else {
        return &ccaes_intel_cbc_decrypt_opt_mode;
    }
#endif

    return &ccaes_gladman_cbc_decrypt_mode;
};

#pragma mark - XTS mode

/* If the Intel accelerated modes are available, use them instead */
#if !CCAES_INTEL_ASM

/* Use generic constructors for an unaccelerated build */
CCMODE_XTS_FACTORY(aes, encrypt);
CCMODE_XTS_FACTORY(aes, decrypt);

/* I wonder if libcorecrypto_noasm.dylib uses the intel opt mode or not. I'll have to check. */

#else

const struct ccmode_xts *ccaes_xts_decrypt_mode(void)
{
    if (CC_HAS_AESNI()) {
#if CORECRYPTO_DEBUG
        cc_printf("corecrypto(aes): using the AES-NI mode for XTS decryption\n");
#endif
        return &ccaes_intel_xts_decrypt_aesni_mode;
    } else {
#if CORECRYPTO_DEBUG
        cc_printf("corecrypto(aes): using the optimised mode for XTS decryption\n");
#endif
        return &ccaes_intel_xts_decrypt_opt_mode;
    }
};

const struct ccmode_xts *ccaes_xts_encrypt_mode(void)
{
    if (CC_HAS_AESNI()) {
#if CORECRYPTO_DEBUG
        cc_printf("corecrypto(aes): using the AES-NI mode for XTS decryption\n");
#endif
        return &ccaes_intel_xts_encrypt_aesni_mode;
    } else {
#if CORECRYPTO_DEBUG
        cc_printf("corecrypto(aes): using the optimised mode for XTS decryption\n");
#endif
        return &ccaes_intel_xts_encrypt_opt_mode;
    }
};

#endif

#pragma mark - Other constructed modes.

CCMODE_CFB_FACTORY(aes, cfb, encrypt)
CCMODE_CFB_FACTORY(aes, cfb, decrypt)
CCMODE_CFB_FACTORY(aes, cfb8, decrypt);
CCMODE_CFB_FACTORY(aes, cfb8, encrypt);

CCMODE_CTR_FACTORY(aes);

CCMODE_OFB_FACTORY(aes);
