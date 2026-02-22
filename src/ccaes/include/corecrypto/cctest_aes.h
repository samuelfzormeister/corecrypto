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

#ifndef _CORECRYPTO_CCTEST_AES_H_
#define _CORECRYPTO_CCTEST_AES_H_

#include <corecrypto/cctest_priv.h>

//
// This declares all available tests to the subsystem.
//
extern const struct cctest_info *ccaes_ltc_ecb_encrypt_gfsbox_ti(void);
extern const struct cctest_info *ccaes_ltc_ecb_encrypt_keysbox_ti(void);
extern const struct cctest_info *ccaes_ltc_ecb_encrypt_varkey_ti(void);
extern const struct cctest_info *ccaes_ltc_ecb_encrypt_vartxt_ti(void);

extern const struct cctest_info *ccaes_ltc_ecb_decrypt_gfsbox_ti(void);
extern const struct cctest_info *ccaes_ltc_ecb_decrypt_keysbox_ti(void);
extern const struct cctest_info *ccaes_ltc_ecb_decrypt_varkey_ti(void);
extern const struct cctest_info *ccaes_ltc_ecb_decrypt_vartxt_ti(void);

extern const struct cctest_info *ccaes_ltc_ecb_encrypt_mmt_ti(void);
extern const struct cctest_info *ccaes_ltc_ecb_decrypt_mmt_ti(void);

#if CCAES_INTEL_ASM
extern const struct cctest_info *ccaes_intel_ecb_encrypt_opt_gfsbox_ti(void);
extern const struct cctest_info *ccaes_intel_ecb_encrypt_opt_keysbox_ti(void);
extern const struct cctest_info *ccaes_intel_ecb_encrypt_opt_varkey_ti(void);
extern const struct cctest_info *ccaes_intel_ecb_encrypt_opt_vartxt_ti(void);

extern const struct cctest_info *ccaes_intel_ecb_decrypt_opt_gfsbox_ti(void);
extern const struct cctest_info *ccaes_intel_ecb_decrypt_opt_keysbox_ti(void);
extern const struct cctest_info *ccaes_intel_ecb_decrypt_opt_varkey_ti(void);
extern const struct cctest_info *ccaes_intel_ecb_decrypt_opt_vartxt_ti(void);

extern const struct cctest_info *ccaes_intel_ecb_encrypt_opt_mmt_ti(void);
extern const struct cctest_info *ccaes_intel_ecb_decrypt_opt_mmt_ti(void);

extern const struct cctest_info *ccaes_intel_ecb_encrypt_aesni_gfsbox_ti(void);
extern const struct cctest_info *ccaes_intel_ecb_encrypt_aesni_keysbox_ti(void);
extern const struct cctest_info *ccaes_intel_ecb_encrypt_aesni_varkey_ti(void);
extern const struct cctest_info *ccaes_intel_ecb_encrypt_aesni_vartxt_ti(void);

extern const struct cctest_info *ccaes_intel_ecb_decrypt_aesni_gfsbox_ti(void);
extern const struct cctest_info *ccaes_intel_ecb_decrypt_aesni_keysbox_ti(void);
extern const struct cctest_info *ccaes_intel_ecb_decrypt_aesni_varkey_ti(void);
extern const struct cctest_info *ccaes_intel_ecb_decrypt_aesni_vartxt_ti(void);

extern const struct cctest_info *ccaes_intel_ecb_encrypt_aesni_mmt_ti(void);
extern const struct cctest_info *ccaes_intel_ecb_decrypt_aesni_mmt_ti(void);
#endif

#pragma mark - CBC test suites

extern const struct cctest_info *ccaes_gladman_cbc_encrypt_gfsbox_ti(void);
extern const struct cctest_info *ccaes_gladman_cbc_encrypt_keysbox_ti(void);
extern const struct cctest_info *ccaes_gladman_cbc_encrypt_varkey_ti(void);
extern const struct cctest_info *ccaes_gladman_cbc_encrypt_vartxt_ti(void);

extern const struct cctest_info *ccaes_gladman_cbc_decrypt_gfsbox_ti(void);
extern const struct cctest_info *ccaes_gladman_cbc_decrypt_keysbox_ti(void);
extern const struct cctest_info *ccaes_gladman_cbc_decrypt_varkey_ti(void);
extern const struct cctest_info *ccaes_gladman_cbc_decrypt_vartxt_ti(void);

#if CCAES_INTEL_ASM
extern const struct cctest_info *ccaes_intel_cbc_encrypt_opt_gfsbox_ti(void);
extern const struct cctest_info *ccaes_intel_cbc_encrypt_opt_keysbox_ti(void);
extern const struct cctest_info *ccaes_intel_cbc_encrypt_opt_varkey_ti(void);
extern const struct cctest_info *ccaes_intel_cbc_encrypt_opt_vartxt_ti(void);

extern const struct cctest_info *ccaes_intel_cbc_decrypt_opt_gfsbox_ti(void);
extern const struct cctest_info *ccaes_intel_cbc_decrypt_opt_keysbox_ti(void);
extern const struct cctest_info *ccaes_intel_cbc_decrypt_opt_varkey_ti(void);
extern const struct cctest_info *ccaes_intel_cbc_decrypt_opt_vartxt_ti(void);

extern const struct cctest_info *ccaes_intel_cbc_encrypt_aesni_gfsbox_ti(void);
extern const struct cctest_info *ccaes_intel_cbc_encrypt_aesni_keysbox_ti(void);
extern const struct cctest_info *ccaes_intel_cbc_encrypt_aesni_varkey_ti(void);
extern const struct cctest_info *ccaes_intel_cbc_encrypt_aesni_vartxt_ti(void);

extern const struct cctest_info *ccaes_intel_cbc_decrypt_aesni_gfsbox_ti(void);
extern const struct cctest_info *ccaes_intel_cbc_decrypt_aesni_keysbox_ti(void);
extern const struct cctest_info *ccaes_intel_cbc_decrypt_aesni_varkey_ti(void);
extern const struct cctest_info *ccaes_intel_cbc_decrypt_aesni_vartxt_ti(void);
#endif

#pragma mark - OFB test suites.

extern const struct cctest_info *ccaes_ltc_ofb_encrypt_gfsbox_ti(void);
extern const struct cctest_info *ccaes_ltc_ofb_encrypt_keysbox_ti(void);
extern const struct cctest_info *ccaes_ltc_ofb_encrypt_varkey_ti(void);
extern const struct cctest_info *ccaes_ltc_ofb_encrypt_vartxt_ti(void);

extern const struct cctest_info *ccaes_ltc_ofb_decrypt_gfsbox_ti(void);
extern const struct cctest_info *ccaes_ltc_ofb_decrypt_keysbox_ti(void);
extern const struct cctest_info *ccaes_ltc_ofb_decrypt_varkey_ti(void);
extern const struct cctest_info *ccaes_ltc_ofb_decrypt_vartxt_ti(void);

extern const struct cctest_info *ccaes_ltc_ofb_encrypt_mmt_ti(void);
extern const struct cctest_info *ccaes_ltc_ofb_decrypt_mmt_ti(void);

#pragma mark - CFB test suites

extern const struct cctest_info *ccaes_ltc_cfb_encrypt_gfsbox_ti(void);
extern const struct cctest_info *ccaes_ltc_cfb_encrypt_keysbox_ti(void);
extern const struct cctest_info *ccaes_ltc_cfb_encrypt_varkey_ti(void);
extern const struct cctest_info *ccaes_ltc_cfb_encrypt_vartxt_ti(void);

extern const struct cctest_info *ccaes_ltc_cfb_decrypt_gfsbox_ti(void);
extern const struct cctest_info *ccaes_ltc_cfb_decrypt_keysbox_ti(void);
extern const struct cctest_info *ccaes_ltc_cfb_decrypt_varkey_ti(void);
extern const struct cctest_info *ccaes_ltc_cfb_decrypt_vartxt_ti(void);

extern const struct cctest_info *ccaes_ltc_cfb_encrypt_mmt_ti(void);
extern const struct cctest_info *ccaes_ltc_cfb_decrypt_mmt_ti(void);

#if CCAES_INTEL_ASM
extern const struct cctest_info *ccaes_intel_cfb_encrypt_opt_gfsbox_ti(void);
extern const struct cctest_info *ccaes_intel_cfb_encrypt_opt_keysbox_ti(void);
extern const struct cctest_info *ccaes_intel_cfb_encrypt_opt_varkey_ti(void);
extern const struct cctest_info *ccaes_intel_cfb_encrypt_opt_vartxt_ti(void);

extern const struct cctest_info *ccaes_intel_cfb_decrypt_opt_gfsbox_ti(void);
extern const struct cctest_info *ccaes_intel_cfb_decrypt_opt_keysbox_ti(void);
extern const struct cctest_info *ccaes_intel_cfb_decrypt_opt_varkey_ti(void);
extern const struct cctest_info *ccaes_intel_cfb_decrypt_opt_vartxt_ti(void);

extern const struct cctest_info *ccaes_intel_cfb_encrypt_aesni_gfsbox_ti(void);
extern const struct cctest_info *ccaes_intel_cfb_encrypt_aesni_keysbox_ti(void);
extern const struct cctest_info *ccaes_intel_cfb_encrypt_aesni_varkey_ti(void);
extern const struct cctest_info *ccaes_intel_cfb_encrypt_aesni_vartxt_ti(void);

extern const struct cctest_info *ccaes_intel_cfb_decrypt_aesni_gfsbox_ti(void);
extern const struct cctest_info *ccaes_intel_cfb_decrypt_aesni_keysbox_ti(void);
extern const struct cctest_info *ccaes_intel_cfb_decrypt_aesni_varkey_ti(void);
extern const struct cctest_info *ccaes_intel_cfb_decrypt_aesni_vartxt_ti(void);

extern const struct cctest_info *ccaes_intel_cfb_encrypt_opt_mmt_ti(void);
extern const struct cctest_info *ccaes_intel_cfb_decrypt_opt_mmt_ti(void);

extern const struct cctest_info *ccaes_intel_cfb_encrypt_aesni_mmt_ti(void);
extern const struct cctest_info *ccaes_intel_cfb_decrypt_aesni_mmt_ti(void);
#endif

#pragma mark - CFB8 test suites

extern const struct cctest_info *ccaes_ltc_cfb8_encrypt_gfsbox_ti(void);
extern const struct cctest_info *ccaes_ltc_cfb8_encrypt_keysbox_ti(void);
extern const struct cctest_info *ccaes_ltc_cfb8_encrypt_varkey_ti(void);
extern const struct cctest_info *ccaes_ltc_cfb8_encrypt_vartxt_ti(void);

extern const struct cctest_info *ccaes_ltc_cfb8_decrypt_gfsbox_ti(void);
extern const struct cctest_info *ccaes_ltc_cfb8_decrypt_keysbox_ti(void);
extern const struct cctest_info *ccaes_ltc_cfb8_decrypt_varkey_ti(void);
extern const struct cctest_info *ccaes_ltc_cfb8_decrypt_vartxt_ti(void);

extern const struct cctest_info *ccaes_ltc_cfb8_encrypt_mmt_ti(void);
extern const struct cctest_info *ccaes_ltc_cfb8_decrypt_mmt_ti(void);

#if CCAES_INTEL_ASM
extern const struct cctest_info *ccaes_intel_cfb8_encrypt_opt_gfsbox_ti(void);
extern const struct cctest_info *ccaes_intel_cfb8_encrypt_opt_keysbox_ti(void);
extern const struct cctest_info *ccaes_intel_cfb8_encrypt_opt_varkey_ti(void);
extern const struct cctest_info *ccaes_intel_cfb8_encrypt_opt_vartxt_ti(void);

extern const struct cctest_info *ccaes_intel_cfb8_decrypt_opt_gfsbox_ti(void);
extern const struct cctest_info *ccaes_intel_cfb8_decrypt_opt_keysbox_ti(void);
extern const struct cctest_info *ccaes_intel_cfb8_decrypt_opt_varkey_ti(void);
extern const struct cctest_info *ccaes_intel_cfb8_decrypt_opt_vartxt_ti(void);

extern const struct cctest_info *ccaes_intel_cfb8_encrypt_aesni_gfsbox_ti(void);
extern const struct cctest_info *ccaes_intel_cfb8_encrypt_aesni_keysbox_ti(void);
extern const struct cctest_info *ccaes_intel_cfb8_encrypt_aesni_varkey_ti(void);
extern const struct cctest_info *ccaes_intel_cfb8_encrypt_aesni_vartxt_ti(void);

extern const struct cctest_info *ccaes_intel_cfb8_decrypt_aesni_gfsbox_ti(void);
extern const struct cctest_info *ccaes_intel_cfb8_decrypt_aesni_keysbox_ti(void);
extern const struct cctest_info *ccaes_intel_cfb8_decrypt_aesni_varkey_ti(void);
extern const struct cctest_info *ccaes_intel_cfb8_decrypt_aesni_vartxt_ti(void);

extern const struct cctest_info *ccaes_intel_cfb8_encrypt_opt_mmt_ti(void);
extern const struct cctest_info *ccaes_intel_cfb8_decrypt_opt_mmt_ti(void);

extern const struct cctest_info *ccaes_intel_cfb8_encrypt_aesni_mmt_ti(void);
extern const struct cctest_info *ccaes_intel_cfb8_decrypt_aesni_mmt_ti(void);
#endif

#endif /* _CORECRYPTO_CCTEST_AES_H_ */
