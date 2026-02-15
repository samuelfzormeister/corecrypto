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

#ifndef _CORECRYPTO_CCTEST_INTERNAL_H_
#define _CORECRYPTO_CCTEST_INTERNAL_H_

#include <corecrypto/cctest_priv.h>
#include <corecrypto/cc_memory.h>

//
// This declares all available tests to the subsystem.
//

extern const struct cctest_info *ccmd2_ti(void);
extern const struct cctest_info *ccmd4_ti(void);
extern const struct cctest_info *ccmd5_ltc_ti(void);

extern const struct cctest_info *ccrmd160_ti(void);

//
// merge all AES tests into converged?
//
extern const struct cctest_info *ccaes_ltc_ecb_encrypt_ecbgfsbox_ti(void);
extern const struct cctest_info *ccaes_ltc_ecb_encrypt_ecbkeysbox_ti(void);
extern const struct cctest_info *ccaes_ltc_ecb_encrypt_ecbvarkey_ti(void);
extern const struct cctest_info *ccaes_ltc_ecb_encrypt_ecbvartxt_ti(void);

extern const struct cctest_info *ccaes_ltc_ecb_decrypt_ecbgfsbox_ti(void);
extern const struct cctest_info *ccaes_ltc_ecb_decrypt_ecbkeysbox_ti(void);
extern const struct cctest_info *ccaes_ltc_ecb_decrypt_ecbvarkey_ti(void);
extern const struct cctest_info *ccaes_ltc_ecb_decrypt_ecbvartxt_ti(void);

#if CCAES_INTEL_ASM
extern const struct cctest_info *ccaes_intel_ecb_encrypt_opt_ecbgfsbox_ti(void);
extern const struct cctest_info *ccaes_intel_ecb_encrypt_opt_ecbkeysbox_ti(void);
extern const struct cctest_info *ccaes_intel_ecb_encrypt_opt_ecbvarkey_ti(void);
extern const struct cctest_info *ccaes_intel_ecb_encrypt_opt_ecbvartxt_ti(void);

extern const struct cctest_info *ccaes_intel_ecb_decrypt_opt_ecbgfsbox_ti(void);
extern const struct cctest_info *ccaes_intel_ecb_decrypt_opt_ecbkeysbox_ti(void);
extern const struct cctest_info *ccaes_intel_ecb_decrypt_opt_ecbvarkey_ti(void);
extern const struct cctest_info *ccaes_intel_ecb_decrypt_opt_ecbvartxt_ti(void);

extern const struct cctest_info *ccaes_intel_ecb_encrypt_aesni_ecbgfsbox_ti(void);
extern const struct cctest_info *ccaes_intel_ecb_encrypt_aesni_ecbkeysbox_ti(void);
extern const struct cctest_info *ccaes_intel_ecb_encrypt_aesni_ecbvarkey_ti(void);
extern const struct cctest_info *ccaes_intel_ecb_encrypt_aesni_ecbvartxt_ti(void);

extern const struct cctest_info *ccaes_intel_ecb_decrypt_aesni_ecbgfsbox_ti(void);
extern const struct cctest_info *ccaes_intel_ecb_decrypt_aesni_ecbkeysbox_ti(void);
extern const struct cctest_info *ccaes_intel_ecb_decrypt_aesni_ecbvarkey_ti(void);
extern const struct cctest_info *ccaes_intel_ecb_decrypt_aesni_ecbvartxt_ti(void);
#endif

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

#if CC_KERNEL
#define CCTEST_LINK_NEXT_ALLOC(link) link->next = (struct _cctest_test_link *)IOMalloc(sizeof(struct _cctest_test_link))
#define CCTEST_LINK_FREE(link) IOFree(link, sizeof(struct _cctest_test_link))
#else
#define CCTEST_LINK_NEXT_ALLOC(link) link->next = (struct _cctest_test_link *)malloc(sizeof(struct _cctest_test_link))
#define CCTEST_LINK_FREE(link) free(link)
#endif

enum {
    CCTEST_SUBSYSTEM_DIGEST = 1,
    CCTEST_SUBSYSTEM_MODE,
};

void cctest_trace_fail(uint32_t subsystem, const char *name, uint32_t failed_vec);
void cctest_trace_general(uint32_t subsystem, const char *name, const char *msg);
void cctest_trace_pass(uint32_t subsystem, const char *name, uint32_t failed_vec);

#endif /* _CORECRYPTO_CCTEST_INTERNAL_H_ */
