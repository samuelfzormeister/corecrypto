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

//
// This declares all available tests to the subsystem.
//

extern const struct cctest_info *ccmd2_ti(void);
extern const struct cctest_info *ccmd4_ti(void);

extern const struct cctest_info *ccaes_ltc_ecb_encrypt_ecbgfsbox_ti(void);
extern const struct cctest_info *ccaes_ltc_ecb_encrypt_ecbkeysbox_ti(void);
extern const struct cctest_info *ccaes_ltc_ecb_encrypt_ecbvarkey_ti(void);
extern const struct cctest_info *ccaes_ltc_ecb_encrypt_ecbvartxt_ti(void);

enum {
    CCTEST_SUBSYSTEM_DIGEST = 1,
    CCTEST_SUBSYSTEM_MODE,
};

void cctest_trace_fail(uint32_t subsystem, const char *name, uint32_t failed_vec);
void cctest_trace_general(uint32_t subsystem, const char *name, const char *msg);
void cctest_trace_pass(uint32_t subsystem, const char *name, uint32_t failed_vec);

#endif /* _CORECRYPTO_CCTEST_INTERNAL_H_ */
