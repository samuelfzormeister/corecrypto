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

#include <corecrypto/cc_runtime_config.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccmode_factory.h>

const struct ccmode_xts *ccaes_xts_encrypt_mode(void)
{
#if CCAES_INTEL_ASM
    if (CC_HAS_AESNI()) {
        return &ccaes_intel_xts_encrypt_aesni_mode;
    } else {
        return &ccaes_intel_xts_encrypt_opt_mode;
    }
#else
    static struct ccmode_xts xts_encrypt_mode;
    const struct ccmode_ecb *ecb = ccaes_ecb_encrypt_mode();

    ccmode_factory_xts_encrypt(&xts_encrypt_mode, ecb, ecb);
    return &xts_encrypt_mode;
#endif
}
