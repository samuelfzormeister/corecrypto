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

const struct ccmode_ctr *ccaes_ctr_crypt_mode(void)
{
    static struct ccmode_ctr ctr_aes;
    
    const struct ccmode_ecb *ecb = ccaes_ecb_encrypt_mode();
    ccmode_factory_ctr_crypt(&ctr_aes, ecb);
    return &ctr_aes;
}
