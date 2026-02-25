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

#include <corecrypto/ccmode_internal.h>

void ccmode_ccm_macdata(ccccm_ctx *key, ccccm_nonce *nonce_ctx, unsigned int new_block, size_t nbytes, const void *in)
{
    struct _ccmode_ccm_nonce *nonce = CCMODE_CCM_NONCE(nonce_ctx);

    if (new_block) {
        // ????
    }
}
