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

int ccmode_ccm_init(const struct ccmode_ccm *ccm, ccccm_ctx *ctx, size_t rawkey_len, const void *rawkey)
{
    struct _ccmode_ccm_key *key = CCMODE_CCM_KEY(ctx);
    const struct ccmode_ecb *ecb = (const struct ccmode_ecb *)ccm->custom;  // WHY IS THIS AN ECB MODE???

    key->ecb = ecb;
    ccecb_init(ecb, CCMODE_CCM_KEY_ECB_CTX(key), rawkey_len, rawkey);

    return 0;
}
