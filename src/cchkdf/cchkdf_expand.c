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

#include <corecrypto/cc_memory.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccdigest_priv.h>
#include <corecrypto/cchkdf.h>
#include <corecrypto/cchmac.h>

//
// https://www.rfc-editor.org/rfc/rfc5869
//
// 2.3 - Step 2: Expand
//

int cchkdf_expand(struct ccdigest_info *di, size_t prk_len, const void *prk,
                  size_t info_len, const void *info,
                  size_t derived_len, void *derived_key)
{
    // --- Use CC_WORKSPACE to enable Windows clients. --- //
    CC_WORKSPACE_STACK_DECL(Tws, di->output_size);
    cchmac_di_decl(di, hmac);
    cchmac_di_decl(di, ihmac);
    uint8_t *T = (uint8_t *)Tws->start;
    size_t n = cc_ceiling(derived_len, di->output_size);
    size_t Tlength = 0;
    size_t offset = 0;

    /* as per the spec, the out length needs to be less than 256 */
    if (n > 255) {
        return CCERR_PARAMETER;
    }

    if (prk_len < di->output_size) {
        return CCERR_PARAMETER;
    }

    cchmac_init(di, ihmac, prk_len, prk);

    for (size_t i = 1; i <= n; i++) {
        uint8_t ctr = (uint8_t)i;

        cc_memcpy(hmac, ihmac, cchmac_di_size(di));

        cchmac_update(di, hmac, Tlength, T);
        cchmac_update(di, hmac, info_len, info);
        cchmac_update(di, hmac, 1, &ctr);

        cchmac_final(di, hmac, T);

        if (i == n) {
            cc_memcpy(derived_key + offset, T, derived_len - offset);
        } else {
            cc_memcpy(derived_key + offset, T, di->output_size);
        }

        Tlength = di->output_size;
        offset += di->output_size;
    }

    cchmac_di_clear(di, hmac);
    cchmac_di_clear(di, ihmac);
    CC_WORKSPACE_STACK_FREE(Tws, di->output_size);

    return CCERR_OK;
}
