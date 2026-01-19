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

#include <corecrypto/cchkdf.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/cc_priv.h>

//
// https://www.rfc-editor.org/rfc/rfc5869
//
// 2.2 - Step 2: Expand
//

int cchkdf_expand(struct ccdigest_info *di, size_t prk_len, const void *prk,
                  size_t info_len, const void *info,
                  size_t derived_len, void *derived_key)
{
    uint8_t T[di->output_size];
    size_t n = cc_ceiling(derived_len, di->output_size);
    size_t Tlength = 0;
    size_t finalBytes = derived_len - (n * di->output_size);
    size_t finalBytesOffset = derived_len - finalBytes;
    cchmac_di_decl(di, hmac);
    cchmac_di_decl(di, hmac_initial);

    if (n > 255) {
        return CCERR_PARAMETER;
    } else if (prk_len < di->output_size) {

    }

    // i'm actually glad that HMAC ops can be split up into different function calls
    cchmac_init(di, hmac_initial, prk_len, prk);

    for (size_t i = 1; i <= n; i++) {
        uint8_t ctr = (uint8_t)i;

        cc_memcpy(hmac, hmac_initial, cchmac_di_size(di));

        // update using the contents of T first.
        cchmac_update(di, hmac, Tlength, T);

        // then; update using the info string
        cchmac_update(di, hmac, info_len, info);

        // and then do the 'counter' field.
        cchmac_update(di, hmac, 1, &ctr);

        // generate the MAC
        cchmac_final(di, hmac, T);

        // that is a piece of our key; copy to derived_key and 'push' the pointer forward
        if (i == n) {
            cc_memcpy(derived_key, T, finalBytes);
        } else {
            cc_memcpy(derived_key, T, di->output_size);
        }

        Tlength = di->output_size;

        derived_key += di->output_size;
    }

    cc_clear(cchmac_di_size(di), hmac);
    cc_clear(cchmac_di_size(di), hmac_initial);
    cc_clear(di->output_size, T);

    return CCERR_OK;
}
