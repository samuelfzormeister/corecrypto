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
// 2.2 - Step 1: Extract
//

int cchkdf_extract(struct ccdigest_info *di, size_t salt_len, const void *salt, size_t ikm_len, const void *ikm, void *prk)
{
    if (salt == NULL || salt_len == 0) {
        // "if not provided, it is set to a string of HashLen zeros."
        uint8_t zero_salt[di->output_size];

        cchmac(di, di->output_size, zero_salt, ikm_len, ikm, prk);
    } else {
        cchmac(di, salt_len, salt, ikm_len, ikm, prk);
    }

    return CCERR_OK;
}
