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

int cchkdf(struct ccdigest_info *di, size_t ikm_len, const void *ikm,
           size_t salt_len, const void *salt,
           size_t info_len, const void *info,
           size_t derived_len, void *derived_key)
{
    uint8_t prk[di->output_size];

    int res = cchkdf_extract(di, salt_len, salt, ikm_len, ikm, prk);
    if (res == CCERR_OK) {
        res = cchkdf_expand(di, di->output_size, prk, info_len, info, derived_len, derived_key);
    }

    cc_clear(di->output_size, prk);
    return res;
}
