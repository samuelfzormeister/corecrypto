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

#include <corecrypto/cc_error.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccscrypt_internal.h>

//
// ccscrypt_storage_size does error checking- allegedly.
//
int64_t ccscrypt_storage_size(uint64_t N, uint32_t r, uint32_t p)
{
    int64_t res;

    if (r == 0 || N == 0) {
        return CCERR_PARAMETER;
    }

    if (p > (UINT32_MAX * 32 / (128 * r))) {
        return CCERR_PARAMETER;
    }

    if ((N & (N-1)) != 0) {
        return CCERR_PARAMETER;
    }

    res += (128 * r * p);
    res += (256 * r);
    res += (128 * r * N);

    return res;
}
