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

#include <corecrypto/ccdigest_priv.h>

// --- I'm assuming the variadic arguments are ccdigest's. --- //
const struct ccdigest_info *ccdigest_oid_lookup(ccoid_t oid, ...)
{
    const struct ccdigest_info *di = NULL;
    va_list list;
    va_start(list, oid);
    
    while ((di = va_arg(list, const struct ccdigest_info *))) {
        if (ccdigest_oid_equal(di, oid)) {
            break;
        } else {
            // --- this is to avoid accidentally returning the last digest structure --- //
            di = NULL;
        }
    }
    
    va_end(list);
    return di;
}
