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

#include <corecrypto/cc_macros.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccwrap_priv.h>

int ccwrap_argsvalid(const struct ccmode_ecb *mode, size_t pt_len, size_t wrapped_len)
{
    int res = CCERR_OK;
    
    cc_require(mode->block_size == (CCWRAP_SEMIBLOCK * 2), fail);
    cc_require((pt_len / CCWRAP_SEMIBLOCK) < CCWRAP_MAX_SEMIBLOCKS, fail);
    cc_require((wrapped_len / CCWRAP_SEMIBLOCK) <= CCWRAP_MAX_SEMIBLOCKS, fail);
    
fail:
    res = CCERR_PARAMETER;
    return res;
}
