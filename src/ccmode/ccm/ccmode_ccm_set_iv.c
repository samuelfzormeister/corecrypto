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

#include <corecrypto/cc_macros.h>
#include <corecrypto/ccmode_internal.h>

/*
 * t = mac nbytes
 * n = nonce_nbytes
 * a = auth_len
 * q = data_len
 */
int ccmode_ccm_set_iv(ccccm_ctx *ctx, ccccm_nonce *nonce_ctx, 
                      size_t nonce_len, const void *nonce, 
                      size_t mac_size, size_t auth_len, size_t data_len)
{
    int ret = CCERR_PARAMETER;
    size_t q = (CCMODE_CCM_KEY_ECB(ctx)->block_size - nonce_len) - 1;

    /* Follow A.1 - Length Requirements */
    cc_require((mac_size % 2 == 0) && ((mac_size >= 4) && mac_size <= 16), out);
    cc_require(((q >= 2) && q <= 8), out);

    out:
    return ret;
}
