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

int ccgcm_init_with_iv(const struct ccmode_gcm *mode, ccgcm_ctx *ctx, 
                       size_t key_nbytes, const void *key, const void *iv)
{
    int ret = ccgcm_init(mode, ctx, key_nbytes, key);

    if (ret == CCERR_OK) {
        ret = ccgcm_set_iv(mode, ctx, CCGCM_IV_NBYTES, iv);
    }

    if (ret == CCERR_OK) {
        CCMODE_GCM_KEY(ctx)->flags |= CCGCM_FLAGS_INIT_WITH_IV;
    }

    return ret;
}
