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

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccmode_internal.h>

int ccmode_xts_init(const struct ccmode_xts *xts, ccxts_ctx *ctx, size_t key_nbytes, const void *data_key, const void *tweak_key)
{
    struct _ccmode_xts_key *key = (struct _ccmode_xts_key *)ctx;

    /* for sanity's sake, let us ensure that data_key and tweak_key are different */
    if (!cc_cmp_safe(key_nbytes, data_key, tweak_key)) {
    }

    /* set the ECB modes for usage in ccmode_xts_set_tweak + ccmode_xts_crypt */
    key->ecb = xts->custom;
    key->ecb_encrypt = xts->custom1;

    ccmode_xts_key_sched(xts, ctx, key_nbytes, data_key, tweak_key);
    return CCERR_OK;
}
