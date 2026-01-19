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

int ccmode_ctr_setctr(const struct ccmode_ctr *mode, ccctr_ctx *ctx, const void *ctr)
{
    struct _ccmode_ctr_key *ckey = (struct _ccmode_ctr_key *)ctx;
    cc_memcpy(CCMODE_CTR_KEY_COUNTER(ckey), ctr, ckey->ecb->block_size); /* This gets a bit absurd for AES,  */
    return CCERR_OK;
}
