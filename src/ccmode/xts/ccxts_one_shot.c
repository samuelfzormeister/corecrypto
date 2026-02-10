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

#include "corecrypto/ccmode.h"
#include <corecrypto/cc_macros.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccmode_internal.h>

int ccxts_one_shot(const struct ccmode_xts *mode, size_t key_nbytes, 
                   const void *data_key, const void *tweak_key, 
                   const void *iv, size_t nblocks, 
                   const void *in, void *out)
{
    int ret = 0;
    void *twkbuf = NULL;

    ccxts_tweak_decl(mode->tweak_size, twk);
    ccxts_ctx_decl(mode->size, ctx);

    ret = ccxts_init(mode, ctx, key_nbytes, data_key, tweak_key);
    cc_require(ret == 0, out);
    ret = ccxts_set_tweak(mode, ctx, twk, iv);
    cc_require(ret == 0, out);
    ccxts_update(mode, ctx, twk, nblocks, in, out);

    out:
    ccxts_ctx_clear(mode->size, ctx);
    ccxts_tweak_clear(mode->tweak_size, twk);
    return ret;
}
