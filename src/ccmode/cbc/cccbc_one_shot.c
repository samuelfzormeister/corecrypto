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
#include <corecrypto/ccmode.h>

int cccbc_one_shot(const struct ccmode_cbc *mode, size_t key_len, 
                   const void *key, const void *iv, 
                   size_t nblocks, const void *in, 
                   void *out)
{
    int ret;
    cccbc_ctx_decl(mode->size, ctx);
    cccbc_iv_decl(mode->block_size, iv_ctx);
    ret = cccbc_init(mode, ctx, key_len, key);
    cc_require(ret == 0, exit);
    // cccbc_set_iv returns zero no matter what, don't care about its return value.
    cccbc_set_iv(mode, iv_ctx, iv);
    ret = cccbc_update(mode, ctx, iv_ctx, nblocks, in, out);

    exit:
    cccbc_ctx_clear(mode->size, ctx);
    return ret;
}