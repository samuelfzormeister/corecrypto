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

#include <corecrypto/cc.h>
#include <corecrypto/cc_macros.h>
#include <corecrypto/cccmac_priv.h>
#include <corecrypto/ccmode.h>

int cccmac_one_shot_verify(const struct ccmode_cbc *cbc, 
                             size_t key_nbytes, const void *key, 
                             size_t data_nbytes, const void *data, 
                             size_t mac_nbytes, const void *mac)
{
    cccmac_mode_decl(cbc, ctx);
    int ret = cccmac_init(cbc, ctx, key_nbytes, key);
    cc_require(ret == CCERR_OK, out);
    ret = cccmac_update(ctx, data_nbytes, data);
    cc_require(ret == CCERR_OK, out);
    ret = cccmac_final_verify(ctx, mac_nbytes, mac);

    out:
    cccmac_mode_clear(cbc, ctx);
    return ret;
}
