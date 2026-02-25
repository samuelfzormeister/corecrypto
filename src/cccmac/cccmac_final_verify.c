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
#include <corecrypto/cccmac_priv.h>
#include <corecrypto/ccmode.h>

int cccmac_final_verify(cccmac_ctx_t ctx, size_t expected_mac_nbytes, const void *expected_mac)
{
    uint8_t mac[CMAC_BLOCKSIZE];

    cccmac_final_generate(ctx, CMAC_BLOCKSIZE, mac);
    if (cc_cmp_safe(expected_mac_nbytes, mac, expected_mac) == 0) {
        return CCERR_OK;
    } else {
        return CCERR_INTEGRITY;
    }
}
