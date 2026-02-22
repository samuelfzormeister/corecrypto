/*
 * Copyright (C) 2025-2026 The PureDarwin Project, All rights reserved.
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
#include <corecrypto/ccn.h>

#if CCN_UNIT_SIZE == 8
#define ccn_clz cc_clz64
#else
#define ccn_clz cc_clz32

#if CC_UNIT_SIZE == 2
#define ccn_clz_extra 16
#elif CC_UNIT_SIZE == 1
#define ccn_clz_extra 24
#endif
#endif

cc_size ccn_bitlen(cc_size n, const cc_unit *s)
{
    cc_size size = 0, leading = 0;
    cc_unit tmp = 0;
    
    for (cc_size i = 0; i < n; i++) {
        CC_HEAVISIDE_STEP(tmp, s[i]);                               // check if the unit is zero
#if CC_UNIT_SIZE == 1 || CC_UNIT_SIZE == 2
        leading = ccn_clz(s[i] | 1) - ccn_clz_extra;                // count leading zeros (if a given unit is zero, the | 1 should aviod an undefined condition)
#else
        leading = ccn_clz(s[i] | 1);                                // count leading zeros (if a given unit is zero, the | 1 should aviod an undefined condition)
#endif
        CC_MUXU(size, tmp, ccn_bitsof_n(i + 1) - leading, size);    // then, update the bit count if the unit is non-zero.
    }

    return size;
}
