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

//
// we want to do this in the right way, which means you guessed it:
// CONSTANT TIME!
//
cc_size ccn_n(cc_size n, const cc_unit *s)
{
    cc_size size = 0;
    cc_unit tmp = 0;

    for (cc_size i = 1; i <= n; i++) {
        CC_HEAVISIDE_STEP(tmp, s[i - 1]);    // this will set tmp to 1 if the unit is non-zero
        CC_MUXU(size, tmp, i, size);         // size = tmp ? i : size
    }
    
    return size;
}
