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

#include "ccn_internal.h"
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccn.h>

#ifdef CCN_ADD_ASM
#undef CCN_ADD_ASM

#define CCN_ADD_ASM 0
#endif

cc_unit ccn_add(cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t)
{
#if CCN_ADD_ASM
    return ccn_add_asm(n, r, s, t);
#else
    cc_unit carry = 0;

    for (int i = 0; i < n; i++) {
        cc_unit u = s[i] + t[i] + carry;
        carry = u < s[i];
        r[i] = u;
    }

    return carry;
#endif
}
