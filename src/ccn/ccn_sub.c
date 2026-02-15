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
#include <corecrypto/cc_memory.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccn.h>

//
// TODO: identify which variant is faster.
//
cc_unit ccn_sub(cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t)
{
#if CCN_UINT128_SUPPORT_FOR_64BIT_ARCH
    cc_dunit tmp1;
    cc_dunit tmp2;
    cc_dunit res;
    cc_unit borrow = 0;

    for (cc_size i = 0; i < n; i++) {
        tmp1 = s[i] + (CCN_UNIT_MASK + 1);
        tmp2 = t[i] + borrow;
        res = tmp1 - tmp2;
        r[i] = (cc_unit)(res & CCN_UNIT_MASK);
        borrow = (res & ~CCN_UNIT_MASK) != 0;
    }
    
    return borrow;
#else
    // do it using all units at once if we can't do it unit by unit.
    CC_WORKSPACE_DECL(work, ccn_sizeof_n(n));

    // if s < t, then we have underflow and need to return the underflow
    cc_unit underflow = ccn_cmp(n, s, t) < 0;

    // make one's complement of t
    for (cc_size i = 0; i < n; i++) {
        work->start[i] = ~t[i];
    }

    // add one to make it two's complement
    ccn_add1(n, work->start, work->start, 1);
    ccn_add(n, r, s, work->start);

    return underflow;
#endif
}
