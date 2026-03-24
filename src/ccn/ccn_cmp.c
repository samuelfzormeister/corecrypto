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

#include "ccn_internal.h"

int ccn_cmp(cc_size n, const cc_unit *s, const cc_unit *t)
{
    int ret = 0;
    cc_size size = 0;
    cc_unit tmp = 0, tmp2 = 0, tmp3 = 0;

    for (cc_size i = 0; i < n; i++) {
        tmp = cc_unit_is_equal(s[i], t[i]);
        CC_MUXU(tmp2, tmp, i, tmp2);        // tmp2 = tmp ? i : tmp2
        CC_MUXU(tmp3, tmp, i, tmp3);        // tmp3 = tmp ? i : tmp3
    }

    return (int)cc_unit_is_less_than(tmp2, tmp3);
}
