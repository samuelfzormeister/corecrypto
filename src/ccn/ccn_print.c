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

#include <corecrypto/cc_debug.h>
#include <corecrypto/ccn.h>

void ccn_print(cc_size n, const cc_unit *s)
{
    while (n--) {
        cc_printf("%" CCPRIx_UNIT, s[n-1]);
    }
}

void ccn_lprint(cc_size n, const char *label, const cc_unit *s)
{
    /* print ts to stdout */
    printf("%s { %zu, ", label, n);

    while (n--) {
        cc_printf("%" CCPRIx_UNIT, s[n-1]);
    }
    printf("}\n");
}
