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

#include <corecrypto/ccder.h>

#if __has_include(<limits.h>)
#include <limits.h>
#endif

//
// IMPLEMENTOR'S NOTE:
// https://luca.ntop.org/Teaching/Appunti/asn1.html
//

size_t ccder_sizeof_tag(ccder_tag tag)
{
    ccder_tag tmp = tag & CCDER_TAGNUM_MASK;

#if CCDER_MULTIBYTE_TAGS
    if (tmp < CCDER_HIGH_TAG_NUMBER) {  /* stock standard */
        return 1;
    } else if (tmp <= 0x7F) {           /* 7 bits */
        return 2;
    } else if (tmp <= 0x3FFF) {         /* 14 bits */
        return 3;
    } else if (tmp <= 0x1FFFFF) {       /* 21 bits */
        return 4;
    } else if (tmp <= 0x3FFFFFF) {      /* 28 bits */
        return 5;
    } else {
        return 6;
    }
#else
    return 1;
#endif
}
