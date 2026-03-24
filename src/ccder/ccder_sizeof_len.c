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

#if __SIZE_WIDTH__ == 64

size_t ccder_sizeof_len(size_t len)
{
    if (len <= 0x7F) {
        return 1;
    } else if (len <= UINT8_MAX) {          /* 8 bits */
        return 2;
    } else if (len <= UINT16_MAX) {         /* 16 bits */
        return 3;
    } else if (len <= 0xFFFFFF) {           /* 24 bits */
        return 4;
    } else if (len <= UINT32_MAX) {         /* 32 bits */
        return 5;
    } else if (len <= 0xFFFFFFFFFF) {       /* 40 bits */
        return 6;
    } else if (len <= 0xFFFFFFFFFFFF) {     /* 48 bits */
        return 7;
    } else if (len <= 0xFFFFFFFFFFFFFF) {   /* 56 bits */
        return 8;
    } else {                                /* 64 bits */
        return 9;
    }
}

#else

size_t ccder_sizeof_len(size_t len)
{
    if (len <= 0x7F) {
        return 1;
    } else if (len <= UINT8_MAX) {  /* 8 bits */
        return 2;
    } else if (len <= UINT16_MAX) { /* 16 bits */
        return 3;
    } else if (len <= 0xffffff) {   /* 24 bits */
        return 4;
    } else {                        /* 32 bits */
        return 5;
    }
}

#endif

