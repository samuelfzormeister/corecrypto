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

#include <corecrypto/cc_priv.h>

int cc_cmp_safe(size_t num, const void *ptr1, const void *ptr2)
{
    size_t i;
    uint8_t flag = 0;
    const uint8_t *p1 = (const uint8_t *)ptr1;
    const uint8_t *p2 = (const uint8_t *)ptr2;

    if (num <= 0) {
        flag = 1;
    }

    for (i = 0; i < num; i++) {
        flag |= (p1[i] ^ p2[i]);
    }

    //
    // this acts as a constant-time ? operator.
    //
    // learnt this from the corecrypto osfmk code.
    //
    CC_HEAVISIDE_STEP(flag, flag);

    return flag;
}
