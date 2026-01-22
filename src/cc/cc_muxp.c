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

//
// derived from CC_MUXU
//
// jankiest fucking shit i've ever seen
//
void *cc_muxp(int s, const void *a, const void *b)
{
    uintptr_t pa = (uintptr_t)a;
    uintptr_t pb = (uintptr_t)b;
    uintptr_t _cond = ~((uintptr_t)(s)-(uintptr_t)1);
    uintptr_t r = (_cond&(pa))|(~_cond&pb);
    return (void *) r;
}
